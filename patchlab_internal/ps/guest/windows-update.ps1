<#
  Installs pending updates from Windows Update / Microsoft Update using the
  Windows Update Agent API. Runs as SYSTEM (see run-as-system.ps1).

  It talks to Microsoft's servers directly, ignoring any WSUS policy, so the
  sandbox receives the same content Windows Update for Business / Autopatch
  rings deliver to production. By default it selects what a quality-update
  ring installs (security, critical, update rollups, cumulative updates) and
  skips optional/preview releases, drivers, definition updates and feature
  upgrades.

  $PatchLabInternalConfig (prepended by PatchLab Internal):
    kbs              ["KB5044281"]  install only these (overrides categories)
    categories       classification names to install
    include_preview  also install "Preview" (optional non-security) releases
    microsoft_update also offer updates for other Microsoft products (.NET, etc.)
#>
$ErrorActionPreference = 'Stop'
$cfg = $PatchLabInternalConfig

$classifications = @{
    'Security Updates' = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
    'Critical Updates' = 'e6cf1350-c01b-414d-a61f-263d14d133b4'
    'Update Rollups'   = '28bc880e-0592-4cbf-8f95-c79b17911d5f'
    'Updates'          = 'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83'
    'Definition Updates' = 'e0789628-ce08-4437-be74-2495b842f43b'
    'Feature Packs'    = 'b54e7d24-7add-428f-8b75-90a396fa584f'
    'Service Packs'    = '68c5b0a3-d1a6-4553-ae49-01d3a7827828'
    'Tools'            = 'b4832bd8-e735-4761-8daf-37f882276dab'
    'Drivers'          = 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0'
    'Upgrades'         = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5'
}
# Match on classification IDs so non-English guests behave the same.
$wantedIds = @($cfg.categories | ForEach-Object {
    if ($classifications.ContainsKey($_)) { $classifications[$_] } else { $_.ToLower() } })
$kbFilter = @($cfg.kbs | Where-Object { $_ })

$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'PatchLab Internal'
$searcher = $session.CreateUpdateSearcher()
$muServiceId = '7971f918-a847-4430-9279-4a52d1efe18d'
$searcher.ServerSelection = 2   # ssWindowsUpdate: bypass WSUS policy
if ($cfg.microsoft_update) {
    try {
        $sm = New-Object -ComObject Microsoft.Update.ServiceManager
        $sm.ClientApplicationID = 'PatchLab Internal'
        $null = $sm.AddService2($muServiceId, 7, '')
        $searcher.ServerSelection = 3   # ssOthers
        $searcher.ServiceID = $muServiceId
    } catch {
        Write-Output "Microsoft Update unavailable, using Windows Update only: $($_.Exception.Message)"
    }
}

Write-Output 'Searching for updates...'
$search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
$report = @()
foreach ($u in $search.Updates) {
    $kbs = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
    $cls = @($u.Categories | Where-Object { $_.Type -eq 'UpdateClassification' })
    $reason = $null
    if ($kbFilter.Count -gt 0) {
        if (-not ($kbs | Where-Object { $kbFilter -contains $_ })) { $reason = 'not in KB filter' }
    } else {
        if (-not ($cls | Where-Object { $wantedIds -contains $_.CategoryID.ToLower() })) {
            $reason = 'classification not selected'
        } elseif ($u.BrowseOnly) {
            $reason = 'optional update'
        } elseif (-not $cfg.include_preview -and $u.Title -match '\bPreview\b') {
            $reason = 'preview release'
        }
    }
    $entry = [ordered]@{
        kb             = ($kbs -join ',')
        title          = $u.Title
        classification = (@($cls | ForEach-Object { $_.Name }) -join ', ')
        selected       = (-not $reason)
        reason         = $reason
        size_mb        = [math]::Round($u.MaxDownloadSize / 1MB, 1)
        result         = $null
        hresult        = $null
    }
    if (-not $reason) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$toInstall.Add($u)
        Write-Output "  + $($u.Title)"
    } else {
        Write-Output "  - $($u.Title) [$reason]"
    }
    $report += $entry
}

$summary = [ordered]@{ updates = $report; selected = $toInstall.Count; reboot_required = $false; result = 'NothingToDo' }
if ($toInstall.Count -eq 0) {
    Write-Output 'No applicable updates.'
    '@@PLJSON ' + (ConvertTo-Json -InputObject $summary -Depth 5 -Compress)
    exit 0
}

Write-Output "Downloading $($toInstall.Count) update(s)..."
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $toInstall
$null = $downloader.Download()

Write-Output 'Installing...'
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
try { $installer.ForceQuiet = $true } catch { Write-Verbose 'ForceQuiet not supported' }
$install = $installer.Install()

$codes = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
$failed = 0
for ($i = 0; $i -lt $toInstall.Count; $i++) {
    $u = $toInstall.Item($i)
    $r = $install.GetUpdateResult($i)
    $entry = $report | Where-Object { $_.title -eq $u.Title } | Select-Object -First 1
    $entry.result = $codes[[int]$r.ResultCode]
    $entry.hresult = ('0x{0:X8}' -f $r.HResult)
    if ([int]$r.ResultCode -ge 4) { $failed++ }
    Write-Output "  $($entry.result): $($u.Title)"
}
$summary.reboot_required = [bool]$install.RebootRequired
$summary.result = $codes[[int]$install.ResultCode]
'@@PLJSON ' + (ConvertTo-Json -InputObject $summary -Depth 5 -Compress)
if ($failed -gt 0) { exit 1 }
exit 0
