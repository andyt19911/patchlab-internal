<#
  Windows health snapshot, captured before and after the patch.

  $PatchLabInternalConfig: watch_paths, watch_registry, ignore_ports_from, ignore_services
  Output: one "@@PLJSON {...}" line. Each section is independent; a failing
  section is reported in "errors" rather than aborting the probe.
#>
$ErrorActionPreference = 'Stop'
$cfg = $PatchLabInternalConfig
$out = [ordered]@{
    os = ''; kernel = ''; pkgmgr = 'windows'; last_boot = ''
    packages = @{}; pkgdb_issues = @(); broken_libs = @(); listening = @()
    files = @{}; services_down = @(); problem_devices = @(); events = @{}
    pending_reboot = @(); errors = @()
}

function Section([string]$name, [scriptblock]$body) {
    try { & $body } catch { $out.errors += "${name}: $($_.Exception.Message)" }
}

$bootTime = $null
Section 'os' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = "$($cv.CurrentBuildNumber).$($cv.UBR)"
    $release = if ($cv.DisplayVersion) { " $($cv.DisplayVersion)" } else { '' }
    $out.os = "$($os.Caption)$release (build $build)"
    $out.kernel = $build
    $script:bootTime = $os.LastBootUpTime
    $out.last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    $out.packages['Windows OS build'] = $build
}

Section 'hotfixes' {
    Get-HotFix | Where-Object { $_.HotFixID } | ForEach-Object { $out.packages[$_.HotFixID] = 'installed' }
}

Section 'servicing packages' {
    Get-WindowsPackage -Online | Where-Object {
        $_.PackageState -eq 'Installed' -and $_.PackageName -match 'RollupFix|ServicingStack|Package_for_KB|DotNetRollup'
    } | ForEach-Object {
        $parts = $_.PackageName -split '~'
        $out.packages["CBS $($parts[0])"] = $parts[-1]
    }
}

Section 'programs' {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName
    } | ForEach-Object { $out.packages[$_.DisplayName] = "$($_.DisplayVersion)" }
    $ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    if ($ndp) { $out.packages['.NET Framework 4'] = "$($ndp.Version) (release $($ndp.Release))" }
}

Section 'component store' {
    $health = Repair-WindowsImage -Online -CheckHealth
    if ("$($health.ImageHealthState)" -ne 'Healthy') {
        $out.pkgdb_issues += "Windows component store is $($health.ImageHealthState) (run DISM /Online /Cleanup-Image /RestoreHealth)"
    }
}

Section 'services' {
    $ignore = @($cfg.ignore_services)
    Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | Where-Object {
        $_.State -ne 'Running' -and $ignore -notcontains $_.Name -and
        # Trigger-start services stop on purpose when idle.
        -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\TriggerInfo")
    } | ForEach-Object { $out.services_down += "$($_.Name) ($($_.DisplayName))" }
}

Section 'devices' {
    Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Degraded' } |
        ForEach-Object { $out.problem_devices += "$($_.FriendlyName) [$($_.Class)]: $($_.Status)" }
}

Section 'listening ports' {
    $limit = if ($cfg.ignore_ports_from) { [int]$cfg.ignore_ports_from } else { 49152 }
    $out.listening = @(Get-NetTCPConnection -State Listen | ForEach-Object { [int]$_.LocalPort } |
        Where-Object { $_ -lt $limit } | Sort-Object -Unique)
}

Section 'event log' {
    # Errors and critical events since the last boot, grouped by source and ID.
    $since = if ($bootTime) { $bootTime } else { (Get-Date).AddHours(-1) }
    $events = Get-WinEvent -ErrorAction SilentlyContinue -MaxEvents 5000 -FilterHashtable @{
        LogName = 'System', 'Application', 'Setup'; Level = 1, 2; StartTime = $since }
    foreach ($e in $events) {
        $key = "$($e.LogName)/$($e.ProviderName)/$($e.Id)"
        if ($out.events.ContainsKey($key)) { $out.events[$key].count++; continue }
        $msg = "$($e.Message)" -split "`r?`n" | Select-Object -First 1
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
        $out.events[$key] = @{ level = $(if ($e.Level -eq 1) { 'Critical' } else { 'Error' }); count = 1; message = $msg }
    }
}

Section 'pending reboot' {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $out.pending_reboot += 'Component Based Servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $out.pending_reboot += 'Windows Update' }
}

Section 'watched files' {
    foreach ($p in @($cfg.watch_paths)) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue |
            Select-Object -First 20000 | ForEach-Object {
                $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) { $out.files[$_.FullName] = $h.Hash }
            }
    }
}

Section 'watched registry' {
    $hives = @{ 'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKCU' = 'HKEY_CURRENT_USER'; 'HKCR' = 'HKEY_CLASSES_ROOT'; 'HKU' = 'HKEY_USERS' }
    $count = 0
    foreach ($key in @($cfg.watch_registry)) {
        if (-not $key) { continue }
        $hive, $rest = $key -split '\\', 2
        if ($hives.ContainsKey($hive.ToUpper())) { $hive = $hives[$hive.ToUpper()] }
        $path = "Registry::$hive\$rest"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $items = @(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath $path -Recurse -ErrorAction SilentlyContinue)
        foreach ($k in $items) {
            if ($count++ -gt 5000) { break }
            $out.files["reg:$($k.Name)\"] = '(key)'
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                if ($v -is [byte[]]) { $v = ($v | ForEach-Object { $_.ToString('x2') }) -join '' }
                elseif ($v -is [array]) { $v = $v -join '|' }
                $name = if ($n) { $n } else { '(Default)' }
                $out.files["reg:$($k.Name)\$name"] = "$v"
            }
        }
    }
}

'@@PLJSON ' + (ConvertTo-Json -InputObject $out -Depth 6 -Compress)
