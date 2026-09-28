<#
.SYNOPSIS
    Tests this month's Windows updates with PatchLab Internal and publishes the verdict.

.DESCRIPTION
    Schedule this on the Hyper-V host (see docs/WINDOWS.md). On Patch Tuesday
    (the second Tuesday of the month, or any day with -Force) it:
      1. runs PatchLab Internal with the config's windows-update patch on every golden image,
         including rollback verification;
      2. copies the report folder to -ReportShare;
      3. writes an Application event log entry (source "PatchLabInternal") for monitoring/SIEM:
         1000 PASS, 1001 WARN, 1002 FAIL, 1003 ERROR;
      4. optionally posts a summary card to a Microsoft Teams channel through a
         Workflows webhook (-WebhookUrl).
    Microsoft releases updates at 10:00 Pacific; scheduling this for the
    evening gives results before Autopatch moves past its Test ring.

.PARAMETER CredentialFile
    Guest administrator credential saved with:
        Get-Credential Administrator | Export-Clixml C:\ProgramData\PatchLabInternal\guest-cred.xml
    Run that as the account the scheduled task uses: DPAPI ties the file to
    that account on this machine.

.EXAMPLE
    .\Invoke-PatchTuesday.ps1 -Force -ReportShare \\files\PatchLabInternal\Reports
#>
[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot 'hyperv.toml'),
    [string]$PatchLabInternalRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$CredentialFile = (Join-Path $env:ProgramData 'PatchLabInternal\guest-cred.xml'),
    [string]$OutDir = (Join-Path $env:ProgramData 'PatchLabInternal\reports'),
    [string]$ReportShare,
    [string]$WebhookUrl,
    [string]$Python = 'python',
    [switch]$Force
)
$ErrorActionPreference = 'Stop'

$today = (Get-Date).Date
$first = Get-Date -Year $today.Year -Month $today.Month -Day 1
$patchTuesday = $first.AddDays(((2 - [int]$first.DayOfWeek + 7) % 7) + 7).Date
if (-not $Force -and $today -ne $patchTuesday) {
    Write-Output "Not Patch Tuesday (this month it is $($patchTuesday.ToString('yyyy-MM-dd'))); use -Force to run anyway."
    exit 0
}

$cred = Import-Clixml -Path $CredentialFile
$env:PATCHLAB_INTERNAL_GUEST_PASSWORD = $cred.GetNetworkCredential().Password

# Our own run id, so we only ever publish THIS run's report (never an older one).
$runId = 'pt-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 4)

Push-Location $PatchLabInternalRoot
try {
    & $Python -m patchlab_internal run $Config --verify-rollback --out $OutDir --run-id $runId
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
    Remove-Item Env:PATCHLAB_INTERNAL_GUEST_PASSWORD -ErrorAction SilentlyContinue
}

$runDir = Join-Path $OutDir $runId
$reportFile = Join-Path $runDir 'report.json'
$problem = $null
if (Test-Path $reportFile) {
    $report = Get-Content -Raw $reportFile | ConvertFrom-Json
    $reportLink = Join-Path $runDir 'report.html'
} else {
    # PatchLab Internal stopped before writing a report (bad config, missing password, no
    # hypervisor...). Report that as an ERROR rather than falling back to old results.
    $problem = "PatchLab Internal exited with code $exitCode before writing a report. Run it by hand to see why."
    $report = [pscustomobject]@{ verdict = 'ERROR'; run_id = $runId; targets = @()
                                 patch = [pscustomobject]@{ label = 'Windows updates' } }
    $reportLink = '(no report)'
}

if ($ReportShare -and (Test-Path $runDir)) {
    $dest = Join-Path $ReportShare $runId
    Copy-Item -Path $runDir -Destination $dest -Recurse -Force
    if (-not $problem) { $reportLink = Join-Path $dest 'report.html' }
}

$summaryLines = @($problem | Where-Object { $_ }) + @(foreach ($t in $report.targets) {
    $top = @($t.findings | Where-Object { $_.severity -in 'fail', 'error' } |
        Select-Object -First 2 | ForEach-Object { $_.message })
    $updates = @($t.updates | ForEach-Object { $_.kb } | Where-Object { $_ }) -join ', '
    "$($t.image): $($t.verdict)" + $(if ($updates) { " [$updates]" }) + $(if ($top) { ' - ' + ($top -join '; ') })
})

# Write-EventLog exists in Windows PowerShell 5.1 (what the scheduled task uses), not in 7.
if (Get-Command Write-EventLog -ErrorAction SilentlyContinue) {
    $eventIds = @{ PASS = 1000; WARN = 1001; FAIL = 1002; ERROR = 1003 }
    if (-not [Diagnostics.EventLog]::SourceExists('PatchLabInternal')) {
        New-EventLog -LogName Application -Source PatchLabInternal
    }
    $entryType = if ($report.verdict -in 'FAIL', 'ERROR') { 'Error' } elseif ($report.verdict -eq 'WARN') { 'Warning' } else { 'Information' }
    Write-EventLog -LogName Application -Source PatchLabInternal -EventId $eventIds[$report.verdict] -EntryType $entryType `
        -Message ("PatchLab Internal $($report.verdict): $($report.patch.label)`n`n" + ($summaryLines -join "`n") + "`n`nReport: $reportLink")
} else {
    Write-Warning 'Write-EventLog is unavailable in this PowerShell edition; skipping the event log entry'
}

if ($WebhookUrl) {
    $card = @{
        type        = 'message'
        attachments = @(@{
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = @{
                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                type      = 'AdaptiveCard'
                version   = '1.4'
                body      = @(
                    @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; text = "Patch test: $($report.verdict)" }
                    @{ type = 'TextBlock'; wrap = $true; text = "$($report.patch.label) - run $($report.run_id)" }
                    @{ type = 'TextBlock'; wrap = $true; text = ($summaryLines -join "`n`n") }
                    @{ type = 'TextBlock'; wrap = $true; isSubtle = $true; text = "Report: $reportLink" }
                )
            }
        })
    }
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json' `
        -Body (ConvertTo-Json -InputObject $card -Depth 10) | Out-Null
}

Write-Output "PatchLab Internal $($report.verdict). Report: $reportLink"
exit $exitCode
