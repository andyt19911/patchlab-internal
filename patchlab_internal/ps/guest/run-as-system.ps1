<#
  Runs a payload script as SYSTEM through a one-off scheduled task and
  relays its output and exit code.

  The Windows Update Agent API and wusa.exe refuse to install from remote
  sessions (PowerShell Direct, WinRM, VMware guest operations), which is why
  update installs go through here. Python substitutes __PAYLOAD__ (base64
  UTF-8 script) and __TIMEOUT__ (seconds).
#>
$ErrorActionPreference = 'Stop'
$root = $env:PATCHLAB_INTERNAL_GUEST_DIR
if (-not $root) { $root = Join-Path $env:ProgramData 'PatchLab Internal' }
New-Item -ItemType Directory -Force -Path $root | Out-Null

$id = [guid]::NewGuid().ToString('N')
$payload = Join-Path $root "task-$id.ps1"
$launcher = Join-Path $root "launch-$id.ps1"
$outFile = Join-Path $root "task-$id.out"
$rcFile = Join-Path $root "task-$id.rc"
$timeout = __TIMEOUT__
$utf8 = New-Object Text.UTF8Encoding $true
[IO.File]::WriteAllText($payload, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')), $utf8)

$launch = @"
`$ErrorActionPreference = 'Continue'
`$code = 1
try {
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$payload" 2>&1 |
        ForEach-Object { "`$_" } | Set-Content -Path "$outFile" -Encoding UTF8
    `$code = `$LASTEXITCODE
} catch {
    Add-Content -Path "$outFile" -Value "`$_" -Encoding UTF8
}
Set-Content -Path "$rcFile" -Value `$code
"@
[IO.File]::WriteAllText($launcher, $launch, $utf8)

$taskName = "PatchLabInternal-$id"
$taskPath = '\PatchLab Internal\'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$launcher`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($timeout + 300)) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath

$started = Get-Date
$deadline = $started.AddSeconds($timeout)
$status = 'ok'
while (-not (Test-Path $rcFile)) {
    if ((Get-Date) -gt $deadline) { $status = 'timeout'; break }
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Ready' -and ((Get-Date) - $started).TotalSeconds -gt 30) {
        Start-Sleep -Seconds 5
        if (-not (Test-Path $rcFile)) { $status = 'died' }
        break
    }
    Start-Sleep -Seconds 5
}
if ($status -eq 'timeout') {
    Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
}
if (Test-Path $outFile) { Get-Content -Path $outFile -Encoding UTF8 }
Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -Force -ErrorAction SilentlyContinue -Path $payload, $launcher, $outFile
if ($status -eq 'timeout') { Write-Output "PatchLab Internal: SYSTEM task timed out after $timeout seconds"; exit 124 }
if ($status -eq 'died') { Write-Output 'PatchLab Internal: SYSTEM task ended without reporting a result'; exit 125 }
$code = [int](Get-Content -Path $rcFile | Select-Object -First 1)
Remove-Item -Force -ErrorAction SilentlyContinue -Path $rcFile
exit $code
