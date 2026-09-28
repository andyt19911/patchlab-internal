<#
  Runs inside the guest (Windows PowerShell 5.1 compatible).

  Hyper-V passes this function to Invoke-Command -VMName as a script block,
  vSphere ships its text through Invoke-VMScript, and the local provider
  calls it directly. It runs a script in a child PowerShell process so the
  exit code, stdout and stderr are captured faithfully and a timeout can
  kill the whole process tree.
#>
function Invoke-PatchLabInternalGuestScript {
    param(
        [string]$ScriptText,
        [string]$ScriptPath,
        [int]$TimeoutSeconds = 300,
        [string]$ResultPath
    )
    $ErrorActionPreference = 'Stop'
    $root = $env:PATCHLAB_INTERNAL_GUEST_DIR
    if (-not $root) { $root = Join-Path $env:ProgramData 'PatchLabInternal' }
    New-Item -ItemType Directory -Force -Path $root | Out-Null

    $id = [guid]::NewGuid().ToString('N')
    if ($ScriptText) {
        $ScriptPath = Join-Path $root "exec-$id.ps1"
        # A BOM makes Windows PowerShell 5.1 read the file as UTF-8.
        [IO.File]::WriteAllText($ScriptPath, $ScriptText, (New-Object Text.UTF8Encoding $true))
    }
    $stdoutFile = Join-Path $root "exec-$id.out"
    $stderrFile = Join-Path $root "exec-$id.err"

    $exe = $env:PATCHLAB_INTERNAL_GUEST_PWSH
    if (-not $exe) {
        $exe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path $exe)) { $exe = (Get-Process -Id $PID).Path }
    }
    $argLine = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $proc = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $root `
        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru -NoNewWindow
    $null = $proc.Handle   # keeps ExitCode readable after exit
    $timedOut = -not $proc.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        if ($PSVersionTable.PSEdition -eq 'Core') { $proc.Kill($true) }
        else { & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null }
        $proc.WaitForExit()
    }
    $exitCode = if ($timedOut) { 124 } else { $proc.ExitCode }
    $stdout = if (Test-Path $stdoutFile) { [IO.File]::ReadAllText($stdoutFile) } else { '' }
    $stderr = if (Test-Path $stderrFile) { [IO.File]::ReadAllText($stderrFile) } else { '' }
    Remove-Item -Force -ErrorAction SilentlyContinue -Path $stdoutFile, $stderrFile
    if ($ScriptText) { Remove-Item -Force -ErrorAction SilentlyContinue -Path $ScriptPath }

    $result = [pscustomobject]@{
        exit_code = $exitCode
        stdout    = "$stdout"
        stderr    = "$stderr"
        timed_out = $timedOut
    }
    if ($ResultPath) {
        [IO.File]::WriteAllText($ResultPath, (ConvertTo-Json -InputObject $result -Compress),
            (New-Object Text.UTF8Encoding $false))
    }
    $result
}
