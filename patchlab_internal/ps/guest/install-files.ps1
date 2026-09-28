<#
  Installs update/package files copied into the guest (runs as SYSTEM):
    .msu  standalone updates from the Microsoft Update Catalog (wusa.exe)
    .cab  servicing packages (DISM)
    .msi  / .msp  Windows Installer packages and patches
    .exe  vendor installers (arguments from exe_args)
  For Windows 11 24H2+ checkpoint cumulative updates, list every .msu in
  the order Microsoft documents; they are installed one after another.

  $PatchLabInternalConfig: files (guest paths, in order), exe_args
#>
$ErrorActionPreference = 'Stop'
$cfg = $PatchLabInternalConfig
$ok = @{ 0 = 'installed'; 3010 = 'installed, reboot required'; 1641 = 'installed, reboot started';
         2359302 = 'already installed' }
$results = @()
$failed = 0

foreach ($file in $cfg.files) {
    $ext = [IO.Path]::GetExtension($file).ToLower()
    Write-Output "== $file"
    $code = $null
    try {
        switch ($ext) {
            '.msu' {
                $p = Start-Process -FilePath wusa.exe -ArgumentList "`"$file`" /quiet /norestart" -Wait -PassThru
                $code = $p.ExitCode
            }
            '.cab' {
                $r = Add-WindowsPackage -Online -PackagePath $file -NoRestart
                $code = if ($r.RestartNeeded) { 3010 } else { 0 }
            }
            '.msi' {
                $p = Start-Process -FilePath msiexec.exe -Wait -PassThru `
                    -ArgumentList "/i `"$file`" /qn /norestart /l*v `"$file.log`""
                $code = $p.ExitCode
            }
            '.msp' {
                $p = Start-Process -FilePath msiexec.exe -Wait -PassThru `
                    -ArgumentList "/p `"$file`" /qn /norestart /l*v `"$file.log`""
                $code = $p.ExitCode
            }
            '.exe' {
                $exeArgs = if ($cfg.exe_args) { $cfg.exe_args } else { '/quiet /norestart' }
                $p = Start-Process -FilePath $file -ArgumentList $exeArgs -Wait -PassThru
                $code = $p.ExitCode
            }
            default { throw "unsupported file type: $ext" }
        }
    } catch {
        Write-Output "  error: $($_.Exception.Message)"
        $code = -1
    }
    $status = if ($ok.ContainsKey([int]$code)) { $ok[[int]$code] } else { 'failed' }
    if ($status -eq 'failed') { $failed++ }
    Write-Output "  exit $code ($status)"
    $results += [ordered]@{ kb = [IO.Path]::GetFileName($file); title = $file; result = $status;
                            hresult = ('0x{0:X8}' -f [int]$code); selected = $true }
}

$reboot = ($results | Where-Object { $_.result -like '*reboot*' }).Count -gt 0
'@@PLJSON ' + (ConvertTo-Json -InputObject ([ordered]@{ updates = $results; reboot_required = $reboot;
    selected = $results.Count; result = $(if ($failed) { 'Failed' } else { 'Succeeded' }) }) -Depth 5 -Compress)
if ($failed -gt 0) { exit 1 }
exit 0
