# Records the installed servicing packages before the patch, so the
# "uninstall" rollback knows exactly what the patch added.
$ErrorActionPreference = 'Stop'
$root = $env:PATCHLAB_INTERNAL_GUEST_DIR
if (-not $root) { $root = Join-Path $env:ProgramData 'PatchLabInternal' }
New-Item -ItemType Directory -Force -Path $root | Out-Null
$file = Join-Path $root 'cbs-baseline.json'
if (Test-Path $file) { Write-Output "baseline already recorded: $file"; exit 0 }
$names = @(Get-WindowsPackage -Online | Where-Object { $_.PackageState -eq 'Installed' } |
    ForEach-Object { $_.PackageName })
ConvertTo-Json -InputObject $names | Set-Content -Path $file -Encoding UTF8
Write-Output "recorded $($names.Count) installed packages"
