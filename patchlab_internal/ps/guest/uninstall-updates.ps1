<#
  Rollback: removes every servicing package installed since cbs-baseline.ps1
  ran, the same way an admin would back out a bad cumulative update in
  production (DISM /Remove-Package). Servicing stack updates cannot be
  removed by design; they are reported, not treated as failures.
#>
$ErrorActionPreference = 'Stop'
$root = $env:PATCHLAB_INTERNAL_GUEST_DIR
if (-not $root) { $root = Join-Path $env:ProgramData 'PatchLab Internal' }
$file = Join-Path $root 'cbs-baseline.json'
if (-not (Test-Path $file)) { Write-Output 'no pre-patch package baseline was recorded'; exit 2 }
# Assign, then cast: in Windows PowerShell 5.1, wrapping the ConvertFrom-Json pipeline
# in an array subexpression makes the whole array ONE element, and every package
# would then look newly installed.
[string[]]$baseline = Get-Content -Raw -Path $file | ConvertFrom-Json
if (-not $baseline -or $baseline.Count -lt 10) {
    Write-Output "pre-patch package baseline looks wrong ($($baseline.Count) entries); refusing to uninstall"
    exit 2
}
$added = @(Get-WindowsPackage -Online | Where-Object {
    $_.PackageState -eq 'Installed' -and $baseline -notcontains $_.PackageName })

$summary = [ordered]@{ removed = @(); skipped = @(); failed = @() }
foreach ($p in $added) {
    if ($p.PackageName -match 'ServicingStack') {
        $summary.skipped += "$($p.PackageName) (servicing stack updates cannot be uninstalled)"
        continue
    }
    Write-Output "Removing $($p.PackageName)"
    try {
        Remove-WindowsPackage -Online -PackageName $p.PackageName -NoRestart | Out-Null
        $summary.removed += $p.PackageName
    } catch {
        $summary.failed += "$($p.PackageName): $($_.Exception.Message)"
    }
}
'@@PLJSON ' + (ConvertTo-Json -InputObject $summary -Compress)
if ($summary.failed.Count -gt 0) { exit 1 }
if ($summary.removed.Count -eq 0) { Write-Output 'nothing that the patch installed can be uninstalled'; exit 3 }
exit 0
