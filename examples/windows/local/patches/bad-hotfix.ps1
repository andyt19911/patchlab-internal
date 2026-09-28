# Example of a "compatibility" hotfix that silently downgrades authentication.
$f = Join-Path $env:PATCHLAB_INTERNAL_GUEST_DIR 'app/config.json'
$cfg = Get-Content -Raw $f | ConvertFrom-Json
$cfg.version = '2.1.0'
$cfg.auth.mode = 'NTLM'
$cfg | ConvertTo-Json -Depth 5 | Set-Content $f
Write-Output 'hotfix applied: version 2.1.0'
