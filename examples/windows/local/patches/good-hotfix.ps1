# Example vendor hotfix: bumps the app version and tightens TLS.
$f = Join-Path $env:PATCHLAB_INTERNAL_GUEST_DIR 'app/config.json'
$cfg = Get-Content -Raw $f | ConvertFrom-Json
$cfg.version = '2.1.0'
$cfg.tls.minimumVersion = '1.3'
$cfg | ConvertTo-Json -Depth 5 | Set-Content $f
Write-Output 'hotfix applied: version 2.1.0, TLS 1.3'
