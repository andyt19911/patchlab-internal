# Tiny stand-in for an application self-test; prints TAP.
$root = $env:PATCHLAB_INTERNAL_GUEST_DIR
$cfg = Get-Content -Raw (Join-Path $root 'app/config.json') | ConvertFrom-Json
$script:n = 0; $script:failed = 0
function Test-That([bool]$ok, [string]$name) {
    $script:n++
    if ($ok) { "ok $script:n - $name" } else { $script:failed++; "not ok $script:n - $name" }
}
Test-That ($cfg.database.connectionString -match 'Server=') 'database connection string configured'
Test-That ($cfg.tls.minimumVersion -in '1.2', '1.3') 'TLS 1.2 or later required'
Test-That ($cfg.auth.mode -eq 'Kerberos') 'Kerberos authentication in use'
Test-That ([version]$cfg.version -ge [version]'2.0') 'application version 2.0 or later'
"1..$script:n"
exit $script:failed
