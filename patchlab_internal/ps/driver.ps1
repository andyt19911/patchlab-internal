<#
  PatchLab Internal provider driver.

  Python starts one of these per sandbox and talks to it over stdin/stdout.
  Each request and response is one line of base64-encoded UTF-8 JSON, so
  script text survives any console code page. Responses are prefixed with
  "@@PL " so stray host output can't be mistaken for a reply.

  Request:  {"id": 1, "action": "exec", "args": {...}}
  Response: {"id": 1, "ok": true, "result": ...} | {"id": 1, "ok": false, "error": "..."}
#>
param([Parameter(Mandatory)][ValidateSet('hyperv', 'vsphere', 'local')][string]$Provider)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

. (Join-Path $PSScriptRoot 'guest-exec.ps1')
. (Join-Path $PSScriptRoot "provider-$Provider.ps1")

function Get-GuestCredential {
    $user = $env:PATCHLAB_INTERNAL_GUEST_USER
    $password = $env:PATCHLAB_INTERNAL_GUEST_PASSWORD
    if (-not $user) { $user = 'Administrator' }
    if (-not $password) { throw 'PATCHLAB_INTERNAL_GUEST_PASSWORD is not set (the guest administrator password)' }
    New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $password -AsPlainText -Force))
}

function Send-Response($obj) {
    $json = ConvertTo-Json -InputObject $obj -Depth 8 -Compress
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    [Console]::Out.WriteLine("@@PL $b64")
    [Console]::Out.Flush()
}

$options = if ($env:PATCHLAB_INTERNAL_PROVIDER_OPTIONS) { $env:PATCHLAB_INTERNAL_PROVIDER_OPTIONS | ConvertFrom-Json } else { New-Object psobject }

while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }
    if (-not $line.Trim()) { continue }
    $id = $null
    try {
        $req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line.Trim())) | ConvertFrom-Json
        $id = $req.id
        if ($req.action -eq 'exit') { Send-Response @{ id = $id; ok = $true; result = $null }; break }
        $result = switch ($req.action) {
            'init'       { Initialize-Provider $options }
            'create'     { Invoke-PLCreate $req.args }
            'exec'       { Invoke-PLExec $req.args }
            'copy_in'    { Invoke-PLCopyIn $req.args }
            'copy_out'   { Invoke-PLCopyOut $req.args }
            'checkpoint' { Invoke-PLCheckpoint $req.args }
            'restore'    { Invoke-PLRestore $req.args }
            'destroy'    { Invoke-PLDestroy $req.args }
            'list'       { @(Invoke-PLList $req.args) }
            default      { throw "unknown action '$($req.action)'" }
        }
        Send-Response @{ id = $id; ok = $true; result = $result }
    } catch {
        Send-Response @{ id = $id; ok = $false; error = "$($_.Exception.Message)" }
    }
}
