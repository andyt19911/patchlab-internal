<#
  Local provider: FOR DEVELOPING AND TESTING PATCHLAB ITSELF.

  "Sandboxes" are just directories on this machine and commands run here,
  with no isolation, no reboots and no checkpoints. Use it to try out check
  scripts and configs quickly (it works with PowerShell 7 on Linux/macOS
  too). Never point a real patch at it.

  Relative deploy destinations are placed inside the sandbox directory,
  which checks can find as $env:PATCHLAB_INTERNAL_GUEST_DIR.
#>

$script:Root = $null

function Initialize-Provider($opts) {
    $script:Root = if ($opts.root) { $opts.root } else { Join-Path ([IO.Path]::GetTempPath()) 'patchlab-internal-local' }
    New-Item -ItemType Directory -Force -Path $script:Root | Out-Null
    @{
        provider     = 'local'
        host         = [Environment]::MachineName
        capabilities = @{ reboot = $false; checkpoint = $false; system_tasks = $false }
    }
}

function Get-SandboxDir($name) {
    if ($name -notlike 'patchlab-internal-*') { throw "not a PatchLab Internal sandbox: $name" }
    Join-Path $script:Root $name
}

function Resolve-GuestPath($name, $path) {
    if ([IO.Path]::IsPathRooted($path)) { return $path }
    Join-Path (Get-SandboxDir $name) $path
}

function Invoke-PLCreate($a) {
    $dir = Get-SandboxDir $a.name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path (Join-Path $dir '.patchlab') -Value "patchlab_internal.run=$($a.run_id)"
    @{ name = $a.name; path = $dir; guest_dir = $dir }
}

function Invoke-PLExec($a) {
    $env:PATCHLAB_INTERNAL_GUEST_DIR = Get-SandboxDir $a.name
    try {
        Invoke-PatchLabInternalGuestScript -ScriptText $a.script -TimeoutSeconds ([int]$a.timeout)
    } finally {
        Remove-Item Env:PATCHLAB_INTERNAL_GUEST_DIR -ErrorAction SilentlyContinue
    }
}

function Invoke-PLCopyIn($a) {
    $dest = Resolve-GuestPath $a.name $a.dest
    $parent = Split-Path -Parent $dest
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    Copy-Item -Path $a.src -Destination $dest -Recurse -Force
    $true
}

function Invoke-PLCopyOut($a) {
    $src = Resolve-GuestPath $a.name $a.src
    if (-not (Test-Path -LiteralPath $src)) { return $false }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $a.dest) | Out-Null
    Copy-Item -LiteralPath $src -Destination $a.dest -Recurse -Force
    $true
}

function Invoke-PLCheckpoint($a) { throw 'the local provider does not support checkpoints' }
function Invoke-PLRestore($a) { throw 'the local provider does not support checkpoints' }

function Invoke-PLDestroy($a) {
    $dir = Get-SandboxDir $a.name
    if (Test-Path -LiteralPath (Join-Path $dir '.patchlab')) { Remove-Item -LiteralPath $dir -Recurse -Force }
    $true
}

function Invoke-PLList($a) {
    Get-ChildItem -Path $script:Root -Directory -Filter 'patchlab-internal-*' | Where-Object {
        $marker = Join-Path $_.FullName '.patchlab'
        (Test-Path $marker) -and (-not $a.run_id -or (Get-Content $marker) -eq "patchlab_internal.run=$($a.run_id)")
    } | ForEach-Object { $_.Name }
}
