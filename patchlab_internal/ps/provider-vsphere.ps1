<#
  VMware vSphere provider (PowerCLI). Can run on any machine with PowerCLI
  and network access to vCenter; the guest needs VMware Tools.

  Each sandbox is a linked clone of a template VM's snapshot, so it is
  created in seconds and uses little storage. Commands run through VMware
  Tools guest operations (Invoke-VMScript / Copy-VMGuestFile), so the guest
  needs no WinRM or inbound firewall rules.

  Credentials: PATCHLAB_INTERNAL_VCENTER_USER / PATCHLAB_INTERNAL_VCENTER_PASSWORD (vCenter)
               PATCHLAB_INTERNAL_GUEST_USER / PATCHLAB_INTERNAL_GUEST_PASSWORD (guest admin)

  [sandbox.vsphere] options:
    server         = "vcenter.example.com"
    base_snapshot  = "patchlab-internal-base"     snapshot on each template VM to clone from
    cluster        = "Lab"               or resource_pool = "..." / vmhost = "..."
    datastore      = "lab-ds01"
    folder         = "PatchLabInternal"          VM folder for sandboxes
    network        = "PatchLabInternal-Isolated" port group (needs internet for Windows Update)
    insecure       = false               true to accept self-signed vCenter certificates
#>

$script:Opts = $null
$script:Cred = $null
$script:VI = $null
$script:Marker = 'patchlab_internal=1'

function Initialize-Provider($opts) {
    Import-Module VMware.VimAutomation.Core -ErrorAction Stop
    if (-not $opts.server) { throw '[sandbox.vsphere] server is required' }
    if (-not $env:PATCHLAB_INTERNAL_VCENTER_USER -or -not $env:PATCHLAB_INTERNAL_VCENTER_PASSWORD) {
        throw 'PATCHLAB_INTERNAL_VCENTER_USER and PATCHLAB_INTERNAL_VCENTER_PASSWORD must be set'
    }
    $certAction = if ($opts.insecure) { 'Ignore' } else { 'Fail' }
    $null = Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false `
        -InvalidCertificateAction $certAction -WebOperationTimeoutSeconds 86400
    $vcCred = New-Object System.Management.Automation.PSCredential($env:PATCHLAB_INTERNAL_VCENTER_USER,
        (ConvertTo-SecureString $env:PATCHLAB_INTERNAL_VCENTER_PASSWORD -AsPlainText -Force))
    $script:VI = Connect-VIServer -Server $opts.server -Credential $vcCred -ErrorAction Stop
    $script:Opts = $opts
    $script:Cred = Get-GuestCredential
    @{
        provider     = 'vsphere'
        host         = "$($script:VI.Name) (vCenter $($script:VI.Version))"
        capabilities = @{ reboot = $true; checkpoint = $true; system_tasks = $true }
    }
}

function Get-SandboxVM($name) { Get-VM -Name $name -Server $script:VI -ErrorAction Stop }

function Invoke-GuestCommand($vm, [string]$text) {
    # Small helper for housekeeping commands (mkdir, unzip) in the guest.
    $r = Invoke-VMScript -VM $vm -ScriptText $text -ScriptType Powershell -GuestCredential $script:Cred -ErrorAction Stop
    if ($r.ExitCode -ne 0) { throw "guest command failed ($($r.ExitCode)): $($r.ScriptOutput)" }
    $r.ScriptOutput
}

function Invoke-PLCreate($a) {
    $o = $script:Opts
    $template = Get-VM -Name $a.image -Server $script:VI -ErrorAction Stop
    $snapName = if ($o.base_snapshot) { $o.base_snapshot } else { 'patchlab-internal-base' }
    $snap = Get-Snapshot -VM $template -Name $snapName -ErrorAction Stop
    $p = @{
        Name = $a.name; VM = $template; LinkedClone = $true; ReferenceSnapshot = $snap
        Server = $script:VI; ErrorAction = 'Stop'
    }
    if ($o.resource_pool) { $p.ResourcePool = Get-ResourcePool -Name $o.resource_pool -Server $script:VI }
    elseif ($o.cluster) { $p.ResourcePool = Get-Cluster -Name $o.cluster -Server $script:VI }
    elseif ($o.vmhost) { $p.VMHost = Get-VMHost -Name $o.vmhost -Server $script:VI }
    if ($o.datastore) { $p.Datastore = Get-Datastore -Name $o.datastore -Server $script:VI }
    if ($o.folder) { $p.Location = Get-Folder -Name $o.folder -Type VM -Server $script:VI }
    $vm = New-VM @p

    $set = @{ VM = $vm; Notes = "$script:Marker;patchlab_internal.run=$($a.run_id)"; Confirm = $false }
    if ($a.memory_mb) { $set.MemoryMB = [int]$a.memory_mb }
    if ($a.cpus) { $set.NumCpu = [int]$a.cpus }
    $vm = Set-VM @set
    if ($o.network) {
        Get-NetworkAdapter -VM $vm | Set-NetworkAdapter -NetworkName $o.network -Confirm:$false | Out-Null
    }
    Start-VM -VM $vm -Confirm:$false | Out-Null
    @{ name = $a.name; path = "$($vm.Folder)/$($a.name)"; guest_dir = 'C:\ProgramData\PatchLabInternal' }
}

function Invoke-PLExec($a) {
    $vm = Get-SandboxVM $a.name
    $id = [guid]::NewGuid().ToString('N')
    $tmp = [IO.Path]::GetTempPath()
    $localScript = Join-Path $tmp "pl-$id.ps1"
    [IO.File]::WriteAllText($localScript, $a.script, (New-Object Text.UTF8Encoding $true))
    $guestScript = "C:\Windows\Temp\pl-$id.ps1"
    $guestResult = "C:\Windows\Temp\pl-$id.json"
    try {
        Copy-VMGuestFile -LocalToGuest -Source $localScript -Destination $guestScript -VM $vm `
            -GuestCredential $script:Cred -Force -ErrorAction Stop
        $fn = ${function:Invoke-PatchLabInternalGuestScript}.ToString()
        $text = "function Invoke-PatchLabInternalGuestScript {`n$fn`n}`n" +
                "Invoke-PatchLabInternalGuestScript -ScriptPath '$guestScript' -TimeoutSeconds $([int]$a.timeout) -ResultPath '$guestResult' | Out-Null`n" +
                "Remove-Item -Force -ErrorAction SilentlyContinue '$guestScript'"
        $null = Invoke-VMScript -VM $vm -ScriptText $text -ScriptType Powershell `
            -GuestCredential $script:Cred -ErrorAction Stop
        Copy-VMGuestFile -GuestToLocal -Source $guestResult -Destination $tmp -VM $vm `
            -GuestCredential $script:Cred -Force -ErrorAction Stop
        $localResult = Join-Path $tmp "pl-$id.json"
        $r = [IO.File]::ReadAllText($localResult) | ConvertFrom-Json
        Remove-Item -Force -ErrorAction SilentlyContinue $localResult
        $null = Invoke-VMScript -VM $vm -ScriptText "Remove-Item -Force -ErrorAction SilentlyContinue '$guestResult'" `
            -ScriptType Powershell -GuestCredential $script:Cred -ErrorAction SilentlyContinue
        $r
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $localScript
    }
}

function Invoke-PLCopyIn($a) {
    # Guest file operations copy single files, so directories travel as a zip.
    $vm = Get-SandboxVM $a.name
    $id = [guid]::NewGuid().ToString('N')
    $tmp = [IO.Path]::GetTempPath()
    $zip = Join-Path $tmp "pl-$id.zip"
    $isDir = Test-Path -LiteralPath $a.src -PathType Container
    if ($isDir) { Compress-Archive -Path (Join-Path $a.src '*') -DestinationPath $zip -Force }
    else { Compress-Archive -LiteralPath $a.src -DestinationPath $zip -Force }
    $guestZip = "C:\Windows\Temp\pl-$id.zip"
    try {
        Copy-VMGuestFile -LocalToGuest -Source $zip -Destination $guestZip -VM $vm `
            -GuestCredential $script:Cred -Force -ErrorAction Stop
        $dest = $a.dest.Replace("'", "''")
        if ($isDir) {
            $cmd = "if (Test-Path -LiteralPath '$dest') { Remove-Item -LiteralPath '$dest' -Recurse -Force }; " +
                   "Expand-Archive -LiteralPath '$guestZip' -DestinationPath '$dest' -Force"
        } else {
            $leaf = Split-Path -Leaf $a.src
            $cmd = "`$p = Split-Path -Parent '$dest'; New-Item -ItemType Directory -Force -Path `$p | Out-Null; " +
                   "`$x = Join-Path `$env:TEMP 'pl-$id'; Expand-Archive -LiteralPath '$guestZip' -DestinationPath `$x -Force; " +
                   "Move-Item -LiteralPath (Join-Path `$x '$leaf') -Destination '$dest' -Force; Remove-Item -Recurse -Force `$x"
        }
        $null = Invoke-GuestCommand $vm "$cmd; Remove-Item -Force '$guestZip'"
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $zip
    }
    $true
}

function Invoke-PLCopyOut($a) {
    try {
        $vm = Get-SandboxVM $a.name
        $destDir = Split-Path -Parent $a.dest
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        Copy-VMGuestFile -GuestToLocal -Source $a.src -Destination $destDir -VM $vm `
            -GuestCredential $script:Cred -Force -ErrorAction Stop
        $got = Join-Path $destDir (Split-Path -Leaf ($a.src -replace '\\', '/'))
        if ($got -ne $a.dest) { Move-Item -LiteralPath $got -Destination $a.dest -Force }
        $true
    } catch {
        $false
    }
}

function Invoke-PLCheckpoint($a) {
    $vm = Get-SandboxVM $a.name
    New-Snapshot -VM $vm -Name $a.snapshot -Confirm:$false | Out-Null
    $true
}

function Invoke-PLRestore($a) {
    $vm = Get-SandboxVM $a.name
    $snap = Get-Snapshot -VM $vm -Name $a.snapshot -ErrorAction Stop
    Set-VM -VM $vm -Snapshot $snap -Confirm:$false | Out-Null
    $vm = Get-SandboxVM $a.name
    if ($vm.PowerState -ne 'PoweredOn') { Start-VM -VM $vm -Confirm:$false | Out-Null }
    $true
}

function Invoke-PLDestroy($a) {
    if ($a.name -notlike 'patchlab-internal-*') { throw "refusing to delete '$($a.name)': not a PatchLab Internal VM" }
    $vm = Get-VM -Name $a.name -Server $script:VI -ErrorAction SilentlyContinue
    if (-not $vm) { return $true }
    if ($vm.Notes -notmatch [regex]::Escape($script:Marker)) {
        throw "refusing to delete '$($a.name)': it is not marked as a PatchLab Internal VM"
    }
    if ($vm.PowerState -eq 'PoweredOn') { Stop-VM -VM $vm -Confirm:$false | Out-Null }
    Remove-VM -VM $vm -DeletePermanently -Confirm:$false
    $true
}

function Invoke-PLList($a) {
    Get-VM -Server $script:VI | Where-Object {
        $_.Notes -match [regex]::Escape($script:Marker) -and
        (-not $a.run_id -or $_.Notes -match [regex]::Escape("patchlab_internal.run=$($a.run_id)"))
    } | ForEach-Object { $_.Name }
}
