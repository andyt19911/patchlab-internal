<#
  Hyper-V provider. Run PatchLab Internal from an elevated prompt on the Hyper-V host.

  Each sandbox VM boots from a differencing disk whose parent is a golden
  VHDX, so creating one takes seconds and the golden image is never touched.
  Commands run over PowerShell Direct (VMBus), so the guest needs no network
  access, WinRM or firewall rules for PatchLab Internal to reach it.

  [sandbox.hyperv] options:
    switch                = "PatchLab Internal"          virtual switch (needs internet for Windows Update)
    vm_path               = "D:\PatchLab Internal\VMs"   where sandbox VMs and disks live
    generation            = 2
    secure_boot_template  = "MicrosoftWindows"
    tpm                   = false               true for Windows 11 images
#>

$script:Opts = $null
$script:Cred = $null
$script:Marker = 'patchlab_internal=1'

function Initialize-Provider($opts) {
    Import-Module Hyper-V -ErrorAction Stop
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'PatchLab Internal must run from an elevated (Run as administrator) prompt on the Hyper-V host'
    }
    $script:Opts = $opts
    $script:Cred = Get-GuestCredential
    @{
        provider     = 'hyperv'
        host         = $env:COMPUTERNAME
        capabilities = @{ reboot = $true; checkpoint = $true; system_tasks = $true }
    }
}

function Get-VMRoot {
    if ($script:Opts.vm_path) { return $script:Opts.vm_path }
    (Get-VMHost).VirtualMachinePath
}

function Invoke-PLCreate($a) {
    $o = $script:Opts
    if (-not (Test-Path -LiteralPath $a.image)) { throw "golden disk not found: $($a.image)" }
    $root = Get-VMRoot
    $dir = Join-Path $root $a.name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $vhd = Join-Path $dir ($a.name + [IO.Path]::GetExtension($a.image))
    New-VHD -Path $vhd -ParentPath $a.image -Differencing | Out-Null

    $generation = if ($o.generation) { [int]$o.generation } else { 2 }
    $vmArgs = @{
        Name               = $a.name
        Generation         = $generation
        MemoryStartupBytes = ([int64]$a.memory_mb * 1MB)
        VHDPath            = $vhd
        Path               = $root
    }
    if ($o.switch) { $vmArgs.SwitchName = $o.switch }
    $vm = New-VM @vmArgs
    Set-VM -VM $vm -ProcessorCount ([int]$a.cpus) -StaticMemory -CheckpointType Standard `
        -AutomaticCheckpointsEnabled $false -AutomaticStopAction TurnOff `
        -Notes "$script:Marker;patchlab_internal.run=$($a.run_id)"
    if ($generation -eq 2) {
        $template = if ($o.secure_boot_template) { $o.secure_boot_template } else { 'MicrosoftWindows' }
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate $template
    }
    if ($o.tpm) {
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
    }
    Get-VMIntegrationService -VM $vm | Where-Object { $_.Name -match 'Guest Service' } |
        Enable-VMIntegrationService -ErrorAction SilentlyContinue
    Start-VM -VM $vm
    @{ name = $a.name; path = $dir; guest_dir = 'C:\ProgramData\PatchLab Internal' }
}

function Invoke-PLExec($a) {
    Invoke-Command -VMName $a.name -Credential $script:Cred -ErrorAction Stop `
        -ScriptBlock ${function:Invoke-PatchLabInternalGuestScript} `
        -ArgumentList $a.script, $null, ([int]$a.timeout), $null |
        Select-Object exit_code, stdout, stderr, timed_out
}

function Invoke-PLCopyIn($a) {
    $session = New-PSSession -VMName $a.name -Credential $script:Cred -ErrorAction Stop
    try {
        Invoke-Command -Session $session -ArgumentList $a.dest -ScriptBlock {
            param($dest)
            $parent = Split-Path -Parent $dest
            if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
            if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        }
        Copy-Item -ToSession $session -Path $a.src -Destination $a.dest -Recurse -Force
    } finally {
        Remove-PSSession $session
    }
    $true
}

function Invoke-PLCopyOut($a) {
    $session = New-PSSession -VMName $a.name -Credential $script:Cred -ErrorAction Stop
    try {
        Copy-Item -FromSession $session -Path $a.src -Destination $a.dest -Recurse -Force
        $true
    } catch {
        $false
    } finally {
        Remove-PSSession $session
    }
}

function Invoke-PLCheckpoint($a) {
    Checkpoint-VM -Name $a.name -SnapshotName $a.snapshot
    $true
}

function Invoke-PLRestore($a) {
    Restore-VMSnapshot -VMName $a.name -Name $a.snapshot -Confirm:$false
    if ((Get-VM -Name $a.name).State -ne 'Running') { Start-VM -Name $a.name }
    $true
}

function Invoke-PLDestroy($a) {
    if ($a.name -notlike 'patchlab-internal-*') { throw "refusing to delete '$($a.name)': not a PatchLab Internal VM" }
    $vm = Get-VM -Name $a.name -ErrorAction SilentlyContinue
    $dir = Join-Path (Get-VMRoot) $a.name
    if ($vm) {
        if ($vm.Notes -notmatch [regex]::Escape($script:Marker)) {
            throw "refusing to delete '$($a.name)': it is not marked as a PatchLab Internal VM"
        }
        if ($vm.Path) { $dir = $vm.Path }
        Stop-VM -VM $vm -TurnOff -Force -ErrorAction SilentlyContinue
        Remove-VM -VM $vm -Force
    }
    # Disk files can stay locked for a moment after the VM goes away.
    if ((Split-Path -Leaf $dir) -like 'patchlab-internal-*') {
        for ($i = 0; $i -lt 10 -and (Test-Path -LiteralPath $dir); $i++) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $dir) { Start-Sleep -Seconds 2 }
        }
    }
    $true
}

function Invoke-PLList($a) {
    Get-VM | Where-Object {
        $_.Notes -match [regex]::Escape($script:Marker) -and
        (-not $a.run_id -or $_.Notes -match [regex]::Escape("patchlab_internal.run=$($a.run_id)"))
    } | ForEach-Object { $_.Name }
}
