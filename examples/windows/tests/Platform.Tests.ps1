<#
  Platform checks for a Windows server or client after patching.

  Written without `Should` so the same file runs on the Pester 3.4 that
  ships in Windows and on Pester 5. Each test targets something monthly
  updates have broken in the real world: .NET code compilation, TLS, the
  certificate store, SMB/authentication, WMI, IIS, Defender.
  Add your own Describe blocks for line-of-business applications.
#>

Describe 'Core Windows services' {
    It 'essential services are running' {
        $required = 'EventLog', 'mpssvc', 'Schedule', 'RpcSs', 'Dnscache', 'CryptSvc', 'LanmanServer', 'Winmgmt'
        $down = @(foreach ($name in $required) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -ne 'Running') { $name }
        })
        if ($down.Count) { throw "not running: $($down -join ', ')" }
    }

    It 'WMI/CIM answers queries' {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if (-not $cs.Name) { throw 'Win32_ComputerSystem returned no name' }
    }

    It 'the security subsystem resolves the current identity' {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not $id.Name -or -not $id.User) { throw 'could not resolve current identity' }
    }
}

Describe '.NET and cryptography' {
    It '.NET Framework can compile and run code' {
        $type = 'PatchLabInternalProbe' + [guid]::NewGuid().ToString('N')
        Add-Type -TypeDefinition "public static class $type { public static int Add(int a, int b) { return a + b; } }"
        $result = Invoke-Expression "[$type]::Add(2, 3)"
        if ($result -ne 5) { throw "expected 5, got $result" }
    }

    It 'TLS 1.2 is not disabled for clients' {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($props -and $props.PSObject.Properties['Enabled'] -and $props.Enabled -eq 0) {
            throw 'TLS 1.2 client is disabled in SCHANNEL'
        }
    }

    It 'the machine certificate stores are readable' {
        $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop)
        if ($roots.Count -lt 5) { throw "only $($roots.Count) trusted root certificates found" }
    }

    It 'SHA-256 hashing works' {
        $sha = [Security.Cryptography.SHA256]::Create()
        $hash = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('patchlab_internal')) | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($hash -ne 'e7784f633b9bcfa0f8c6948751f959ecb6fb22c923321c643a531159988b6054') { throw "unexpected SHA-256 output: $hash" }
    }
}

Describe 'File sharing and authentication' {
    It 'the local administrative share is reachable over SMB' {
        if (-not (Test-Path "\\localhost\C$\Windows")) { throw 'cannot reach \\localhost\C$ (SMB server or authentication broken)' }
    }

    It 'SMB2/3 is enabled' {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        if (-not $cfg.EnableSMB2Protocol) { throw 'SMB2/3 server protocol is disabled' }
    }
}

Describe 'Optional roles (tested only where installed)' {
    It 'IIS default site responds' {
        if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return }
        $r = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 30
        if ($r.StatusCode -ne 200) { throw "IIS returned HTTP $($r.StatusCode)" }
    }

    It 'Microsoft Defender real-time protection is on' {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return }
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp -and -not $mp.RealTimeProtectionEnabled) { throw 'Defender real-time protection is off' }
    }

    It 'Remote Desktop is listening when enabled' {
        $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
        if (-not $ts -or $ts.fDenyTSConnections -ne 0) { return }
        if (-not (Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue)) {
            throw 'RDP is enabled but nothing listens on 3389'
        }
    }
}
