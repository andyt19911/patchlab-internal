# Windows patch testing with PatchLab Internal

This guide covers testing Windows monthly updates (the same content Intune /
Windows Autopatch deploys) on **Hyper-V** for a lab/pilot and **VMware
vSphere** for production-scale testing.

> **Status:** The Windows pipeline, the PowerShell driver, guest execution,
> the probe, the reports and the local provider are covered by automated tests,
> and the PowerShell passes Windows PowerShell 5.1 compatibility analysis.
> The Hyper-V and vSphere providers and the Windows Update installer have
> **not yet been run against a real hypervisor**. Expect the first run on
> your hosts to need small fixes. Start with one golden image and
> `--keep-on-failure`.

## Where it fits with Intune / Autopatch

Autopatch (and Windows Update for Business rings) roll a quality update out
in stages: **Test → First → Fast → Broad**. Every stage is real devices. What
most organisations lack is a stage *before* Test that answers "does this
month's update break our builds and our apps?" automatically, on the evening
it's released.

```
Patch Tuesday 18:00 UTC     ~19:00            next morning              day 1+
Microsoft releases ──► PatchLab Internal ring "-1" ──► report / Teams card ──► Autopatch Test ring ──► First ──► ...
                       golden VMs per build     PASS: let it flow
                       baseline → install →     FAIL: pause the release in Intune
                       reboot → re-test →       (Autopatch > Release management)
                       uninstall → re-test      and investigate from the report
```

PatchLab Internal pulls updates **directly from Windows Update / Microsoft Update**
using the same Windows Update Agent API Windows itself uses, ignoring any
WSUS policy, so the sandbox gets exactly what WUfB/Autopatch rings get. By
default it selects what a quality ring installs (Security, Critical, Update
Rollups and cumulative Updates) and skips previews, optional updates, drivers,
definition updates and feature upgrades.

## What a Windows run checks

Your checks (Pester suites, HTTP probes, SQL queries, scripts) run **before**
and **after** the update, in the same VM. On top of those, the built-in probe
compares:

| Area | Detects | Severity |
|---|---|---|
| Updates | Each KB installed, its classification and result code; install failures with HRESULT | FAIL on failure |
| OS build | e.g. `20348.2700 → 20348.2762`, new KBs, servicing packages, programs, .NET | info |
| Reboots | Pending-reboot loops, how long each reboot took, reboot still pending at the end | WARN |
| Services | Automatic services that ran before and don't after (trigger-start and update plumbing ignored) | FAIL |
| Event log | New *kinds* of error events since boot. Bugchecks, unexpected shutdowns, WHEA and update failures are FAIL; other new errors (app crashes, service errors) are WARN | FAIL/WARN |
| Drivers | Devices newly in Error/Degraded state | FAIL |
| Network | Listening TCP ports that disappeared (dynamic RPC range ignored) | FAIL |
| Component store | `DISM /CheckHealth` no longer Healthy | FAIL |
| Hardening drift | Registry values under SCHANNEL, LSA, KDC, Netlogon, WinTrust and printer policy (configurable) | info, listed |
| Config files | Hash changes under `watch_paths` (hosts file, your app's web.config, ...) | info, listed |
| Rollback | The update can be uninstalled (DISM), the machine reboots, and baseline checks pass again | FAIL if not |

Because everything is compared against the baseline, noise that's always
there (DCOM 10016 errors, a stopped service that's always stopped) doesn't
count against the patch.

## Hyper-V setup (initial testing)

### 1. Host

- Windows Server 2019+ or Windows 10/11 Pro/Enterprise with the Hyper-V role.
- Python 3.11+ (`winget install Python.Python.3.12`).
- Enough RAM for your images in parallel (4 GB each by default; use `--jobs` to limit concurrency).
- A virtual switch with internet access for Windows Update. A NAT switch keeps test VMs off your corporate LAN:

```powershell
New-VMSwitch -Name PatchLabInternal-NAT -SwitchType Internal
New-NetIPAddress -IPAddress 192.168.250.1 -PrefixLength 24 -InterfaceAlias 'vEthernet (PatchLabInternal-NAT)'
New-NetNat -Name PatchLabInternal-NAT -InternalIPInterfaceAddressPrefix 192.168.250.0/24
# Give golden images a static IP in 192.168.250.0/24 with gateway .1 and a public DNS server,
# or run a small DHCP server on the switch.
```

### 2. Golden images: one per Windows build you run

For each build (e.g. Server 2022, Server 2019, Windows 11 23H2 Enterprise):

1. Create a Generation 2 VM and install Windows (evaluation media is fine for testing).
2. Install the roles, agents and line-of-business apps that production servers of that type have.
3. Patch it to **the same level as production today** (last month's update), then stop.
   The golden image should match production; PatchLab Internal installs the new month's updates.
4. Set the local Administrator password (this is `PATCHLAB_INTERNAL_GUEST_PASSWORD`) and keep it
   out of your domain. Don't enrol it in Intune or Autopilot: policies would fight PatchLab Internal.
5. Stop Windows from updating itself so the image stays at the production level:
   `Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1`
   (create the key first). PatchLab Internal's Windows Update calls still work with this set.
6. Shut down cleanly (not sysprep; the VM should boot straight to a usable state) and
   copy the VHDX to `D:\PatchLabInternal\Golden\`. Mark it read-only: sandboxes only ever
   read it through differencing disks.

**Each month, after the update has reached Broad**, refresh the golden images
(boot, install that month's update, shut down) so next month is tested against
the new production baseline.

### 3. Configure and run

Edit `examples/windows/hyperv.toml` (image paths, switch, VM folder), then
from an **elevated** prompt:

```powershell
cd C:\PatchLabInternal            # a clone of this repository
$env:PATCHLAB_INTERNAL_GUEST_PASSWORD = (Get-Credential Administrator).GetNetworkCredential().Password
python -m patchlab_internal validate examples\windows\hyperv.toml
python -m patchlab_internal run examples\windows\hyperv.toml --image D:\PatchLabInternal\Golden\ws2022-std.vhdx `
       --patch windows-update --verify-rollback --keep-on-failure
```

Patch variants:

```powershell
--patch windows-update                         # everything a quality ring would install
--patch windows-update:KB5044281               # one KB (e.g. an out-of-band fix)
--patch package-file:C:\Updates\windows10.0-kb5044281-x64.msu   # a catalog download
--patch script:C:\Vendor\agent-hotfix.ps1      # anything else, run as SYSTEM
```

Rollback modes (`[patch] rollback`):

- `"uninstall"` (the default for updates): removes what the update added with DISM, reboots
  and re-runs the checks. This tests your real production back-out plan.
  Servicing stack updates can't be uninstalled; the report says so.
- `"checkpoint"`: reverts the VM to a checkpoint taken just before patching. This proves
  nothing about uninstalling, but it's quick.
- Any PowerShell text: your own back-out script.

### 4. Schedule it for Patch Tuesday

```powershell
# As the account the task will run as (DPAPI ties the file to it):
Get-Credential Administrator | Export-Clixml C:\ProgramData\PatchLabInternal\guest-cred.xml

$action  = New-ScheduledTaskAction -Execute powershell.exe -Argument `
  '-NoProfile -ExecutionPolicy Bypass -File C:\PatchLabInternal\examples\windows\Invoke-PatchTuesday.ps1 -ReportShare \\files\PatchLabInternal -WebhookUrl https://...'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Tuesday -At 20:00
Register-ScheduledTask -TaskName 'PatchLab Internal - Patch Tuesday' -Action $action -Trigger $trigger `
  -User 'CONTOSO\svc-patchlab' -Password '...' -RunLevel Highest
```

`Invoke-PatchTuesday.ps1` runs only on the second Tuesday (use `-Force` for
out-of-band releases). It copies the report to the share, writes Application
event 1000/1001/1002/1003 (PASS/WARN/FAIL/ERROR) for your monitoring, and can post a card to
Teams through a Workflows webhook.

## vSphere setup (production)

1. **Template VMs:** build golden images as above, but as ordinary VMs with VMware Tools.
   Take a snapshot named `patchlab-internal-base` on each (powered off). Sandboxes are
   **linked clones** of that snapshot, so they're created in seconds and use little storage.
   Don't convert them to vSphere templates: linked clones need a snapshot.
2. **Network:** an isolated port group with outbound internet access for Windows Update.
3. **Service account** in vCenter with a role scoped to the PatchLab Internal folder, resource pool
   and datastore that allows: *Virtual machine → Inventory (create from existing, remove)*,
   *Provisioning (clone, deploy)*, *Snapshot management*, *Interaction (power on/off)*,
   *Configuration (change CPU/memory/settings, annotation)*, *Guest operations
   (modify, program execution, queries)*, and *Datastore → Allocate space*.
4. **Runner:** any Windows or Linux machine with Python 3.11+, PowerShell 7 and PowerCLI
   (`Install-Module VMware.PowerCLI -Scope CurrentUser`).
5. Edit `examples/windows/vsphere.toml` (server, cluster, datastore, folder, network, template names) and run:

```powershell
$env:PATCHLAB_INTERNAL_VCENTER_USER = 'svc-patchlab@vsphere.local'
$env:PATCHLAB_INTERNAL_VCENTER_PASSWORD = '...'
$env:PATCHLAB_INTERNAL_GUEST_PASSWORD = '...'
python -m patchlab_internal run examples\windows\vsphere.toml --patch windows-update --verify-rollback
```

`hyperv.toml` and `vsphere.toml` share `checks.toml`, so what you validate on
Hyper-V is exactly what runs in production.

## Writing checks

Checks are PowerShell run inside the guest; exit code 0 is a pass. For
per-test comparisons, write a Pester suite (see `examples/windows/tests/`)
and point `results` at its XML output. JUnit (Pester 5) and NUnit (Pester 3/4)
both work. Good candidates, in order of value:

1. **The things that break each month in real life:** line-of-business app health
   pages, logins (Kerberos/NTLM, certificate-based), printing, SQL connectivity,
   scheduled jobs, SMB shares, TLS connections to partners.
2. **Your existing smoke tests:** if the service desk has a "check it's working" list, script it.
3. **Service-specific probes:** IIS app pools, SQL Agent jobs, certificate enrolment,
   backup agent status, EDR/AV agent health.

Try checks quickly without a VM using `examples/windows/local-dev.toml`,
which runs the same pipeline on your workstation with PowerShell 7.

## Cleanup

- Sandbox VMs are named `patchlab-internal-<run>-<image>` and tagged in their Notes
  (`patchlab_internal=1;patchlab_internal.run=<id>`). Teardown always removes the VM and its
  differencing disk or linked clone, including after errors and Ctrl-C.
- `python -m patchlab_internal gc --config examples\windows\hyperv.toml` removes anything left
  over from a crash. It only deletes VMs carrying the PatchLab Internal tag and a `patchlab-internal-` name.
- `--keep-on-failure` keeps a failing VM so you can log in
  (`Enter-PSSession -VMName <name>` on Hyper-V) and investigate.

## Known limits and next steps

- **Authentication hardening needs a domain.** Kerberos, NTLM, Netlogon and certificate-mapping
  enforcement changes only show up with a domain controller and a client. The next step is a
  multi-VM lab (DC + member server + client) per target.
- **Drivers and firmware aren't tested.** VMs don't have your hardware; keep a small physical pilot group.
- **Microsoft 365 Apps / Edge** update through their own channels, not Windows Update. A
  `m365-apps` patch kind (Click-to-Run channel update) would be the natural addition.
- **Pausing Autopatch on FAIL** is manual today. It could be automated through Microsoft Graph.
