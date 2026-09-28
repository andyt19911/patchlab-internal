# Testing patches on clones of cloud assets (AWS, Azure, GCP, OCI)

PatchLab Internal can take a **real production instance**, clone it into an isolated
network, patch and test the clone, report, and destroy it, without touching
the original:

```
connect ──► clone asset ──► boot in isolation ──► baseline ──► patch + reboots ──► verify ──► (rollback) ──► report ──► destroy
(cloud CLI)  disk copy of     private subnet,        your checks   Windows Update /    same checks    uninstall +        JSON/MD/   delete every
             the running      no public IP,          + OS probes   packages / KB /    + OS diff      re-verify          HTML       tagged resource
             source           tagged                               script
```

It works for **Windows and Linux** guests on all four clouds, with the same
checks, probes and reports as the Hyper-V/vSphere and container targets.
Because clones are real VMs, **kernel updates and reboots are tested for
real**, which containers can't do.

> **Status:** Every provider's clone/run/destroy flow is covered by tests
> using a recording fake CLI. Every `aws`, `az` and `oci` command line
> PatchLab Internal builds has been validated against the real CLIs. That validation
> found and fixed one bug, in OCI terminate. `gcloud` commands could not be
> validated in the development environment. **None of the providers has yet
> run against a live cloud account.** Do the first run in a non-production
> account with `--keep-on-failure`. Every CLI call is logged to
> `reports/<run>/<target>/<cloud>-cli.log`.

## How each cloud is driven

| | Clone (source keeps running) | Commands run via | Teardown |
|---|---|---|---|
| **AWS** | `create-image --no-reboot` → `run-instances` from that AMI; AMI + snapshots deleted as soon as the clone runs | SSM Run Command (root / SYSTEM) | terminate + sweep by tag |
| **Azure** | `az disk create --source <disk>` for OS and data disks, in a new resource group per clone | Managed Run Command (root / SYSTEM) | delete the resource group |
| **GCP** | `gcloud compute disks create --source-disk` per disk | SSH through IAP (no public IP) | delete instance + disks, sweep by label |
| **OCI** | boot volume and block volume clones | Oracle Cloud Agent Run Command | terminate + delete volumes, sweep by tag |

Authentication is whatever the cloud CLI is configured with: `aws sso login`
or roles, `az login` or a service principal/managed identity, `gcloud auth`
or workload identity, and an OCI config profile or instance principal. PatchLab Internal
never handles cloud credentials itself.

## Data safety and isolation (read this first)

A clone is **a full copy of a production server: its data, secrets,
certificates, service accounts and configuration**. Treat the test
environment with the same classification as production.

What PatchLab Internal guarantees:

- **The source isn't modified.** Only read and copy APIs touch it: describe,
  `create-image --no-reboot`, disk copy or clone. The tests check this for every provider.
- **Clones get no public IP**, and they don't reuse the source's security groups/NSGs.
  They land only in the subnet you configure. On GCP the source's metadata
  (startup scripts, SSH keys) isn't copied, and the clone has no service account.
- **Every resource is tagged** `patchlab_internal=1`, `patchlab-internal-run=<id>` and `patchlab-internal-source=<asset>`,
  and teardown and `gc` only ever delete resources carrying those tags and a `patchlab-internal-` name.
- **Intermediate copies are short-lived:** AWS AMIs and snapshots are deleted as soon as
  the clone is running, and Azure and GCP copy disks directly without snapshots.
- **A failed teardown is an ERROR** in the report, with the `gc` command to run, never a silent leak.

What you must provide:

1. **An isolated subnet.** It needs no route to production networks, domain controllers,
   databases, payment gateways or partners. Outbound access should be limited to what patching
   needs: Windows Update / package mirrors, and the cloud's command endpoints (SSM,
   Azure agent, IAP or OCI agent), ideally through private endpoints or a proxy. A clone has
   the same hostname, domain membership and configuration as production. If it could reach
   production, it could process jobs, send email or corrupt shared state.
2. **Neutralise side effects in `setup`,** which runs before the baseline. For example,
   stop schedulers and outbound integrations:
   `setup = ["Stop-Service PayrollBatch; Set-Service PayrollBatch -StartupType Disabled"]`.
3. **Least-privilege identities** (below), ideally with delete permissions restricted to
   resources tagged `patchlab_internal=1`.
4. **Key access:** if volumes are encrypted with customer-managed keys, the PatchLab Internal identity
   needs to use those keys (AWS can re-encrypt clone volumes with `kms_key_id`).

Copies are **crash-consistent**, like pulling the power: databases run their normal
crash recovery on the clone's first boot. That's usually fine for patch testing.

## AWS

**Network:** a private subnet with a security group that has **no inbound rules**,
plus VPC interface endpoints for `ssm`, `ssmmessages` and `ec2messages`, a gateway
endpoint for S3, and NAT or a proxy for Windows Update or package mirrors.

**Instance profile** for clones (`instance_profile`): `AmazonSSMManagedInstanceCore`,
plus `s3:PutObject`/`s3:GetObject` on the staging bucket if you use one.

**PatchLab Internal identity** (sketch; scope to your accounts/regions):

```json
{"Version": "2012-10-17", "Statement": [
 {"Effect": "Allow", "Action": ["ec2:Describe*", "ec2:CreateImage", "ec2:RunInstances", "ec2:CreateTags",
   "ssm:SendCommand", "ssm:GetCommandInvocation", "ssm:DescribeInstanceInformation", "sts:GetCallerIdentity"],
  "Resource": "*"},
 {"Effect": "Allow", "Action": ["ec2:TerminateInstances", "ec2:DeregisterImage", "ec2:DeleteSnapshot", "ec2:DeleteVolume"],
  "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/patchlab_internal": "1"}}},
 {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::*:role/PatchLabInternalSSM"},
 {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::patchlab-internal-staging-*", "arn:aws:s3:::patchlab-internal-staging-*/*"]}]}
```

**Staging bucket (optional, recommended):** it lifts SSM's 24,000-character output limit
and speeds up file transfer. Without it, PatchLab Internal moves large outputs in chunks.

Config: `examples/cloud/aws-windows.toml`. Assets are `i-...` IDs, `tag:Key=Value`,
or a `Name` tag value; each must match exactly one instance.

## Azure

**Network:** a subnet in a dedicated VNet (not peered to production), an NSG that denies
inbound, and outbound through a NAT gateway or firewall limited to update endpoints.

**Roles for PatchLab Internal:**
- **Reader** on the source VMs and disks.
- Rights to create resource groups, disks, NICs and VMs in the clone subscription
  (Contributor on it, or a custom role).
- **Network Contributor**, or `Microsoft.Network/virtualNetworks/subnets/join/action`, on the isolated subnet.
- **Storage Blob Data Contributor** and **Storage Blob Delegator** on the staging account.

**Staging account (recommended):** managed Run Command returns only about 4 KB of output
inline. With a staging account, the full output goes to a blob via a short-lived
user-delegation SAS.

Every clone lives in its own resource group, `patchlab-internal-<run>-<target>`, so teardown is
one `az group delete`. Config: `examples/cloud/azure-windows.toml`. Assets are
`resource-group/vm-name` or a full resource ID.

## Google Cloud

**Network:** a subnet in a separate VPC, a firewall rule allowing TCP 22 from IAP's range
`35.235.240.0/20` to the `network_tags` you configure, and Cloud NAT for updates.

**Roles for PatchLab Internal:**
- `roles/compute.instanceAdmin.v1` on the clone project.
- `roles/compute.viewer` plus disk-read access on the source.
- `roles/iap.tunnelResourceAccessor`.
- `roles/compute.osAdminLogin` if OS Login is enforced.

**Windows guests** must have the Google Compute Engine OpenSSH server, which recent GCE
Windows images include. PatchLab Internal sets `enable-windows-ssh=TRUE` on the clone.

Config: `examples/cloud/gcp-linux.toml`. Assets are `zone/instance`, or `instance`
with `zone` set.

## Oracle Cloud Infrastructure

**Network:** a private subnet with an NSG that has no ingress, plus a Service Gateway (for
the agent and Object Storage) and NAT for updates.

**Policies** (sketch):

```
Allow group PatchLab Internal to read instance-family in compartment Production
Allow group PatchLab Internal to use volume-family in compartment Production
Allow group PatchLab Internal to manage instance-family in compartment PatchLab Internal
Allow group PatchLab Internal to manage volume-family in compartment PatchLab Internal
Allow group PatchLab Internal to manage instance-agent-command-family in compartment PatchLab Internal
Allow group PatchLab Internal to use virtual-network-family in compartment Network
Allow dynamic-group PatchLabInternalClones to use instance-agent-command-execution-family in compartment PatchLab Internal
```

**Run Command privileges:** Run Command executes as the `ocarun` user. On Linux sources,
give it passwordless sudo (Oracle's documented `/etc/sudoers.d/101-oracle-cloud-agent-run-command`).
On Windows, add `ocarun` to Administrators. PatchLab Internal elevates with `sudo -n`, and ships
PowerShell to Windows through a small batch file, because Windows Run Command uses cmd.

Config: `examples/cloud/oci-linux.toml`. Assets are instance OCIDs or display names
(looked up in `source_compartment_id`).

## Running and cleaning up

```bash
python -m patchlab_internal validate examples/cloud/aws-windows.toml
python -m patchlab_internal run examples/cloud/aws-windows.toml --verify-rollback --keep-on-failure
python -m patchlab_internal gc --config examples/cloud/aws-windows.toml     # remove anything left over
```

- `images` lists the assets to clone. They're tested in parallel, so limit that with `--jobs`.
- `clone_timeout` (default 3600s) bounds disk copying. Large volumes take a while the first time.
- Costs: a clone costs what the source costs, for the duration of the run (typically
  30–90 minutes for Windows cumulative updates), plus transient snapshot/AMI storage on AWS.
- Checkpoint rollback isn't available on cloud clones. Use `rollback = "uninstall"`
  (Windows) or a back-out script. The clone is destroyed either way.
