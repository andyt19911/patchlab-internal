"""Tests for the cloud providers.

FakeCLI stands in for aws/az/gcloud/oci and records every command, so the
clone -> run -> destroy flows can be checked without cloud accounts. The
recorded commands are also replayed against the real CLIs (when installed)
by CLISyntaxTest, which catches misspelt flags and bad argument shapes.

Run with:  python -m unittest discover -s tests
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from patchlab_internal import config
from patchlab_internal.cloud import base, oci as oci_mod
from patchlab_internal.cloud.aws import AWSProvider
from patchlab_internal.cloud.azure import AzureProvider
from patchlab_internal.cloud.base import CloudError, CloudProvider, CloudSandbox, Clone
from patchlab_internal.cloud.gcp import GCPProvider, gce_name
from patchlab_internal.cloud.oci import OCIProvider

RECORDED: dict[str, list[list[str]]] = {"aws": [], "az": [], "gcloud": [], "oci": []}


class FakeCLI:
    """Returns canned responses for commands containing all the given tokens."""

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[list[str]] = []
        self.files: dict[str, str] = {}

    def available(self, exe):
        return True

    def __call__(self, argv, *, input=None, timeout=900, json_out=True, check=True):
        self.calls.append(list(argv))
        RECORDED.setdefault(argv[0], []).append(list(argv))
        for a in argv:   # keep file:// / @file payloads for inspection
            path = a[7:] if a.startswith("file://") else a[1:] if a.startswith("@") else None
            if path and os.path.exists(path):
                self.files[a] = Path(path).read_text(encoding="utf-8")
        for tokens, resp in self.responses:
            if all(t in argv for t in tokens):
                value = resp(argv) if callable(resp) else resp
                if isinstance(value, Exception):
                    if check:
                        raise value
                    return None
                return value
        return {} if json_out else ""

    def verbs(self):
        return [" ".join(a for a in c[1:4] if not a.startswith("-")) for c in self.calls]


def sequence(*values):
    it = iter(values)
    last = [None]

    def next_value(argv):
        try:
            last[0] = next(it)
        except StopIteration:
            pass
        return last[0]
    return next_value


class NoSleep(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(base.time, "sleep", lambda s: None)
        patcher.start()
        self.addCleanup(patcher.stop)


# ---------------------------------------------------------------- AWS

AWS_SRC = {"Reservations": [{"Instances": [{
    "InstanceId": "i-0source", "InstanceType": "m5.large", "PlatformDetails": "Windows",
    "Tags": [{"Key": "Name", "Value": "payroll-web-01"}]}]}]}
AWS_IMAGE = {"Images": [{"State": "available", "BlockDeviceMappings": [
    {"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": "snap-1"}},
    {"DeviceName": "xvdb", "Ebs": {"SnapshotId": "snap-2"}}]}]}
AWS_OPTS = {"region": "eu-west-2", "subnet_id": "subnet-iso", "security_group_ids": ["sg-none"],
            "instance_profile": "PatchLabInternalSSM"}


class AWSFlowTest(NoSleep):
    def fake(self, **extra):
        return FakeCLI([
            (["describe-instances", "--instance-ids"], AWS_SRC),
            (["create-image"], {"ImageId": "ami-1"}),
            (["describe-images", "--image-ids"], sequence({"Images": [{"State": "pending"}]}, AWS_IMAGE)),
            (["run-instances"], {"Instances": [{"InstanceId": "i-0clone"}]}),
            (["describe-instances", "--filters"], {"Reservations": [{"Instances": [{"InstanceId": "i-0clone"}]}]}),
            (["send-command"], {"Command": {"CommandId": "0b8e1d7c-3f2a-4c55-9a61-2d4b7e9f1a3c"}}),
            (["get-command-invocation"], sequence(
                CloudError("InvocationDoesNotExist"),
                {"Status": "InProgress"},
                {"Status": "Success", "StandardOutputContent": "hello\n"})),
            *extra.get("more", []),
        ])

    def test_clone_run_destroy(self):
        cli = self.fake()
        p = AWSProvider(AWS_OPTS, cli)
        c = Clone("patchlab-internal-r1-payroll", "i-0source", "r1")
        p.clone(c, "windows", 600)
        self.assertEqual((c.os, c.instance), ("windows", "i-0clone"))
        run = next(a for a in cli.calls if "run-instances" in a)
        nic = json.loads(run[run.index("--network-interfaces") + 1])[0]
        self.assertEqual((nic["SubnetId"], nic["AssociatePublicIpAddress"], nic["Groups"]),
                         ("subnet-iso", False, ["sg-none"]))
        self.assertTrue(all(m["Ebs"]["DeleteOnTermination"]
                            for m in json.loads(run[run.index("--block-device-mappings") + 1])))
        self.assertIn("HttpTokens=required,HttpEndpoint=enabled", run)
        # The AMI and its snapshots are dropped as soon as the clone runs.
        verbs = cli.verbs()
        self.assertIn("ec2 deregister-image", verbs)
        self.assertEqual(sum(v == "ec2 delete-snapshot" for v in verbs), 2)

        self.assertEqual(p.run(c, "Write-Output hello", 60), "hello\n")
        params = next(v for k, v in cli.files.items() if k.startswith("file://"))
        self.assertEqual(json.loads(params)["commands"], ["Write-Output hello"])
        self.assertIn("AWS-RunPowerShellScript", next(a for a in cli.calls if "send-command" in a))

        p.destroy(c)
        term = next(a for a in cli.calls if "terminate-instances" in a)
        self.assertIn("i-0clone", term)

    def test_source_is_never_modified(self):
        cli = self.fake()
        p = AWSProvider(AWS_OPTS, cli)
        c = Clone("patchlab-internal-r1-payroll", "i-0source", "r1")
        p.clone(c, "windows", 600)
        p.destroy(c)
        for call in cli.calls:
            if "i-0source" in call:
                self.assertIn(call[2], ("describe-instances", "create-image"), call)
                if call[2] == "create-image":
                    self.assertIn("--no-reboot", call)

    def test_refusals_happen_before_anything_is_created(self):
        cli = self.fake()
        with self.assertRaises(CloudError):
            AWSProvider(AWS_OPTS, cli).clone(Clone("patchlab-internal-x", "i-0source", "r1"), "linux", 60)
        self.assertNotIn("ec2 create-image", cli.verbs())
        clone_src = json.loads(json.dumps(AWS_SRC))
        clone_src["Reservations"][0]["Instances"][0]["Tags"].append({"Key": "patchlab_internal", "Value": "1"})
        cli = FakeCLI([(["describe-instances"], clone_src)])
        with self.assertRaisesRegex(CloudError, "itself a PatchLab Internal clone"):
            AWSProvider(AWS_OPTS, cli).clone(Clone("patchlab-internal-x", "i-0source", "r1"), "windows", 60)

    def test_check_requires_isolation_settings(self):
        reason = AWSProvider({"region": "eu-west-2"}, FakeCLI([])).check()
        self.assertIn("subnet_id", reason)

    def test_tag_lookup_and_ambiguity(self):
        two = {"Reservations": [{"Instances": [AWS_SRC["Reservations"][0]["Instances"][0]] * 2}]}
        with self.assertRaisesRegex(CloudError, "matched 2"):
            AWSProvider(AWS_OPTS, FakeCLI([(["describe-instances"], two)])).clone(
                Clone("patchlab-internal-x", "tag:Role=payroll", "r1"), "windows", 60)


# ---------------------------------------------------------------- Azure

AZ_VM = {
    "location": "uksouth", "zones": ["1"], "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
    "securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}},
    "storageProfile": {"osDisk": {"osType": "Windows", "managedDisk": {"id": "/subs/x/disks/src-os"}},
                       "dataDisks": [{"lun": 0, "managedDisk": {"id": "/subs/x/disks/src-data0"}}]},
    "tags": {}}
AZ_OPTS = {"subnet_id": "/subscriptions/s/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/v/subnets/iso",
           "staging_account": "plstage", "staging_container": "patchlab_internal"}


class AzureFlowTest(NoSleep):
    def fake(self):
        return FakeCLI([
            (["run-command", "show"], {"instanceView": {"executionState": "Succeeded", "output": "inline"}}),
            (["vm", "show"], AZ_VM),
            (["disk", "show"], {"sku": {"name": "Premium_LRS"}, "hyperVGeneration": "V2",
                                "securityProfile": {"securityType": "TrustedLaunch"}}),
            (["disk", "create"], lambda a: {"id": f"/subs/x/rg/{a[a.index('-n') + 1]}"}),
            (["nic", "create"], {"NewNIC": {"id": "/subs/x/nic1"}}),
            (["vm", "create"], {"id": "/subs/x/vm1"}),
            (["generate-sas"], "https://plstage.blob.core.windows.net/patchlab/x?sig=1"),
            (["group", "show"], {"name": "patchlab-internal-r1-web", "tags": {"patchlab_internal": "1"}}),
        ])

    def test_clone_uses_isolated_nic_and_copied_disks(self):
        cli = self.fake()
        p = AzureProvider(AZ_OPTS, cli)
        c = Clone("patchlab-internal-r1-web", "prod-rg/web01", "r1")
        p.clone(c, "windows", 600)
        self.assertEqual(c.location, "patchlab-internal-r1-web")
        disks = [a for a in cli.calls if a[1:3] == ["disk", "create"]]
        self.assertEqual([a[a.index("--source") + 1] for a in disks], ["/subs/x/disks/src-os", "/subs/x/disks/src-data0"])
        self.assertIn("TrustedLaunch", disks[0])
        nic = next(a for a in cli.calls if a[1:4] == ["network", "nic", "create"])
        self.assertIn(AZ_OPTS["subnet_id"], nic)
        vm = next(a for a in cli.calls if a[1:3] == ["vm", "create"])
        self.assertIn("--attach-os-disk", vm)
        self.assertNotIn("--public-ip-address", vm)   # the NIC has none
        # Nothing but reads and disk copies reference the source VM or its disks.
        for call in cli.calls:
            if "prod-rg" in call or any("/disks/src-" in a for a in call):
                self.assertIn(call[1:3], (["vm", "show"], ["disk", "show"], ["disk", "create"]), call)

    def test_run_falls_back_to_inline_output(self):
        cli = self.fake()
        p = AzureProvider(AZ_OPTS, cli)
        c = Clone("patchlab-internal-r1-web", "prod-rg/web01", "r1", os="linux", instance="patchlab-internal-r1-web",
                  location="patchlab-internal-r1-web")
        with mock.patch.object(AzureProvider, "_read_blob", return_value=None):
            self.assertEqual(p.run(c, "echo hi", 60), "inline")
        create = next(a for a in cli.calls if a[1:4] == ["vm", "run-command", "create"])
        self.assertEqual(cli.files[create[create.index("--script") + 1]], "echo hi")
        self.assertIn("--output-blob-uri", create)
        self.assertIn(["az", "vm", "run-command", "delete"], [a[:4] for a in cli.calls])

    def test_never_deletes_foreign_resource_groups(self):
        cli = FakeCLI([(["group", "show"], {"name": "prod-rg", "tags": {}})])
        with self.assertRaisesRegex(CloudError, "refusing"):
            AzureProvider(AZ_OPTS, cli).destroy_named("prod-rg")
        cli = FakeCLI([(["group", "show"], {"name": "patchlab-internal-x", "tags": {}})])
        with self.assertRaisesRegex(CloudError, "refusing"):
            AzureProvider(AZ_OPTS, cli).destroy_named("patchlab-internal-x")
        self.assertNotIn("group delete", " ".join(" ".join(c) for c in cli.calls))


# ---------------------------------------------------------------- GCP

GCP_INST = {
    "machineType": "zones/europe-west2-a/machineTypes/e2-standard-4",
    "shieldedInstanceConfig": {"enableSecureBoot": True, "enableVtpm": True, "enableIntegrityMonitoring": True},
    "disks": [{"boot": True, "type": "PERSISTENT", "index": 0, "deviceName": "boot",
               "source": "projects/p/zones/europe-west2-a/disks/web-boot",
               "licenses": ["projects/windows-cloud/global/licenses/windows-server-2022-dc"]},
              {"boot": False, "type": "PERSISTENT", "index": 1, "deviceName": "data",
               "source": "projects/p/zones/europe-west2-a/disks/web-data"}]}


class GCPFlowTest(NoSleep):
    def test_clone_and_run(self):
        cli = FakeCLI([
            (["instances", "describe"], sequence(GCP_INST, {"status": "RUNNING"})),
            (["disks", "describe"], {"type": "projects/p/zones/z/diskTypes/pd-ssd"}),
            (["compute", "ssh"], "@@PLOK\n"),
        ])
        p = GCPProvider({"project": "p", "subnet": "projects/p/regions/europe-west2/subnetworks/iso"}, cli)
        c = Clone("patchlab-internal-20260926-web.01", "europe-west2-a/web", "20260926-1")
        p.clone(c, "windows", 600)
        self.assertEqual(c.instance, "patchlab-internal-20260926-web-01")
        create = next(a for a in cli.calls if a[1:4] == ["compute", "instances", "create"])
        for flag in ("--no-address", "--no-service-account", "--no-scopes", "--shielded-secure-boot"):
            self.assertIn(flag, create)
        self.assertTrue(any(a.startswith("--metadata=enable-windows-ssh=TRUE") for a in create))
        self.assertEqual(sum(a.startswith("--disk=") for a in create), 2)
        self.assertTrue(any(a.startswith("--disk=") and a.endswith("boot=yes") for a in create))
        self.assertEqual(p.run(c, "Write-Output hi", 60), "@@PLOK\n")
        scp = next(a for a in cli.calls if a[1:3] == ["compute", "scp"])
        self.assertIn("--tunnel-through-iap", scp)
        p.destroy(c)
        # Only reads and disk copies reference the source instance or its disks.
        for call in cli.calls:
            if "web" in call or any("disks/web-" in a for a in call) or "web-boot" in call or "web-data" in call:
                self.assertIn(call[1:4], (["compute", "instances", "describe"], ["compute", "disks", "describe"],
                                          ["compute", "disks", "create"]), call)

    def test_names_are_valid_gce_names(self):
        self.assertEqual(gce_name("PatchLab-20260926-ws2022.vhdx"), "patchlab-20260926-ws2022-vhdx")
        self.assertEqual(gce_name("9lives"), "p-9lives")
        self.assertLessEqual(len(gce_name("x" * 100)), 63)


# ---------------------------------------------------------------- OCI

OCI_SRC = {"data": {"id": "ocid1.instance.src", "availability-domain": "AD-1", "compartment-id": "ocid1.compartment.prod",
                    "shape": "VM.Standard.E4.Flex", "shape-config": {"ocpus": 2, "memory-in-gbs": 16},
                    "source-details": {"image-id": "ocid1.image.win"}, "freeform-tags": {}}}


class OCIFlowTest(NoSleep):
    def test_clone_run_destroy(self):
        cli = FakeCLI([
            (["compute", "instance", "get"], OCI_SRC),
            (["compute", "image", "get"], {"data": {"operating-system": "Windows"}}),
            (["boot-volume-attachment", "list"], {"data": [{"boot-volume-id": "ocid1.bootvolume.src"}]}),
            (["boot-volume", "create"], {"data": {"id": "ocid1.bootvolume.clone"}}),
            (["volume-attachment", "list"], {"data": [{"volume-id": "ocid1.volume.src", "lifecycle-state": "ATTACHED"}]}),
            (["bv", "volume", "create"], {"data": {"id": "ocid1.volume.clone"}}),
            (["compute", "instance", "launch"], {"data": {"id": "ocid1.instance.clone"}}),
            (["command", "create"], {"data": {"id": "ocid1.cmd"}}),
            (["command-execution", "get"], sequence({"data": {"lifecycle-state": "IN_PROGRESS"}},
                                                    {"data": {"lifecycle-state": "SUCCEEDED", "content": {"text": "out"}}})),
            (["structured-search"], {"data": {"items": [
                {"resource-type": "Instance", "identifier": "ocid1.instance.clone", "display-name": "patchlab-internal-r1-web",
                 "lifecycle-state": "RUNNING"},
                {"resource-type": "Volume", "identifier": "ocid1.volume.clone", "display-name": "patchlab-internal-r1-web-data0",
                 "lifecycle-state": "AVAILABLE"}]}}),
        ])
        p = OCIProvider({"compartment_id": "ocid1.compartment.lab", "subnet_id": "ocid1.subnet.iso"}, cli)
        c = Clone("patchlab-internal-r1-web", "ocid1.instance.src", "r1")
        p.clone(c, "windows", 600)
        launch = next(a for a in cli.calls if a[1:4] == ["compute", "instance", "launch"])
        self.assertEqual(launch[launch.index("--assign-public-ip") + 1], "false")
        self.assertEqual(launch[launch.index("--source-boot-volume-id") + 1], "ocid1.bootvolume.clone")
        self.assertEqual(json.loads(launch[launch.index("--shape-config") + 1]), {"ocpus": 2, "memoryInGBs": 16})
        self.assertEqual(p.run(c, "Write-Output hi", 60), "out")
        content = json.loads(next(v for k, v in cli.files.items() if k.startswith("file://")))
        self.assertTrue(content["source"]["text"].startswith("@echo off"))    # Windows = batch shell
        p.destroy(c)
        term = next(a for a in cli.calls if a[1:4] == ["compute", "instance", "terminate"])
        self.assertIn("ocid1.instance.clone", term)
        for call in cli.calls:
            if "ocid1.instance.src" in call:
                self.assertIn(call[1:4], (["compute", "instance", "get"], ["compute", "boot-volume-attachment", "list"],
                                          ["compute", "volume-attachment", "list"]), call)

    def test_windows_batch_lines_fit_cmd_limit(self):
        batch = oci_mod.batch_for_powershell("x" * 50000)
        self.assertLess(max(len(l) for l in batch.split("\r\n")), 8191)


# ---------------------------------------------------------------- CloudSandbox over a local "cloud"

class LocalCloud(CloudProvider):
    """Runs scripts on this machine; tiny limits force every chunked path."""
    name = "localtest"

    def __init__(self, os_name, max_script, max_output, guest_root):
        super().__init__({}, None)
        self.os_name, self.max_script_chars, self.max_output_chars = os_name, max_script, max_output
        self.guest_root = guest_root
        self.destroyed = False

    def clone(self, clone, expected_os, timeout, cancel=None):
        clone.os, clone.instance = self.os_name, "local"

    def wait_agent(self, clone, timeout, cancel=None):
        pass

    def run(self, clone, script, timeout):
        assert len(script) <= self.max_script_chars, len(script)
        if self.os_name == "linux":
            p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        else:
            f = tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig")
            f.write(script)
            f.close()
            p = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-File", f.name], capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=timeout, env={**os.environ, "ProgramData": str(self.guest_root)})
        return p.stdout[:self.max_output_chars]   # like a truncating run-command channel

    def destroy(self, clone):
        self.destroyed = True

    def list_clones(self, run_id=None):
        return []


class CloudSandboxTest(unittest.TestCase):
    def roundtrip(self, os_name):
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "src"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_text("alpha")
        (src / "sub" / "blob.bin").write_bytes(os.urandom(20000))
        (src / "skip.log").write_text("excluded")
        for limits in ((200000, 200000), (6000, 3000)):
            prov = LocalCloud(os_name, *limits, tmp)
            box = CloudSandbox(prov, "asset", "patchlab-internal-t", "r", os_name)
            box.start()
            with mock.patch.object(base, "LINUX_GUEST_DIR", str(tmp / "lg")), \
                 mock.patch.object(CloudSandbox, "gpath", lambda self, *p: "/".join([str(tmp / "g"), *p])):
                if os_name == "linux":
                    r = box.exec("echo héllo; echo oops >&2; exit 5", 30)
                    big = box.exec("head -c 30000 /dev/zero | tr '\\0' x", 30)
                    slow = box.exec("sleep 20", 2)
                    long_script = box.exec("echo " + "y" * 9000 + " | wc -c", 30)
                else:
                    r = box.exec("Write-Output 'héllo'; [Console]::Error.WriteLine('oops'); exit 5", 30)
                    big = box.exec("'x' * 30000", 30)
                    slow = box.exec("Start-Sleep 20", 2)
                    long_script = box.exec("('" + "y" * 9000 + "').Length", 30)
                dest = str(tmp / f"deployed-{limits[0]}")
                box.copy_in(src, dest, ["*.log"])
                back = tmp / "back.bin"
                copied = box.copy_out(dest + "/sub/blob.bin", back)
                missing = box.copy_out(dest + "/nope", back)
            self.assertEqual((r.exit_code, r.stdout.strip()), (5, "héllo"))
            self.assertIn("oops", r.stderr)
            self.assertEqual(len(big.stdout.strip()), 30000)
            self.assertTrue(slow.timed_out)
            self.assertIn(long_script.stdout.strip(), ("9000", "9001"))
            self.assertEqual((Path(dest) / "a.txt").read_text(), "alpha")
            self.assertFalse((Path(dest) / "skip.log").exists())
            self.assertTrue(copied)
            self.assertEqual(back.read_bytes(), (src / "sub" / "blob.bin").read_bytes())
            self.assertFalse(missing)
            box.destroy()
            self.assertTrue(prov.destroyed)

    @unittest.skipUnless(shutil.which("bash") and sys.platform != "win32", "needs bash")
    def test_linux_guest(self):
        self.roundtrip("linux")

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 (pwsh) not installed")
    def test_windows_guest(self):
        self.roundtrip("windows")


# ---------------------------------------------------------------- whole pipeline on a fake cloud

class PipelineOnFakeCloudTest(unittest.TestCase):
    """Runs PatchLab Internal end to end with provider = "aws", but the "cloud" is this machine."""

    @unittest.skipUnless(shutil.which("bash") and sys.platform != "win32", "needs bash")
    def test_linux_pipeline(self):
        from patchlab_internal import cloud, report, runner
        tmp = Path(tempfile.mkdtemp())
        (tmp / "app").mkdir()
        (tmp / "app" / "version").write_text("1\n")
        (tmp / "bump.sh").write_text(f"echo 2 > {tmp}/deployed/version\n")
        cfg_file = tmp / "cloud.toml"
        cfg_file.write_text(f"""
[sandbox]
provider = "aws"
images = ["i-0fake"]
settle_seconds = 0
[sandbox.aws]
subnet_id = "subnet-x"
security_group_ids = ["sg-x"]
instance_profile = "p"
[[deploy]]
src = "app"
dest = "{tmp}/deployed"
[[checks]]
name = "version-file"
run = "test -s {tmp}/deployed/version && cat {tmp}/deployed/version"
[[checks]]
name = "still-version-1"
critical = false
run = "grep -qx 1 {tmp}/deployed/version"
[health]
enabled = false
""")
        cfg = config.load(cfg_file)
        patch = config.parse_patch_spec(f"script:{tmp}/bump.sh", None)
        made = []

        class NoRebootSandbox(CloudSandbox):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.caps = {"reboot": False, "checkpoint": False, "system_tasks": False}
                made.append(self)

        with mock.patch.object(cloud, "provider_class", lambda name: lambda o, c: LocalCloud("linux", 30000, 20000, tmp)), \
             mock.patch.object(cloud, "CloudSandbox", NoRebootSandbox), \
             mock.patch.object(base, "LINUX_GUEST_DIR", str(tmp / "guest")):
            rep = runner.run(cfg, patch, runner.Options(out_dir=tmp / "reports", quiet=True))
            report.write_all(rep)
        t = rep.targets[0]
        self.assertEqual(t.verdict, "WARN", [f.message for f in t.findings])   # non-critical check regressed
        self.assertEqual([d.transition for d in t.deltas], ["ok", "regressed"])
        self.assertTrue(made and made[0].provider.destroyed)
        self.assertEqual([s.name for s in t.stages][:3], ["clone", "boot", "deploy"])
        self.assertIn("teardown", [s.name for s in t.stages])


# ---------------------------------------------------------------- real CLI syntax

def _flows():
    """Run every provider flow against FakeCLI so RECORDED holds real command lines."""
    with mock.patch.object(base.time, "sleep", lambda s: None):
        suite = unittest.TestSuite()
        for cls in (AWSFlowTest, AzureFlowTest, GCPFlowTest, OCIFlowTest):
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
        with open(os.devnull, "w") as devnull:
            unittest.TextTestRunner(stream=devnull).run(suite)
    # Commands used by gc/list/upload paths that the flows above do not reach.
    aws = AWSProvider({**AWS_OPTS, "staging_bucket": "b"}, FakeCLI([]))
    aws._sweep("r1", "patchlab-internal-x")
    aws.list_clones("r1")
    aws.upload(Clone("patchlab-internal-x", "i-1", "r1"), b"x", "k")
    az = AzureProvider(AZ_OPTS, FakeCLI([]))
    az.list_clones("r1")
    az.upload(Clone("patchlab-internal-x", "a/b", "r1"), b"x", "k")
    o = OCIProvider({"compartment_id": "c", "subnet_id": "s", "staging_bucket": "b", "region": "uk-london-1"},
                    FakeCLI([(["preauth-request"], {"data": {"access-uri": "/p/x"}})]))
    o.upload(Clone("patchlab-internal-x", "i", "r1"), b"x", "k")
    o.list_clones("r1")


PARSE_ERRORS = ("unrecognized arguments", "the following arguments are required", "invalid choice", "Invalid choice",
                "Must be specified", "valid keys are", "Bad value",
                "Unknown options", "Unknown parameter", "Parameter validation failed", "No such option",
                "Missing option", "Invalid value", "Error parsing parameter", "expected one argument",
                "is not a valid", "Got unexpected extra argument")


def _materialise(argv: list[str], tmp: Path) -> list[str]:
    """Replace file:// and @file arguments (deleted after the flow) with real temp files."""
    out = []
    for a in argv:
        if out and out[-1] == "--file" and not os.path.exists(a):   # upload source deleted after the flow
            f = tmp / f"upload{len(out)}.bin"
            f.write_bytes(b"x")
            a = str(f)
        elif a.startswith("file://") or (a.startswith("@") and len(a) > 1 and "/" in a):
            f = tmp / f"arg{len(out)}.json"
            f.write_text('{"commands": ["echo"], "executionTimeout": ["60"]}' if "file://" in a and "aws" in argv[0]
                         else json.dumps({"source": {"sourceType": "TEXT", "text": "echo"},
                                          "output": {"outputType": "TEXT"}}) if "file://" in a else "echo")
            a = ("file://" if a.startswith("file://") else "@") + str(f)
        out.append(a)
    return out


@unittest.skipIf(os.environ.get("PATCHLAB_INTERNAL_SKIP_CLI_SYNTAX"), "PATCHLAB_INTERNAL_SKIP_CLI_SYNTAX is set")
class CLISyntaxTest(unittest.TestCase):
    """Replays recorded commands through the real CLIs against dead endpoints.

    A parse error means PatchLab Internal would build a command the CLI rejects.
    A connection/auth error means the command line itself is well formed.
    """

    @classmethod
    def setUpClass(cls):
        for k in RECORDED:
            RECORDED[k].clear()
        _flows()
        cls.tmp = Path(tempfile.mkdtemp())

    def replay(self, exe, extra, env):
        seen, bad = set(), []
        cmds = [c for c in RECORDED[exe] if tuple(c) not in seen and not seen.add(tuple(c))]
        self.assertTrue(cmds, f"no {exe} commands were recorded")
        # One sample per sub-command and flag combination keeps the run short.
        by_verb = {}
        for c in cmds:
            key = (tuple(x for x in c[1:4] if not x.startswith("-")),
                   tuple(sorted(a.split("=")[0] for a in c if a.startswith("--"))))
            by_verb.setdefault(key, c)
        lock = threading.Lock()

        def check(argv):
            argv = _materialise(argv, self.tmp) + extra
            try:
                # Through PatchLab Internal's own launcher, so Windows .cmd quoting is exercised too.
                p = subprocess.run(base.command_line(argv), capture_output=True, text=True, timeout=180,
                                   env={**os.environ, **env}, encoding="utf-8", errors="replace")
                text = p.stdout + p.stderr
            except subprocess.TimeoutExpired:
                text = ""
            hit = next((e for e in PARSE_ERRORS if e in text), None)
            if hit:
                with lock:
                    bad.append(f"{' '.join(argv[:4])}: {text.strip()[-400:]}")

        threads = [threading.Thread(target=check, args=(c,)) for c in by_verb.values()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(bad, "\n\n".join(bad))
        return len(by_verb)

    @unittest.skipUnless(shutil.which("aws"), "aws CLI not installed")
    def test_aws(self):
        n = self.replay("aws", ["--endpoint-url", "http://127.0.0.1:9", "--cli-connect-timeout", "2",
                                "--cli-read-timeout", "2"],
                        {"AWS_ACCESS_KEY_ID": "AKIAFAKE", "AWS_SECRET_ACCESS_KEY": "fake",
                         "AWS_MAX_ATTEMPTS": "1", "AWS_RETRY_MODE": "standard"})
        self.assertGreater(n, 10)

    @unittest.skipUnless(shutil.which("az"), "Azure CLI not installed")
    def test_azure(self):
        cfg = Path(tempfile.mkdtemp())
        self.assertGreater(self.replay("az", [], {"AZURE_CONFIG_DIR": str(cfg), "AZURE_CORE_COLLECT_TELEMETRY": "0"}), 8)

    @unittest.skipUnless(shutil.which("gcloud"), "gcloud CLI not installed")
    def test_gcloud(self):
        cfg = Path(tempfile.mkdtemp())
        self.assertGreater(self.replay("gcloud", [], {"CLOUDSDK_CONFIG": str(cfg), "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
                                                      "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING": "1"}), 5)

    @unittest.skipUnless(shutil.which("oci"), "OCI CLI not installed")
    def test_oci(self):
        d = Path(tempfile.mkdtemp())
        key = d / "key.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], capture_output=True, check=True)
        der = subprocess.run(["openssl", "rsa", "-pubout", "-outform", "DER", "-in", str(key)],
                             capture_output=True, check=True).stdout
        import hashlib
        fp = ":".join(f"{b:02x}" for b in hashlib.md5(der).digest())
        (d / "config").write_text(f"[DEFAULT]\nuser=ocid1.user.oc1..a\nfingerprint={fp}\ntenancy=ocid1.tenancy.oc1..a\n"
                                  f"region=uk-london-1\nkey_file={key}\n")
        os.chmod(d / "config", 0o600)
        os.chmod(key, 0o600)
        self.assertGreater(self.replay("oci", ["--config-file", str(d / "config"), "--endpoint", "http://127.0.0.1:9",
                                               "--connection-timeout", "2", "--read-timeout", "2", "--no-retry"],
                                       {"OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING": "True",
                                        "SUPPRESS_LABEL_WARNING": "True"}), 8)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- review regressions

class ExactCleanupTest(NoSleep):
    """Teardown must only ever touch the clone it is tearing down."""

    def test_aws_leftovers_are_named_and_swept_exactly(self):
        tagged = lambda name: [{"Key": "patchlab-internal-clone", "Value": name}]
        cli = FakeCLI([
            (["describe-instances"], {"Reservations": [{"Instances": [{"InstanceId": "i-1", "Tags": tagged("patchlab-internal-r1-a")}]}]}),
            (["describe-images"], {"Images": [{"ImageId": "ami-9", "Tags": tagged("patchlab-internal-r1-b")}]}),
            (["describe-snapshots"], {"Snapshots": []}),
            (["describe-volumes"], {"Volumes": [{"VolumeId": "vol-3", "Tags": tagged("patchlab-internal-r1-c")}]}),
        ])
        p = AWSProvider(AWS_OPTS, cli)
        self.assertEqual(p.list_clones("r1"), ["patchlab-internal-r1-a", "patchlab-internal-r1-b", "patchlab-internal-r1-c"])
        cli.calls.clear()
        p.destroy_named("patchlab-internal-r1-b")
        describes = [c for c in cli.calls if c[2].startswith("describe-")]
        self.assertTrue(describes and all("Name=tag:patchlab-internal-clone,Values=patchlab-internal-r1-b" in c for c in describes))
        with self.assertRaises(CloudError):
            p.destroy_named("prod-web")          # not a PatchLab Internal name
        with self.assertRaises(CloudError):
            p._sweep("r1", "")                   # never an unfiltered sweep

    def test_oci_sibling_with_longer_name_survives(self):
        items = [{"resource-type": "Instance", "identifier": "ocid.web", "display-name": "patchlab-internal-r1-web",
                  "lifecycle-state": "RUNNING", "freeform-tags": {"patchlab-internal-clone": "patchlab-internal-r1-web"}},
                 {"resource-type": "Instance", "identifier": "ocid.replica", "display-name": "patchlab-internal-r1-web-replica",
                  "lifecycle-state": "RUNNING", "freeform-tags": {"patchlab-internal-clone": "patchlab-internal-r1-web-replica"}}]
        cli = FakeCLI([(["structured-search"], {"data": {"items": items}})])
        p = OCIProvider({"compartment_id": "c", "subnet_id": "s"}, cli)
        p.destroy(Clone("patchlab-internal-r1-web", "asset", "r1"))
        terminated = [c[c.index("--instance-id") + 1] for c in cli.calls if "terminate" in c]
        self.assertEqual(terminated, ["ocid.web"])
        self.assertEqual(p.list_clones("r1"), ["patchlab-internal-r1-web", "patchlab-internal-r1-web-replica"])

    def test_gcp_teardown_before_instance_exists_only_touches_its_own_disks(self):
        def listing(argv):
            flt = next(a for a in argv if a.startswith("--filter="))
            if "patchlab-internal-clone=patchlab-internal-r1-a" in flt:
                return [{"name": "patchlab-internal-r1-a-d0", "zone": "z/europe-west2-a"}] if "disks" in argv else []
            return [{"name": "patchlab-internal-r1-b-d0", "zone": "z/europe-west2-a"}]   # the sibling's disk
        cli = FakeCLI([(["list"], listing)])
        p = GCPProvider({"project": "p", "subnet": "s"}, cli)
        p.destroy(Clone("patchlab-internal-r1-a", "europe-west2-a/web", "r1"))   # clone.instance never set
        deleted = [c[4] for c in cli.calls if c[1:4] == ["compute", "disks", "delete"]]
        self.assertEqual(deleted, ["patchlab-internal-r1-a-d0"])

    def test_cleanup_names_match_what_list_clones_reports(self):
        c = Clone("patchlab-internal-20260926-Web.01", "zone/web", "20260926")
        self.assertEqual(GCPProvider({}, FakeCLI([])).cleanup_name(c), gce_name("patchlab-internal-20260926-Web.01"))
        self.assertEqual(AzureProvider({}, FakeCLI([])).cleanup_name(c), c.name[:90])
        self.assertEqual(AWSProvider(AWS_OPTS, FakeCLI([])).cleanup_name(c), c.name)


class WindowsCmdShimTest(unittest.TestCase):
    def test_quote(self):
        self.assertEqual(base.cmd_quote('a&b"c'), '"a&b""c"')

    @unittest.skipUnless(sys.platform == "win32", "Windows only: .cmd shims")
    def test_metacharacters_survive_a_cmd_shim(self):
        d = Path(tempfile.mkdtemp())
        shim = d / "echoargs.cmd"
        shim.write_text(f'@"{sys.executable}" -c "import sys,json; print(json.dumps(sys.argv[1:]))" %*\r\n')
        args = ["a&b", "c|d", "x<y>z", "sp ace", "https://h/p?sv=1&sig=a%2Fb", "q^"]
        out = base.CLI()([str(shim), *args])
        self.assertEqual(out, args)
