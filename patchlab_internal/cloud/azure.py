"""Azure: copy a VM's managed disks into a throw-away resource group and
drive the copy with Run Command.

Clone:   one resource group per clone (patchlab-internal-<run>-<target>), tagged
         -> copy the OS and data disks straight from the source disks
            (az disk create --source; the source VM keeps running)
         -> NIC in the isolated subnet, no public IP
         -> VM that boots the copied OS disk (same size, Trusted Launch if the
            source used it)
Run:     managed Run Command (az vm run-command create), as SYSTEM / root;
         with a staging storage account the full output goes to a blob
Destroy: delete the resource group, which removes everything in one go

[sandbox.azure]
  subscription       = "..."                  # optional; else the CLI default
  subnet_id          = "/subscriptions/.../subnets/patchlab-isolated"   # REQUIRED
  nsg_id             = ""                     # optional NSG for the clone's NIC
  vm_size            = ""                     # default: same as the source
  staging_account    = "patchlabstaging"      # storage account for output/files (recommended)
  staging_container  = "patchlab_internal"
"""

from __future__ import annotations

import datetime as dt
import tempfile
import urllib.request
import uuid
from pathlib import Path

from .base import (RUN_TAG_KEY, TAG_KEY, CloudError, CloudProvider, Clone, poll, tags)


class AzureProvider(CloudProvider):
    name = "azure"
    cli_exe = "az"
    max_script_chars = 200000
    max_output_chars = 3900        # instance-view output without a staging blob
    poll_interval = 5.0

    def __init__(self, options, cli):
        super().__init__(options, cli)
        if self._staging():
            self.max_output_chars = 2_000_000

    def _staging(self) -> bool:
        return bool(self.o.get("staging_account"))

    def _az(self, *args, **kw):
        argv = ["az", *args, "--only-show-errors", "-o", "json"]
        if self.o.get("subscription") and args[0] not in ("storage",):
            argv += ["--subscription", self.o["subscription"]]
        return self.cli(argv, **kw)

    def check(self) -> str | None:
        reason = super().check()
        if reason:
            return reason
        if not self.o.get("subnet_id"):
            return "[sandbox.azure] needs subnet_id (clones must land in an isolated subnet)"
        try:
            self._az("account", "show", timeout=60)
        except CloudError as e:
            return f"Azure CLI is not logged in: {e}"
        return None

    # -- clone
    def _resolve(self, asset: str) -> dict:
        if asset.startswith("/subscriptions/"):
            vm = self._az("vm", "show", "--ids", asset, timeout=120)
        elif "/" in asset:
            rg, name = asset.split("/", 1)
            vm = self._az("vm", "show", "-g", rg, "-n", name, timeout=120)
        else:
            raise CloudError(f"Azure asset '{asset}' must be 'resource-group/vm-name' or a resource ID")
        if (vm.get("tags") or {}).get(TAG_KEY) == "1":
            raise CloudError(f"asset '{asset}' is itself a PatchLab Internal clone")
        return vm

    def _tag_args(self, clone: Clone) -> list[str]:
        return [f"{k}={v}" for k, v in tags(clone, clone.asset.rsplit("/", 1)[-1]).items()]

    def cleanup_name(self, clone: Clone) -> str:
        return clone.name[:90]      # the clone's resource group

    def clone(self, clone: Clone, expected_os: str, timeout: float, cancel=None) -> None:
        vm = self._resolve(clone.asset)
        storage = vm["storageProfile"]
        os_ = storage["osDisk"]["osType"].lower()
        if os_ != expected_os:
            raise CloudError(f"asset '{clone.asset}' runs {os_} but the config is for {expected_os}")
        clone.os = os_
        location = vm["location"]
        zone = (vm.get("zones") or [None])[0]
        rg = self.cleanup_name(clone)
        clone.location = rg
        tag_args = self._tag_args(clone)

        self._az("group", "create", "-n", rg, "-l", location, "--tags", *tag_args, timeout=300)
        clone.add("resource-group", rg)

        def copy_disk(src_id: str, new_name: str, is_os: bool) -> str:
            src = self._az("disk", "show", "--ids", src_id, timeout=120)
            args = ["disk", "create", "-g", rg, "-n", new_name, "--source", src_id,
                    "--sku", src.get("sku", {}).get("name", "Premium_LRS"), "--tags", *tag_args]
            if zone:
                args += ["--zone", zone]
            if is_os:
                args += ["--os-type", storage["osDisk"]["osType"]]
                if src.get("hyperVGeneration"):
                    args += ["--hyper-v-generation", src["hyperVGeneration"]]
                sec = (src.get("securityProfile") or {}).get("securityType")
                if sec == "TrustedLaunch":
                    args += ["--security-type", sec]
            disk = self._az(*args, timeout=timeout)
            clone.add("disk", disk["id"])
            return disk["id"]

        os_disk = copy_disk(storage["osDisk"]["managedDisk"]["id"], f"{clone.name}-os", True)
        data_disks = [copy_disk(d["managedDisk"]["id"], f"{clone.name}-data{d['lun']}", False)
                      for d in sorted(storage.get("dataDisks", []), key=lambda d: d["lun"])]

        nic_args = ["network", "nic", "create", "-g", rg, "-n", f"{clone.name}-nic",
                    "--subnet", self.o["subnet_id"], "--tags", *tag_args]
        if self.o.get("nsg_id"):
            nic_args += ["--network-security-group", self.o["nsg_id"]]
        nic = self._az(*nic_args, timeout=300)
        nic_id = nic.get("NewNIC", nic)["id"]
        clone.add("nic", nic_id)

        vm_args = ["vm", "create", "-g", rg, "-n", clone.name[:64], "--attach-os-disk", os_disk,
                   "--os-type", os_, "--nics", nic_id,
                   "--size", self.o.get("vm_size") or vm["hardwareProfile"]["vmSize"], "--tags", *tag_args]
        if data_disks:
            vm_args += ["--attach-data-disks", *data_disks]
        if zone:
            vm_args += ["--zone", zone]
        sec = (vm.get("securityProfile") or {})
        if sec.get("securityType") == "TrustedLaunch":
            uefi = sec.get("uefiSettings") or {}
            vm_args += ["--security-type", "TrustedLaunch",
                        "--enable-secure-boot", str(bool(uefi.get("secureBootEnabled"))).lower(),
                        "--enable-vtpm", str(bool(uefi.get("vTpmEnabled"))).lower()]
        created = self._az(*vm_args, timeout=1800)
        clone.instance = clone.name[:64]
        clone.info["vm_id"] = (created or {}).get("id", "")

    def wait_agent(self, clone: Clone, timeout: float, cancel=None) -> None:
        def ready():
            view = self._az("vm", "get-instance-view", "-g", clone.location, "-n", clone.instance, timeout=120)
            statuses = ((view.get("instanceView") or {}).get("vmAgent") or {}).get("statuses") or []
            return any(s.get("displayStatus") == "Ready" for s in statuses)

        poll(f"Azure VM agent on {clone.instance}", ready, timeout, interval=15, cancel=cancel)

    # -- staging storage
    def _sas(self, blob: str, permissions: str, hours: int = 6) -> str:
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%MZ")
        url = self._az("storage", "blob", "generate-sas", "--account-name", self.o["staging_account"],
                       "--container-name", self.o.get("staging_container", "patchlab_internal"), "--name", blob,
                       "--permissions", permissions, "--expiry", expiry, "--auth-mode", "login",
                       "--as-user", "--full-uri", "--https-only", timeout=120)
        return url.strip('"') if isinstance(url, str) else str(url)

    def _read_blob(self, url: str) -> str | None:
        try:
            with urllib.request.urlopen(url, timeout=300) as resp:
                return resp.read().decode("utf-8", "replace")
        except OSError:
            return None

    # -- run
    def run(self, clone: Clone, script: str, timeout: int) -> str:
        rc_name = f"pl{uuid.uuid4().hex[:12]}"
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(script)
            script_file = f.name
        args = ["vm", "run-command", "create", "-g", clone.location, "--vm-name", clone.instance,
                "--run-command-name", rc_name, "--script", f"@{script_file}",
                "--async-execution", "false", "--timeout-in-seconds", str(int(timeout))]
        out_url = err_url = None
        if self._staging():
            prefix = f"{clone.run_id}/{clone.name}/{rc_name}"
            out_url, err_url = self._sas(f"{prefix}.out", "racw"), self._sas(f"{prefix}.err", "racw")
            args += ["--output-blob-uri", out_url, "--error-blob-uri", err_url]
        try:
            self._az(*args, timeout=timeout + 900, check=False)
            view = self._az("vm", "run-command", "show", "-g", clone.location, "--vm-name", clone.instance,
                            "--run-command-name", rc_name, "--instance-view", timeout=120)
        finally:
            Path(script_file).unlink(missing_ok=True)
        iv = (view or {}).get("instanceView") or {}
        state = iv.get("executionState")
        output = (self._read_blob(out_url) if out_url else None) or iv.get("output") or ""
        self._az("vm", "run-command", "delete", "-g", clone.location, "--vm-name", clone.instance,
                 "--run-command-name", rc_name, "--yes", timeout=600, check=False, json_out=False)
        if state not in ("Succeeded", "Failed", "TimedOut") and not output:
            raise CloudError(f"Run Command on {clone.instance} ended in state {state}: {iv.get('error', '')}")
        return output

    def upload(self, clone: Clone, data: bytes, key: str) -> str | None:
        if not self._staging():
            return None
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            local = f.name
        try:
            self._az("storage", "blob", "upload", "--account-name", self.o["staging_account"],
                     "--container-name", self.o.get("staging_container", "patchlab_internal"), "--name", key,
                     "--file", local, "--overwrite", "--auth-mode", "login", timeout=900)
            return self._sas(key, "r", hours=2)
        finally:
            Path(local).unlink(missing_ok=True)

    # -- destroy
    def destroy(self, clone: Clone) -> None:
        if clone.location:
            self._delete_group(clone.location)
        if self._staging():
            self._az("storage", "blob", "delete-batch", "--account-name", self.o["staging_account"],
                     "--source", self.o.get("staging_container", "patchlab_internal"),
                     "--pattern", f"{clone.run_id}/{clone.name}/*", "--auth-mode", "login",
                     timeout=600, check=False)

    def _delete_group(self, rg: str) -> None:
        group = self._az("group", "show", "-n", rg, timeout=120, check=False)
        if not isinstance(group, dict):
            return   # already gone
        if not rg.startswith("patchlab-internal-") or (group.get("tags") or {}).get(TAG_KEY) != "1":
            raise CloudError(f"refusing to delete resource group '{rg}': not a PatchLab Internal clone group")
        self._az("group", "delete", "-n", rg, "--yes", timeout=3600, json_out=False)

    def list_clones(self, run_id: str | None = None) -> list[str]:
        groups = self._az("group", "list", "--tag", f"{TAG_KEY}=1", timeout=120) or []
        return sorted(g["name"] for g in groups
                      if g["name"].startswith("patchlab-internal-")
                      and (not run_id or (g.get("tags") or {}).get(RUN_TAG_KEY) == run_id))

    def destroy_named(self, name: str) -> None:
        self._delete_group(name)
