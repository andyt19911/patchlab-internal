"""Google Cloud: clone a Compute Engine instance's disks and drive the copy
over SSH through Identity-Aware Proxy (no public IP, no inbound firewall hole).

Clone:   copy every disk straight from the source disk
         (gcloud compute disks create --source-disk; the source keeps running)
         -> instance in the isolated subnet, --no-address, no service account,
            Shielded VM settings copied, source metadata (startup scripts,
            SSH keys) NOT copied
Run:     gcloud compute ssh --tunnel-through-iap (Windows guests need the
         built-in OpenSSH server, enabled with metadata enable-windows-ssh=TRUE)
Destroy: delete the instance with all its disks, then sweep labelled disks

[sandbox.gcp]
  project       = "my-project"
  zone          = ""                        # default: the source instance's zone
  subnet        = "projects/P/regions/R/subnetworks/patchlab-isolated"   # REQUIRED
  network_tags  = ["patchlab-internal-isolated"]     # tags your IAP/egress firewall rules match
  machine_type  = ""                        # default: same as the source
"""

from __future__ import annotations

import re
import tempfile
import uuid
from pathlib import Path

from .base import (CLONE_TAG_KEY, RUN_TAG_KEY, TAG_KEY, CloudError, CloudProvider, Clone, poll, tags)


def gce_name(text: str, limit: int = 63) -> str:
    """Lower-case, dash-separated, starts with a letter: valid for GCE names and labels."""
    s = re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")
    if not s or not s[0].isalpha():
        s = "p-" + s
    return s[:limit].rstrip("-")


class GCPProvider(CloudProvider):
    name = "gcp"
    cli_exe = "gcloud"
    # Scripts travel as files over scp and output streams back over SSH.
    max_script_chars = 10_000_000
    max_output_chars = 10_000_000
    poll_interval = 0

    def _gcloud(self, *args, **kw):
        argv = ["gcloud", *args, "--quiet"]
        if self.o.get("project"):
            argv += ["--project", self.o["project"]]
        if kw.pop("fmt", True):
            argv += ["--format=json"]
        return self.cli(argv, **kw)

    def check(self) -> str | None:
        reason = super().check()
        if reason:
            return reason
        if not self.o.get("subnet"):
            return "[sandbox.gcp] needs subnet (clones must land in an isolated subnet)"
        try:
            accounts = self._gcloud("auth", "list", "--filter=status:ACTIVE", timeout=60)
            if not accounts:
                return "gcloud has no active account (gcloud auth login / activate-service-account)"
        except CloudError as e:
            return f"gcloud is not usable: {e}"
        return None

    @staticmethod
    def _last(url: str) -> str:
        return url.rstrip("/").rsplit("/", 1)[-1]

    def _labels(self, clone: Clone) -> str:
        return ",".join(f"{gce_name(k)}={gce_name(v)}" for k, v in tags(clone).items())

    def cleanup_name(self, clone: Clone) -> str:
        return gce_name(clone.name)     # also the instance name and its patchlab-internal-clone label

    # -- clone
    def _resolve(self, asset: str) -> tuple[dict, str]:
        zone, _, name = asset.rpartition("/")
        zone = zone or self.o.get("zone")
        if not zone:
            raise CloudError(f"GCP asset '{asset}' needs a zone: use 'zone/instance' or set [sandbox.gcp] zone")
        inst = self._gcloud("compute", "instances", "describe", name, "--zone", zone, timeout=120)
        if (inst.get("labels") or {}).get(TAG_KEY) == "1":
            raise CloudError(f"asset '{asset}' is itself a PatchLab Internal clone")
        return inst, zone

    def clone(self, clone: Clone, expected_os: str, timeout: float, cancel=None) -> None:
        inst, src_zone = self._resolve(clone.asset)
        zone = self.o.get("zone") or src_zone
        licenses = " ".join(lic for d in inst.get("disks", []) for lic in d.get("licenses", []))
        features = " ".join(f.get("type", "") for d in inst.get("disks", []) for f in d.get("guestOsFeatures", []))
        os_ = "windows" if ("windows-cloud" in licenses or "WINDOWS" in features) else "linux"
        if os_ != expected_os:
            raise CloudError(f"asset '{clone.asset}' runs {os_} but the config is for {expected_os}")
        clone.os = os_
        clone.location = zone
        name = gce_name(clone.name)
        clone.instance = name
        labels = self._labels(clone)

        disk_args = []
        for i, d in enumerate(sorted(inst.get("disks", []), key=lambda d: (not d.get("boot"), d.get("index", 0)))):
            if d.get("type") != "PERSISTENT":
                continue   # local SSDs cannot be copied
            src = self._gcloud("compute", "disks", "describe", self._last(d["source"]),
                               "--zone", src_zone, timeout=120)
            new = gce_name(f"{name}-d{i}")
            self._gcloud("compute", "disks", "create", new, "--zone", zone, f"--source-disk={d['source']}",
                         f"--type={self._last(src.get('type', 'pd-balanced'))}", f"--labels={labels}",
                         timeout=timeout)
            clone.add("disk", f"{zone}/{new}")
            spec = f"name={new},auto-delete=yes,device-name={d.get('deviceName', new)}"
            disk_args.append(f"--disk={spec},boot=yes" if d.get("boot") else f"--disk={spec}")

        args = ["compute", "instances", "create", name, "--zone", zone,
                f"--machine-type={self.o.get('machine_type') or self._last(inst['machineType'])}",
                f"--subnet={self.o['subnet']}", "--no-address", "--no-service-account", "--no-scopes",
                f"--labels={labels}", *disk_args]
        if self.o.get("network_tags"):
            args.append(f"--tags={','.join(self.o['network_tags'])}")
        shielded = inst.get("shieldedInstanceConfig") or {}
        if shielded.get("enableSecureBoot"):
            args.append("--shielded-secure-boot")
        if shielded.get("enableVtpm"):
            args.append("--shielded-vtpm")
        if shielded.get("enableIntegrityMonitoring"):
            args.append("--shielded-integrity-monitoring")
        if os_ == "windows":
            args.append("--metadata=enable-windows-ssh=TRUE,sysprep-specialize-script-ps1=")
        self._gcloud(*args, timeout=900)
        clone.add("instance", f"{zone}/{name}")

    def _ssh_base(self, clone: Clone) -> list[str]:
        return ["--zone", clone.location, "--tunnel-through-iap", "--strict-host-key-checking=no"]

    def wait_agent(self, clone: Clone, timeout: float, cancel=None) -> None:
        def running():
            inst = self._gcloud("compute", "instances", "describe", clone.instance, "--zone", clone.location,
                                timeout=120)
            return inst.get("status") == "RUNNING"

        poll(f"GCE instance {clone.instance}", running, timeout, interval=10, cancel=cancel)
        probe = "echo @@PLOK" if clone.os == "linux" else "echo @@PLOK"
        poll(f"SSH to {clone.instance} through IAP",
             lambda: "@@PLOK" in self._ssh(clone, probe, 120), timeout, interval=20, cancel=cancel)

    def _ssh(self, clone: Clone, command: str, timeout: int) -> str:
        return self._gcloud("compute", "ssh", clone.instance, *self._ssh_base(clone), f"--command={command}",
                            timeout=timeout, json_out=False, fmt=False) or ""

    # -- run
    def run(self, clone: Clone, script: str, timeout: int) -> str:
        ext = "ps1" if clone.os == "windows" else "sh"
        remote = f"pl-{uuid.uuid4().hex}.{ext}"
        with tempfile.NamedTemporaryFile("w", suffix=f".{ext}", delete=False,
                                         encoding="utf-8-sig" if ext == "ps1" else "utf-8", newline="\n") as f:
            f.write(script)
            local = f.name
        try:
            self._gcloud("compute", "scp", local, f"{clone.instance}:{remote}", *self._ssh_base(clone),
                         timeout=600, json_out=False, fmt=False)
        finally:
            Path(local).unlink(missing_ok=True)
        if clone.os == "windows":
            cmd = (f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {remote} "
                   f"& del {remote}")
        else:
            cmd = f"bash {remote}; rc=$?; rm -f {remote}; exit $rc"
        return self._ssh(clone, cmd, timeout + 600)

    # -- destroy
    def destroy(self, clone: Clone) -> None:
        self.destroy_named(self.cleanup_name(clone))

    def _by_label(self, kind: str, label: str) -> list[dict]:
        flt = f"labels.{TAG_KEY}=1 AND labels.{CLONE_TAG_KEY}={label}"   # exact match, never a prefix
        return self._gcloud("compute", kind, "list", f"--filter={flt}", timeout=120) or []

    def list_clones(self, run_id: str | None = None) -> list[str]:
        flt = f"labels.{TAG_KEY}=1" + (f" AND labels.{RUN_TAG_KEY}={gce_name(run_id)}" if run_id else "")
        found = set()
        for kind in ("instances", "disks"):
            for item in self._gcloud("compute", kind, "list", f"--filter={flt}", timeout=120) or []:
                label = (item.get("labels") or {}).get(CLONE_TAG_KEY)
                if label and (kind == "instances" or not item.get("users")):
                    found.add(label)
        return sorted(found)

    def destroy_named(self, name: str) -> None:
        if not name.startswith("patchlab-internal-"):
            raise CloudError(f"refusing to delete '{name}': not a PatchLab Internal clone")
        for inst in self._by_label("instances", name):
            self._gcloud("compute", "instances", "delete", inst["name"], "--zone", self._last(inst["zone"]),
                         "--delete-disks=all", timeout=1200, check=False, json_out=False)
        for disk in self._by_label("disks", name):
            if not disk.get("users"):
                self._gcloud("compute", "disks", "delete", disk["name"], "--zone", self._last(disk["zone"]),
                             timeout=600, check=False, json_out=False)
