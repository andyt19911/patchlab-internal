"""Oracle Cloud Infrastructure: clone an instance's boot and block volumes and
drive the copy with the Oracle Cloud Agent's Run Command.

Clone:   clone the boot volume and each block volume directly from the source
         (no downtime), launch an instance from the cloned boot volume in the
         isolated subnet without a public IP, attach the cloned block volumes
Run:     oci instance-agent command create. Linux scripts run in bash as the
         `ocarun` user (PatchLab Internal elevates with `sudo -n`); Windows scripts run
         in cmd, so PatchLab Internal ships PowerShell through certutil-decoded base64
Destroy: terminate (boot volume included), delete cloned block volumes, then
         sweep anything carrying the run's freeform tag

[sandbox.oci]
  profile          = "DEFAULT"                # ~/.oci/config profile (or use instance principals)
  auth             = ""                       # "instance_principal" to use the runner's identity
  region           = "uk-london-1"
  compartment_id   = "ocid1.compartment..."   # REQUIRED: where clones are created
  source_compartment_id = ""                  # where to look up assets by name (default: compartment_id)
  subnet_id        = "ocid1.subnet..."        # REQUIRED: isolated subnet
  nsg_ids          = []                       # optional network security groups
  shape            = ""                       # default: same shape/config as the source
  staging_bucket   = ""                       # optional Object Storage bucket for fast file transfer
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import tempfile
import uuid
from pathlib import Path

from .base import (CLONE_TAG_KEY, RUN_TAG_KEY, TAG_KEY, CloudError, CloudProvider, Clone, poll, tags)

DONE = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}


def batch_for_powershell(script: str, line: int = 7000) -> str:
    """cmd script that rebuilds a PowerShell file from base64 and runs it.

    cmd lines are limited to 8191 characters, so the script travels as
    base64 in short `echo` lines that certutil decodes back into a .ps1.
    """
    b64 = base64.b64encode(b"\xef\xbb\xbf" + script.encode("utf-8")).decode("ascii")
    ident = uuid.uuid4().hex
    lines = ["@echo off",
             "set D=%ProgramData%\\PatchLabInternal",
             'if not exist "%D%" mkdir "%D%"',
             f"set F=%D%\\oc-{ident}",
             "("]
    lines += [f"echo {b64[i:i + line]}" for i in range(0, len(b64), line)]
    lines += [') > "%F%.b64"',
              'certutil -f -decode "%F%.b64" "%F%.ps1" >nul',
              'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%F%.ps1"',
              "set RC=%ERRORLEVEL%",
              'del /q "%F%.b64" "%F%.ps1"',
              "exit /b %RC%"]
    return "\r\n".join(lines) + "\r\n"


class OCIProvider(CloudProvider):
    name = "oci"
    cli_exe = "oci"
    max_script_chars = 90000
    max_output_chars = 60000
    poll_interval = 5.0

    def _oci(self, *args, **kw):
        argv = ["oci", *args]
        if self.o.get("auth"):
            argv += ["--auth", self.o["auth"]]
        elif self.o.get("profile"):
            argv += ["--profile", self.o["profile"]]
        if self.o.get("region"):
            argv += ["--region", self.o["region"]]
        return self.cli(argv, **kw)

    def check(self) -> str | None:
        reason = super().check()
        if reason:
            return reason
        missing = [k for k in ("compartment_id", "subnet_id") if not self.o.get(k)]
        if missing:
            return f"[sandbox.oci] needs {', '.join(missing)} (clones must land in an isolated subnet)"
        try:
            self._oci("iam", "compartment", "get", "--compartment-id", self.o["compartment_id"], timeout=60)
        except CloudError as e:
            return f"OCI CLI cannot reach the compartment: {e}"
        return None

    def _tags(self, clone: Clone) -> str:
        return json.dumps(tags(clone))

    # -- clone
    def _resolve(self, asset: str) -> dict:
        if asset.startswith("ocid1.instance."):
            inst = self._oci("compute", "instance", "get", "--instance-id", asset, timeout=120)["data"]
        else:
            comp = self.o.get("source_compartment_id") or self.o["compartment_id"]
            found = [i for i in (self._oci("compute", "instance", "list", "-c", comp, "--display-name", asset,
                                           "--all", timeout=120) or {}).get("data", [])
                     if i.get("lifecycle-state") in ("RUNNING", "STOPPED")]
            if len(found) != 1:
                raise CloudError(f"asset '{asset}' matched {len(found)} instances (need exactly one)")
            inst = found[0]
        if (inst.get("freeform-tags") or {}).get(TAG_KEY) == "1":
            raise CloudError(f"asset '{asset}' is itself a PatchLab Internal clone")
        return inst

    def clone(self, clone: Clone, expected_os: str, timeout: float, cancel=None) -> None:
        src = self._resolve(clone.asset)
        ad, src_comp = src["availability-domain"], src["compartment-id"]
        comp = self.o["compartment_id"]
        os_ = expected_os
        image_id = (src.get("source-details") or {}).get("image-id")
        if image_id:
            try:
                img = self._oci("compute", "image", "get", "--image-id", image_id, timeout=120)["data"]
                os_ = "windows" if "windows" in img.get("operating-system", "").lower() else "linux"
            except CloudError:
                pass   # image deleted since launch: trust the config
        if os_ != expected_os:
            raise CloudError(f"asset '{clone.asset}' runs {os_} but the config is for {expected_os}")
        clone.os = os_
        clone.info.update(compartment=comp, ad=ad)
        tag_json = self._tags(clone)
        wait = ["--wait-for-state", "AVAILABLE", "--max-wait-seconds", str(int(timeout))]

        bva = (self._oci("compute", "boot-volume-attachment", "list", "--availability-domain", ad,
                         "-c", src_comp, "--instance-id", src["id"], timeout=120) or {}).get("data", [])
        if not bva:
            raise CloudError(f"no boot volume found for {clone.asset}")
        boot = self._oci("bv", "boot-volume", "create", "--source-boot-volume-id", bva[0]["boot-volume-id"],
                         "-c", comp, "--availability-domain", ad, "--display-name", f"{clone.name}-boot",
                         "--freeform-tags", tag_json, *wait, timeout=timeout + 120)["data"]
        clone.add("boot-volume", boot["id"])

        data_volumes = []
        for va in (self._oci("compute", "volume-attachment", "list", "-c", src_comp, "--instance-id", src["id"],
                             "--all", timeout=120) or {}).get("data", []):
            if va.get("lifecycle-state") != "ATTACHED":
                continue
            vol = self._oci("bv", "volume", "create", "--source-volume-id", va["volume-id"], "-c", comp,
                            "--availability-domain", ad, "--display-name", f"{clone.name}-data{len(data_volumes)}",
                            "--freeform-tags", tag_json, *wait, timeout=timeout + 120)["data"]
            clone.add("volume", vol["id"])
            data_volumes.append(vol["id"])

        shape = self.o.get("shape") or src["shape"]
        args = ["compute", "instance", "launch", "-c", comp, "--availability-domain", ad, "--shape", shape,
                "--subnet-id", self.o["subnet_id"], "--assign-public-ip", "false",
                "--source-boot-volume-id", boot["id"], "--display-name", clone.name,
                "--freeform-tags", tag_json,
                "--agent-config", json.dumps({"pluginsConfig": [
                    {"name": "Compute Instance Run Command", "desiredState": "ENABLED"}]}),
                "--wait-for-state", "RUNNING", "--max-wait-seconds", "1800"]
        cfg = src.get("shape-config") or {}
        if not self.o.get("shape") and ".Flex" in shape and cfg.get("ocpus"):
            args += ["--shape-config", json.dumps({"ocpus": cfg["ocpus"], "memoryInGBs": cfg.get("memory-in-gbs")})]
        if self.o.get("nsg_ids"):
            args += ["--nsg-ids", json.dumps(list(self.o["nsg_ids"]))]
        inst = self._oci(*args, timeout=2000)["data"]
        clone.instance = inst["id"]
        clone.add("instance", inst["id"])
        for vid in data_volumes:
            self._oci("compute", "volume-attachment", "attach", "--instance-id", clone.instance,
                      "--volume-id", vid, "--type", "paravirtualized", "--wait-for-state", "ATTACHED",
                      "--max-wait-seconds", "900", timeout=1000)

    def wait_agent(self, clone: Clone, timeout: float, cancel=None) -> None:
        probe = "echo @@PLOK"
        poll(f"Oracle Cloud Agent Run Command on {clone.name}",
             lambda: "@@PLOK" in self.run(clone, probe, 120), timeout, interval=20, cancel=cancel)

    # -- run
    def run(self, clone: Clone, script: str, timeout: int) -> str:
        text = batch_for_powershell(script) if clone.os == "windows" else script
        content = {"source": {"sourceType": "TEXT", "text": text}, "output": {"outputType": "TEXT"}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(content, f)
            content_file = f.name
        try:
            cmd = self._oci("instance-agent", "command", "create", "-c", clone.info["compartment"],
                            "--target", json.dumps({"instanceId": clone.instance}),
                            "--content", f"file://{content_file}", "--timeout-in-seconds", str(int(timeout)),
                            "--display-name", f"patchlab-internal-{clone.run_id}", timeout=120)["data"]["id"]
        finally:
            Path(content_file).unlink(missing_ok=True)

        def done():
            ex = self._oci("instance-agent", "command-execution", "get", "--instance-id", clone.instance,
                           "--command-id", cmd, timeout=60)["data"]
            return ex if ex.get("lifecycle-state") in DONE else None

        ex = poll(f"Run Command {cmd}", done, timeout + 900, interval=self.poll_interval)
        return (ex.get("content") or {}).get("text") or ""

    def upload(self, clone: Clone, data: bytes, key: str) -> str | None:
        bucket = self.o.get("staging_bucket")
        if not bucket:
            return None
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            local = f.name
        try:
            obj = f"patchlab_internal/{key}"
            self._oci("os", "object", "put", "--bucket-name", bucket, "--name", obj, "--file", local,
                      "--force", timeout=900)
            expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            par = self._oci("os", "preauth-request", "create", "--bucket-name", bucket, "--name",
                            f"patchlab-internal-{uuid.uuid4().hex[:8]}", "--access-type", "ObjectRead",
                            "--object-name", obj, "--time-expires", expires, timeout=120)["data"]
            return par.get("full-path") or (f"https://objectstorage.{self.o.get('region')}.oraclecloud.com"
                                            f"{par['access-uri']}")
        finally:
            Path(local).unlink(missing_ok=True)

    # -- destroy
    def destroy(self, clone: Clone) -> None:
        # First the exact resources this clone recorded, then anything else tagged with its name.
        for kind, rid in reversed(clone.resources):
            self._delete(kind, rid)
        self._sweep(clone.run_id, clone.name)
        if self.o.get("staging_bucket"):
            self._oci("os", "object", "bulk-delete", "--bucket-name", self.o["staging_bucket"],
                      "--prefix", f"patchlab_internal/{clone.run_id}/{clone.name}/", "--force", timeout=600, check=False)

    def _delete(self, kind: str, rid: str) -> None:
        if kind in ("instance", "Instance"):
            self._oci("compute", "instance", "terminate", "--instance-id", rid,
                      # terminate waits on its work request, hence SUCCEEDED rather than TERMINATED
                      "--preserve-boot-volume", "false", "--force", "--wait-for-state", "SUCCEEDED",
                      "--max-wait-seconds", "1800", timeout=1900, check=False)
        elif kind in ("volume", "Volume"):
            self._oci("bv", "volume", "delete", "--volume-id", rid, "--force", timeout=600, check=False)
        elif kind in ("boot-volume", "BootVolume"):
            self._oci("bv", "boot-volume", "delete", "--boot-volume-id", rid, "--force", timeout=600, check=False)

    def _search(self, run_id: str | None = None, clone_name: str | None = None) -> list[dict]:
        cond = f"(freeformTags.key = '{TAG_KEY}' && freeformTags.value = '1')"
        if run_id:
            cond += f" && (freeformTags.key = '{RUN_TAG_KEY}' && freeformTags.value = '{run_id}')"
        if clone_name:
            cond += f" && (freeformTags.key = '{CLONE_TAG_KEY}' && freeformTags.value = '{clone_name}')"
        res = self._oci("search", "resource", "structured-search", "--query-text",
                        f"query instance, volume, bootvolume resources where {cond}", timeout=120) or {}
        items = [r for r in (res.get("data") or {}).get("items", [])
                 if r.get("lifecycle-state") not in ("TERMINATED", "TERMINATING")]
        if clone_name:   # belt and braces: exact tag value, never a display-name prefix
            items = [r for r in items if (r.get("freeform-tags") or {}).get(CLONE_TAG_KEY, clone_name) == clone_name]
        return items

    def _sweep(self, run_id: str | None, clone_name: str) -> None:
        if not clone_name:
            raise CloudError("refusing to sweep without a clone name")
        items = self._search(run_id, clone_name)
        for r in sorted(items, key=lambda r: r["resource-type"] != "Instance"):   # instances first
            self._delete(r["resource-type"], r["identifier"])

    def list_clones(self, run_id: str | None = None) -> list[str]:
        return sorted({(r.get("freeform-tags") or {}).get(CLONE_TAG_KEY) for r in self._search(run_id)} - {None})

    def destroy_named(self, name: str) -> None:
        if not name.startswith("patchlab-internal-"):
            raise CloudError(f"refusing to delete '{name}': not a PatchLab Internal clone")
        self._sweep(None, name)
