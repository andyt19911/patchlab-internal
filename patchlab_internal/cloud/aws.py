"""AWS: clone an EC2 instance through an AMI and drive it with SSM Run Command.

Clone:   create-image --no-reboot (the source keeps running, crash-consistent)
         -> run-instances from that AMI into the isolated subnet, no public IP,
            IMDSv2 only, every volume deleted on termination
         -> deregister the AMI and delete its snapshots as soon as the clone runs
Run:     SSM send-command (AWS-RunShellScript / AWS-RunPowerShellScript), as
         root / SYSTEM, optionally writing full output to S3
Destroy: terminate, then sweep anything tagged with the run id

[sandbox.aws]
  region               = "eu-west-2"
  profile              = "patchlab_internal"            # optional; else the default credential chain
  subnet_id            = "subnet-..."          # REQUIRED: isolated subnet (see docs/CLOUD.md)
  security_group_ids   = ["sg-..."]            # REQUIRED: no inbound rules
  instance_profile     = "PatchLabInternalSSM"         # REQUIRED: role with AmazonSSMManagedInstanceCore
  instance_type        = ""                    # default: same as the source
  staging_bucket       = ""                    # optional: S3 bucket for output + file transfer
  kms_key_id           = ""                    # optional: re-encrypt clone volumes with this key
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .base import (CLONE_TAG_KEY, RUN_TAG_KEY, TAG_KEY, CloudError, CloudProvider, Clone, poll, tags)

TERMINAL_SSM = {"Success", "Failed", "TimedOut", "Cancelled", "Cancelling", "DeliveryTimedOut",
                "Undeliverable", "Terminated", "InvalidPlatform", "AccessDenied"}


def _tag_specs(kinds: list[str], t: dict[str, str]) -> str:
    return json.dumps([{"ResourceType": k, "Tags": [{"Key": a, "Value": b} for a, b in t.items()]}
                       for k in kinds])


class AWSProvider(CloudProvider):
    name = "aws"
    cli_exe = "aws"
    # SSM returns at most 24,000 characters of stdout inline; the parameter
    # payload is limited too, so stay well inside both.
    max_script_chars = 30000
    max_output_chars = 23000

    def __init__(self, options, cli):
        super().__init__(options, cli)
        if options.get("staging_bucket"):
            self.max_output_chars = 2_000_000   # full output comes from S3

    def _aws(self, *args, **kw):
        argv = ["aws", *args, "--output", "json"]
        if self.o.get("region"):
            argv += ["--region", self.o["region"]]
        if self.o.get("profile"):
            argv += ["--profile", self.o["profile"]]
        return self.cli(argv, **kw)

    def check(self) -> str | None:
        reason = super().check()
        if reason:
            return reason
        missing = [k for k in ("subnet_id", "security_group_ids", "instance_profile") if not self.o.get(k)]
        if missing:
            return f"[sandbox.aws] needs {', '.join(missing)} (clones must land in an isolated subnet)"
        try:
            self._aws("sts", "get-caller-identity", timeout=60)
        except CloudError as e:
            return f"AWS credentials are not usable: {e}"
        return None

    # -- clone
    def _resolve(self, asset: str) -> dict:
        if asset.startswith("i-"):
            args = ["--instance-ids", asset]
        elif asset.startswith("tag:") and "=" in asset:
            k, v = asset[4:].split("=", 1)
            args = ["--filters", f"Name=tag:{k},Values={v}", "Name=instance-state-name,Values=running,stopped"]
        else:
            args = ["--filters", f"Name=tag:Name,Values={asset}", "Name=instance-state-name,Values=running,stopped"]
        data = self._aws("ec2", "describe-instances", *args, timeout=120) or {}
        found = [i for r in data.get("Reservations", []) for i in r.get("Instances", [])]
        if len(found) != 1:
            raise CloudError(f"asset '{asset}' matched {len(found)} instances (need exactly one)")
        inst = found[0]
        if any(t.get("Key") == TAG_KEY for t in inst.get("Tags", [])):
            raise CloudError(f"asset '{asset}' is itself a PatchLab Internal clone")
        return inst

    def clone(self, clone: Clone, expected_os: str, timeout: float, cancel=None) -> None:
        src = self._resolve(clone.asset)
        os_ = "windows" if "windows" in (src.get("PlatformDetails", "") + src.get("Platform", "")).lower() else "linux"
        if os_ != expected_os:
            raise CloudError(f"asset '{clone.asset}' runs {os_} but the config is for {expected_os}")
        clone.os = os_
        clone.info["source_instance"] = src["InstanceId"]
        t = {**tags(clone), "Name": clone.name}

        img = self._aws("ec2", "create-image", "--instance-id", src["InstanceId"], "--name", clone.name,
                        "--description", f"PatchLab Internal clone of {src['InstanceId']} (temporary)",
                        "--no-reboot", "--tag-specifications", _tag_specs(["image", "snapshot"], t),
                        timeout=300)
        image_id = img["ImageId"]
        clone.add("image", image_id)

        def image_ready():
            d = self._aws("ec2", "describe-images", "--image-ids", image_id, timeout=120)
            state = d["Images"][0]["State"] if d.get("Images") else "pending"
            if state in ("failed", "invalid", "error", "deregistered"):
                raise RuntimeError(f"AMI {image_id} entered state {state}")
            return d["Images"][0] if state == "available" else None

        try:
            image = poll(f"AMI {image_id}", image_ready, timeout, interval=15, cancel=cancel)
        except RuntimeError as e:
            raise CloudError(str(e)) from None
        for m in image.get("BlockDeviceMappings", []):
            if m.get("Ebs", {}).get("SnapshotId"):
                clone.add("snapshot", m["Ebs"]["SnapshotId"])

        mappings = []
        for m in image.get("BlockDeviceMappings", []):
            if "Ebs" in m:
                ebs = {"DeleteOnTermination": True}
                if self.o.get("kms_key_id"):
                    ebs.update({"Encrypted": True, "KmsKeyId": self.o["kms_key_id"]})
                mappings.append({"DeviceName": m["DeviceName"], "Ebs": ebs})
        nic = [{"DeviceIndex": 0, "SubnetId": self.o["subnet_id"], "Groups": list(self.o["security_group_ids"]),
                "AssociatePublicIpAddress": False, "DeleteOnTermination": True}]
        profile = self.o["instance_profile"]
        run = self._aws(
            "ec2", "run-instances", "--image-id", image_id,
            "--instance-type", self.o.get("instance_type") or src["InstanceType"],
            "--count", "1", "--network-interfaces", json.dumps(nic),
            "--iam-instance-profile", f"Arn={profile}" if profile.startswith("arn:") else f"Name={profile}",
            "--block-device-mappings", json.dumps(mappings),
            "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
            "--tag-specifications", _tag_specs(["instance", "volume", "network-interface"], t),
            timeout=300)
        clone.instance = run["Instances"][0]["InstanceId"]
        clone.add("instance", clone.instance)
        self._aws("ec2", "wait", "instance-running", "--instance-ids", clone.instance, timeout=900,
                  json_out=False)
        # The clone has its own volumes now; drop the AMI and its snapshots so
        # no extra copy of production data lingers.
        self._drop_image(image_id, [rid for kind, rid in clone.resources if kind == "snapshot"])

    def _drop_image(self, image_id: str, snapshots: list[str]) -> None:
        self._aws("ec2", "deregister-image", "--image-id", image_id, timeout=120, check=False)
        for s in snapshots:
            self._aws("ec2", "delete-snapshot", "--snapshot-id", s, timeout=120, check=False)

    def wait_agent(self, clone: Clone, timeout: float, cancel=None) -> None:
        def online():
            d = self._aws("ssm", "describe-instance-information", "--filters",
                          f"Key=InstanceIds,Values={clone.instance}", timeout=120) or {}
            info = d.get("InstanceInformationList", [])
            return bool(info) and info[0].get("PingStatus") == "Online"

        poll(f"SSM agent on {clone.instance}", online, timeout, interval=15, cancel=cancel)

    # -- run
    def run(self, clone: Clone, script: str, timeout: int) -> str:
        doc = "AWS-RunPowerShellScript" if clone.os == "windows" else "AWS-RunShellScript"
        params = {"commands": [script], "executionTimeout": [str(int(timeout))]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(params, f)
            params_file = f.name
        try:
            args = ["ssm", "send-command", "--instance-ids", clone.instance, "--document-name", doc,
                    "--parameters", f"file://{params_file}", "--timeout-seconds", "600",
                    "--comment", f"PatchLab Internal {clone.run_id}"[:100]]
            bucket = self.o.get("staging_bucket")
            if bucket:
                args += ["--output-s3-bucket-name", bucket, "--output-s3-key-prefix",
                         f"patchlab_internal/{clone.run_id}/ssm"]
            cmd = self._aws(*args, timeout=120)["Command"]["CommandId"]
        finally:
            Path(params_file).unlink(missing_ok=True)

        def finished():
            try:
                inv = self._aws("ssm", "get-command-invocation", "--command-id", cmd,
                                "--instance-id", clone.instance, timeout=60)
            except CloudError as e:
                if "InvocationDoesNotExist" in str(e):
                    return None
                raise
            return inv if inv.get("Status") in TERMINAL_SSM else None

        inv = poll(f"SSM command {cmd}", finished, timeout + 900, interval=self.poll_interval)
        if inv["Status"] in ("DeliveryTimedOut", "Undeliverable", "InvalidPlatform", "AccessDenied"):
            raise CloudError(f"SSM could not run the command on {clone.instance}: {inv['Status']}")
        out = inv.get("StandardOutputContent", "")
        url = inv.get("StandardOutputUrl", "")
        if self.o.get("staging_bucket") and url:
            key = url.split(".amazonaws.com/", 1)[-1]           # https://s3.<region>.amazonaws.com/<bucket>/<key>
            if key.startswith(self.o["staging_bucket"] + "/"):
                key = key[len(self.o["staging_bucket"]) + 1:]
            out = self._aws("s3", "cp", f"s3://{self.o['staging_bucket']}/{key}", "-", timeout=300,
                            json_out=False, check=False) or out
        return out

    def upload(self, clone: Clone, data: bytes, key: str) -> str | None:
        bucket = self.o.get("staging_bucket")
        if not bucket:
            return None
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            local = f.name
        try:
            uri = f"s3://{bucket}/patchlab/{key}"
            self._aws("s3", "cp", local, uri, timeout=900, json_out=False)
            return self._aws("s3", "presign", uri, "--expires-in", "3600", timeout=60, json_out=False).strip()
        finally:
            Path(local).unlink(missing_ok=True)

    # -- destroy
    def destroy(self, clone: Clone) -> None:
        self._sweep(clone.run_id, clone.name)
        if self.o.get("staging_bucket"):
            self._aws("s3", "rm", f"s3://{self.o['staging_bucket']}/patchlab/{clone.run_id}/", "--recursive",
                      timeout=600, json_out=False, check=False)

    @staticmethod
    def _filters(run_id: str | None, clone_name: str | None) -> list[str]:
        f = [f"Name=tag:{TAG_KEY},Values=1"]
        if run_id:
            f.append(f"Name=tag:{RUN_TAG_KEY},Values={run_id}")
        if clone_name:
            f.append(f"Name=tag:{CLONE_TAG_KEY},Values={clone_name}")   # exact match, never a prefix
        return f

    def _sweep(self, run_id: str | None, clone_name: str) -> None:
        """Delete everything tagged with exactly this clone name."""
        if not clone_name:
            raise CloudError("refusing to sweep without a clone name")
        filters = self._filters(run_id, clone_name)
        data = self._aws("ec2", "describe-instances", "--filters", *filters,
                         "Name=instance-state-name,Values=pending,running,stopping,stopped", timeout=120) or {}
        ids = [i["InstanceId"] for r in data.get("Reservations", []) for i in r.get("Instances", [])]
        if ids:
            self._aws("ec2", "terminate-instances", "--instance-ids", *ids, timeout=120)
            self._aws("ec2", "wait", "instance-terminated", "--instance-ids", *ids, timeout=1200,
                      json_out=False, check=False)
        images = self._aws("ec2", "describe-images", "--owners", "self", "--filters", *filters, timeout=120) or {}
        for img in images.get("Images", []):
            snaps = [m["Ebs"]["SnapshotId"] for m in img.get("BlockDeviceMappings", []) if m.get("Ebs", {}).get("SnapshotId")]
            self._drop_image(img["ImageId"], snaps)
        snaps = self._aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters", *filters, timeout=120) or {}
        for s in snaps.get("Snapshots", []):
            self._aws("ec2", "delete-snapshot", "--snapshot-id", s["SnapshotId"], timeout=120, check=False)
        vols = self._aws("ec2", "describe-volumes", "--filters", *filters, "Name=status,Values=available",
                         timeout=120) or {}
        for v in vols.get("Volumes", []):
            self._aws("ec2", "delete-volume", "--volume-id", v["VolumeId"], timeout=120, check=False)

    def list_clones(self, run_id: str | None = None) -> list[str]:
        """Clone names with anything left: instances, AMIs, snapshots or unattached volumes."""
        filters = self._filters(run_id, None)

        def names(items):
            return {t["Value"] for i in items for t in i.get("Tags", []) if t["Key"] == CLONE_TAG_KEY}

        inst = self._aws("ec2", "describe-instances", "--filters", *filters,
                         "Name=instance-state-name,Values=pending,running,stopping,stopped", timeout=120) or {}
        found = names(i for r in inst.get("Reservations", []) for i in r.get("Instances", []))
        found |= names((self._aws("ec2", "describe-images", "--owners", "self", "--filters", *filters,
                                  timeout=120) or {}).get("Images", []))
        found |= names((self._aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters", *filters,
                                  timeout=120) or {}).get("Snapshots", []))
        found |= names((self._aws("ec2", "describe-volumes", "--filters", *filters, "Name=status,Values=available",
                                  timeout=120) or {}).get("Volumes", []))
        return sorted(found)

    def destroy_named(self, name: str) -> None:
        if not name.startswith("patchlab-internal-"):
            raise CloudError(f"refusing to delete '{name}': not a PatchLab Internal clone")
        self._sweep(None, name)
