"""Linux targets: Docker sandboxes, shell patch commands, shell health probe."""

from __future__ import annotations

import shlex
import time
from typing import TYPE_CHECKING

from . import probes, sandbox
from .compare import Finding
from .config import Config, Patch
from .probes import Snapshot
from .sandbox import DockerSandbox

if TYPE_CHECKING:
    from .runner import TargetRun

PATCH_DIR = "/tmp/patchlab"

# Prints "@@REBOOT <reason>" when the patched system needs a reboot to take effect.
REBOOT_REQUIRED = r"""
if [ -f /var/run/reboot-required ]; then echo "@@REBOOT /var/run/reboot-required"
elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then
  echo "@@REBOOT needs-restarting"
else
  newest=$(ls -1t /boot/vmlinuz-* 2>/dev/null | head -n 1)
  if [ -n "$newest" ] && [ "$newest" != "/boot/vmlinuz-$(uname -r)" ]; then echo "@@REBOOT new kernel installed"; fi
fi
"""


def patch_command(patch: Patch) -> str:
    q = shlex.quote
    if patch.kind == "source":
        files = " ".join(q(f"{PATCH_DIR}/files/{f.name}") for f in patch.files)
        return f"""set -e
cd {q(patch.target)}
for f in {files}; do
  echo "== applying $f"
  if command -v git >/dev/null 2>&1; then git apply --verbose "$f"
  elif command -v patch >/dev/null 2>&1; then patch -p1 --forward --batch < "$f"
  else echo "neither git nor patch is installed in the sandbox; add one to [sandbox].setup" >&2; exit 127
  fi
done"""
    if patch.kind == "os-packages":
        pkgs = " ".join(q(p) for p in patch.packages)
        return f"""set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  echo "== pending updates"; apt list --upgradable 2>/dev/null | tail -n +2 || true
  if [ -n "{pkgs}" ]; then apt-get install -y -q --only-upgrade -o Dpkg::Options::=--force-confold {pkgs}
  else apt-get dist-upgrade -y -q -o Dpkg::Options::=--force-confold; fi
elif command -v dnf >/dev/null 2>&1; then dnf -y upgrade {pkgs}
elif command -v yum >/dev/null 2>&1; then yum -y update {pkgs}
elif command -v apk >/dev/null 2>&1; then apk update && apk upgrade {pkgs}
else echo "no supported package manager found" >&2; exit 127; fi"""
    if patch.kind == "package-file":
        files = " ".join(q(f"{PATCH_DIR}/files/{f.name}") for f in patch.files)
        return f"""set -e
if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q {files}
elif command -v dnf >/dev/null 2>&1; then dnf -y install {files}
elif command -v yum >/dev/null 2>&1; then yum -y install {files}
elif command -v apk >/dev/null 2>&1; then apk add --allow-untrusted {files}
else echo "no supported package manager found" >&2; exit 127; fi"""
    # script
    if patch.files:
        return "\n".join(f"chmod +x {q(f'{PATCH_DIR}/files/{f.name}')} && "
                         f"{q(f'{PATCH_DIR}/files/{f.name}')}" for f in patch.files)
    return patch.run or "true"


def rollback_command(patch: Patch) -> str | None:
    if patch.rollback:
        return patch.rollback
    if patch.kind == "source":
        files = " ".join(shlex.quote(f"{PATCH_DIR}/files/{f.name}") for f in reversed(patch.files))
        return f"""set -e
cd {shlex.quote(patch.target)}
for f in {files}; do
  if command -v git >/dev/null 2>&1; then git apply --reverse --verbose "$f"
  else patch -p1 --reverse --batch < "$f"; fi
done"""
    return None


class LinuxPlatform:
    name = "linux"

    def __init__(self, cfg: Config | None):
        self.cfg = cfg
        self.cloud = None
        if cfg is not None and cfg.sandbox.provider != "docker":
            from .cloud import CloudOps
            self.cloud = CloudOps(cfg)

    def provision(self, tr: "TargetRun") -> None:
        if self.cloud:
            self._provision_cloud(tr)
            return
        from .runner import StageFailed
        sb, r = self.cfg.sandbox, tr.result
        with tr.stage("provision") as st:
            tag = sandbox.cache_tag(tr.image, sb.setup, sb.env)
            use_cache = sb.cache and tr.opts.use_cache and bool(sb.setup)
            r.cache_hit = use_cache and sandbox.image_exists(tag)
            tr.box = DockerSandbox(
                tag if r.cache_hit else tr.image, tr.run_id,
                tr.sandbox_name(120),
                memory=sb.memory, cpus=sb.cpus, pids=sb.pids, network=sb.network, env=sb.env)
            tr.box.start()
            st.detail = f"container {tr.box.name}" + (" (from setup cache)" if r.cache_hit else "")

        if not r.cache_hit and sb.setup:
            with tr.stage("setup") as st:
                for i, cmd in enumerate(sb.setup):
                    res = tr.box.exec(cmd, timeout=1800)
                    tr.write_log(f"setup/{i + 1:02d}.log", res, f"$ {cmd}\n")
                    if not res.ok:
                        tail = res.output.strip().splitlines()[-5:]
                        raise StageFailed(f"setup command failed: {cmd} "
                                          f"(see {r.slug}/setup/{i + 1:02d}.log)", tail)
                if use_cache:
                    tr.box.commit(tag)
                    st.detail = f"cached as {tag}"

    def _provision_cloud(self, tr: "TargetRun") -> None:
        from .runner import StageFailed
        sb, r = self.cfg.sandbox, tr.result
        self.cloud.provision(tr, "linux")
        if sb.setup:
            with tr.stage("setup"):
                for i, cmd in enumerate(sb.setup):
                    res = tr.box.exec(cmd, timeout=1800)
                    tr.write_log(f"setup/{i + 1:02d}.log", res, f"$ {cmd}\n")
                    if not res.ok:
                        raise StageFailed(f"setup command failed: {cmd} (see {r.slug}/setup/{i + 1:02d}.log)",
                                          res.output.strip().splitlines()[-5:])
        self._settle(tr, "after boot")

    def _settle(self, tr: "TargetRun", why: str) -> None:
        secs = self.cfg.sandbox.settle_seconds
        if secs <= 0 or not tr.box.caps.get("reboot"):
            return
        with tr.stage("settle") as st:
            st.detail = f"waiting {secs}s for services ({why})"
            end = time.monotonic() + secs
            while time.monotonic() < end and not tr.cancel.is_set():
                time.sleep(min(5, max(0, end - time.monotonic())))

    def _reboot_cycle(self, tr: "TargetRun") -> bool:
        """Reboot while the system says it needs one (new kernel, libc, ...)."""
        if not tr.box.caps.get("reboot"):
            return False
        rebooted = False
        for _ in range(self.cfg.sandbox.max_reboots):
            res = tr.box.exec(REBOOT_REQUIRED, timeout=120)
            reason = next((l[9:].strip() for l in res.stdout.splitlines() if l.startswith("@@REBOOT ")), None)
            if not reason:
                break
            with tr.stage("reboot") as st:
                secs = tr.box.reboot(self.cfg.sandbox.boot_timeout, cancel=tr.cancel)
                tr.result.reboots.append(round(secs, 1))
                st.detail = f"{reason}; back in {secs:.0f}s"
            rebooted = True
        if rebooted:
            self._settle(tr, "after reboot")
        return rebooted

    def upload_patch_files(self, tr: "TargetRun") -> None:
        if tr.patch.files:
            tr.box.exec(f"mkdir -p {PATCH_DIR}/files", timeout=30)
            for f in tr.patch.files:
                tr.box.copy_in(f, f"{PATCH_DIR}/files/{f.name}")

    def apply_patch(self, tr: "TargetRun") -> bool:
        with tr.stage("apply-patch") as st:
            res = tr.box.exec(patch_command(tr.patch), timeout=tr.patch.timeout)
            tr.write_log("patch.log", res, f"# {tr.patch.label}\n")
            if not res.ok:
                st.status = "failed"
                st.detail = "patch did not apply cleanly (see patch.log)"
                tr.result.findings.append(Finding("fail", "patch", "the patch failed to install/apply",
                                                  res.output.strip().splitlines()[-15:]))
                return False
        self._reboot_cycle(tr)
        return True

    def rollback(self, tr: "TargetRun") -> bool | None:
        """Back the patch out. None = no rollback available, False = rollback failed."""
        cmd = rollback_command(tr.patch)
        if not cmd:
            return None
        res = tr.box.exec(cmd, timeout=tr.patch.timeout)
        tr.write_log("rollback.log", res, "# rollback\n")
        if not res.ok:
            tr.result.findings.append(Finding("fail", "rollback", "the rollback procedure failed",
                                              res.output.strip().splitlines()[-15:]))
            return False
        self._reboot_cycle(tr)
        return True

    def capture(self, tr: "TargetRun") -> Snapshot:
        h = self.cfg.health
        return probes.capture(tr.box, h.watch_paths, h.lib_scan_paths, h.ignore_files)

    def patch_changed_nothing(self, tr: "TargetRun") -> bool:
        return tr.patch.kind in ("os-packages", "package-file")

    def gc(self, run_id: str | None = None, include_cache: bool = False) -> str:
        if self.cloud:
            return self.cloud.gc(run_id)
        if run_id:
            return f"removed {len(sandbox.remove_run(run_id))} container(s)"
        containers, images = sandbox.gc(include_cache)
        return (f"removed {len(containers)} container(s)" +
                (f" and {len(images)} cached image(s)" if include_cache else ""))

    def leftovers(self, run_id: str) -> list[str]:
        return self.cloud.leftovers(run_id) if self.cloud else sandbox.run_containers(run_id)

    def remove(self, names: list[str]) -> None:
        if self.cloud:
            self.cloud.remove(names)
        else:
            sandbox.remove_containers(names)

    def available(self) -> str | None:
        return self.cloud.available() if self.cloud else sandbox.docker_available()

    def debug_hint(self, name: str) -> str:
        return self.cloud.debug_hint(name) if self.cloud else f"docker exec -it {name} sh"
