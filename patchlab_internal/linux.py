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
MIRROR_DIR = "/opt/patchlab/mirrors"
CA_PATH = "/usr/local/share/patchlab/ca-bundle.crt"
# Every tool that reads its own CA setting, pointed at the same bundle.
CA_ENV = ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE",
          "PIP_CERT", "CARGO_HTTP_CAINFO", "CURL_CA_BUNDLE")

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


def mirror_dest(index: int, mirror) -> str:
    return f"{MIRROR_DIR}/{index + 1:02d}-{mirror.path.name}"


def sandbox_env(sb) -> dict[str, str]:
    """The container environment: the config's env, the CA settings and git's
    insteadOf rules for mirrors (GIT_CONFIG_COUNT needs git 2.31 or newer)."""
    env = dict(sb.env)
    if sb.ca_bundle:
        for k in CA_ENV:
            env.setdefault(k, CA_PATH)
    pairs = []
    for i, m in enumerate(sb.mirrors):
        for url in m.urls:
            pairs.append((f"url.file://{mirror_dest(i, m)}.insteadOf", url))
    if pairs:
        pairs.append(("safe.directory", "*"))
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for n, (k, v) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{n}"] = k
            env[f"GIT_CONFIG_VALUE_{n}"] = v
    return env


# leftovers() marks networks with this prefix so remove() can tell them from containers.
NET = "network:"


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
        env = sandbox_env(sb)
        private = bool(sb.sidecars) or sb.check_network == "isolated"
        with tr.stage("provision") as st:
            tag = sandbox.cache_tag(tr.image, sb.setup, env)
            use_cache = sb.cache and tr.opts.use_cache and bool(sb.setup)
            r.cache_hit = use_cache and sandbox.image_exists(tag)
            name = tr.sandbox_name(120)
            tr.box = DockerSandbox(
                tag if r.cache_hit else tr.image, tr.run_id, name,
                memory=sb.memory, cpus=sb.cpus, pids=sb.pids,
                network=name + "-net" if private and sb.network == "none" else sb.network,
                env=env)
            if private:
                # Created before the sandbox so a failure here still tears down cleanly.
                tr.box.private_network = sandbox.create_network(name + "-net", tr.run_id)
            tr.box.start()
            if private and tr.box.network != tr.box.private_network:
                tr.box.connect(tr.box.private_network)
            if sb.ca_bundle:
                tr.box.exec(f"mkdir -p {shlex.quote(CA_PATH.rsplit('/', 1)[0])}", timeout=30)
                tr.box.copy_in(sb.ca_bundle, CA_PATH)
            st.detail = f"container {tr.box.name}" + (" (from setup cache)" if r.cache_hit else "")

        if sb.sidecars:
            self._start_sidecars(tr)

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

    def _start_sidecars(self, tr: "TargetRun") -> None:
        from .runner import StageFailed
        box = tr.box
        with tr.stage("sidecars") as st:
            for sc in self.cfg.sandbox.sidecars:
                cname = f"{box.name}-{sc.name}"
                box.sidecars.append(cname)
                sandbox.start_sidecar(sc.image, tr.run_id, cname, sc.name, box.private_network, sc.env)
            for sc in self.cfg.sandbox.sidecars:
                cname = f"{box.name}-{sc.name}"
                if sc.health and not sandbox.wait_healthy(cname, sc.health, sc.health_timeout):
                    raise StageFailed(f"sidecar '{sc.name}' ({sc.image}) did not become healthy "
                                      f"within {sc.health_timeout}s",
                                      sandbox.container_logs(cname).strip().splitlines()[-10:])
            st.detail = ", ".join(f"{sc.name} ({sc.image})" for sc in self.cfg.sandbox.sidecars)

    def deploy_extras(self, tr: "TargetRun") -> None:
        """Copy git mirrors in. After setup, so a cached setup image never holds stale mirrors."""
        for i, m in enumerate(self.cfg.sandbox.mirrors):
            tr.box.copy_in(m.path, mirror_dest(i, m))

    def install(self, tr: "TargetRun", when: str) -> list[str] | None:
        """Run [sandbox].install. Returns None on success, else the output tail.

        With check_network = "isolated" the sandbox is on the outside network
        only while installing; checks never are."""
        sb, box = self.cfg.sandbox, tr.box
        isolated = sb.check_network == "isolated" and box.private_network and box.network != box.private_network
        if not sb.install:
            if isolated and when == "deploy":
                box.disconnect(box.network)
            return None
        if isolated and when != "deploy":
            box.connect(box.network)
        try:
            for i, cmd in enumerate(sb.install):
                res = box.exec(cmd, timeout=sb.install_timeout, workdir=sb.workdir)
                tr.write_log(f"install-{when}/{i + 1:02d}.log", res, f"$ {cmd}\n")
                if not res.ok:
                    return [f"$ {cmd}", *res.output.strip().splitlines()[-12:]]
        finally:
            if isolated:
                box.disconnect(box.network)
        return None

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
        if self.cfg.sandbox.install and not self.cloud:
            with tr.stage("install-patched") as st:
                tail = self.install(tr, "patched")
                if tail:
                    st.status, st.detail = "failed", "dependencies did not install after the patch"
                    tr.result.findings.append(Finding(
                        "fail", "install", "dependencies failed to install after the patch", tail))
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
        if self.cfg.sandbox.install and not self.cloud:
            tail = self.install(tr, "rollback")
            if tail:
                tr.result.findings.append(Finding(
                    "fail", "rollback", "dependencies failed to reinstall after the rollback", tail))
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
        if self.cloud:
            return self.cloud.leftovers(run_id)
        return sandbox.run_containers(run_id) + [NET + n for n in sandbox.run_networks(run_id)]

    def remove(self, names: list[str]) -> None:
        if self.cloud:
            self.cloud.remove(names)
            return
        # Containers first: Docker refuses to remove a network that is still in use.
        sandbox.remove_containers([n for n in names if not n.startswith(NET)])
        for n in names:
            if n.startswith(NET):
                sandbox.remove_network(n[len(NET):])

    def available(self) -> str | None:
        return self.cloud.available() if self.cloud else sandbox.docker_available()

    def debug_hint(self, name: str) -> str:
        return self.cloud.debug_hint(name) if self.cloud else f"docker exec -it {name} sh"
