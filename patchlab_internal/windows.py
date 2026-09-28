"""Windows targets: VMs on Hyper-V or vSphere, driven through PowerShell.

Python keeps one long-lived PowerShell "driver" process per sandbox
(ps/driver.ps1 + ps/provider-<name>.ps1) and exchanges base64 JSON lines
with it, so module imports and vCenter logins happen once per VM rather
than once per command.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

from .compare import Finding
from .config import Config, Patch
from .probes import Snapshot
from .sandbox import ExecResult, SandboxError

if TYPE_CHECKING:
    from .runner import TargetRun

PS_DIR = Path(__file__).resolve().parent / "ps"
PREPATCH_CHECKPOINT = "patchlab-internal-prepatch"
DEFAULT_IGNORE_SERVICES = [
    # Update and telemetry plumbing that starts and stops on its own schedule.
    "BITS", "wuauserv", "UsoSvc", "WaaSMedicSvc", "TrustedInstaller", "sppsvc",
    "gupdate", "gupdatem", "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService",
    "MapsBroker", "RemoteRegistry", "tiledatamodelsvc", "CDPSvc", "ShellHWDetection",
    "WbioSrvc", "sysmain", "clr_optimization_v4.0.30319_32", "clr_optimization_v4.0.30319_64",
]


class DriverError(SandboxError):
    pass


def _ps(name: str) -> str:
    return (PS_DIR / name).read_text(encoding="utf-8")


def find_powershell(provider: str) -> str | None:
    override = os.environ.get("PATCHLAB_INTERNAL_POWERSHELL")
    if override:
        return override
    # Windows PowerShell 5.1 always ships the Hyper-V module; PowerCLI and the
    # local provider are happiest on PowerShell 7.
    order = ["powershell", "pwsh"] if provider == "hyperv" else ["pwsh", "powershell"]
    for exe in order:
        found = shutil.which(exe)
        if found:
            return found
    return None


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def with_config(script: str, config: dict) -> str:
    """Prefix a guest script with $PatchLabInternalConfig built from ``config``."""
    return ("$PatchLabInternalConfig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
            f"'{_b64(json.dumps(config))}')) | ConvertFrom-Json\n" + script)


def as_system(payload: str, timeout: int) -> str:
    return (_ps("guest/run-as-system.ps1")
            .replace("__PAYLOAD__", _b64(payload)).replace("__TIMEOUT__", str(int(timeout))))


def extract_json(stdout: str):
    """Return the last '@@PLJSON {...}' payload printed by a guest script."""
    for line in reversed(stdout.splitlines()):
        line = line.strip().lstrip("\ufeff")
        if line.startswith("@@PLJSON "):
            return json.loads(line[len("@@PLJSON "):])
    return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ---------------------------------------------------------------- driver

class PowerShellDriver:
    def __init__(self, provider: str, options: dict, guest_user: str, log_path: Path | None = None):
        self.provider = provider
        self.options = options
        self.guest_user = guest_user
        self.log_path = log_path
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.info: dict = {}
        self._id = 0
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(log_path, "a", encoding="utf-8") if log_path else None
        self._log_lock = threading.Lock()
        self._start()

    def _start(self) -> None:
        exe = find_powershell(self.provider)
        if not exe:
            raise DriverError("PowerShell not found (install PowerShell 7 or set PATCHLAB_INTERNAL_POWERSHELL)")
        env = dict(os.environ)
        env["PATCHLAB_INTERNAL_PROVIDER_OPTIONS"] = json.dumps(self.options)
        env["PATCHLAB_INTERNAL_GUEST_USER"] = self.guest_user
        self.proc = subprocess.Popen(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(PS_DIR / "driver.ps1"), "-Provider", self.provider],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self._log or subprocess.DEVNULL, env=env,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self._responses: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, args=(self.proc, self._responses), daemon=True).start()
        self.info = self.request("init", {}, timeout=300) or {}

    def _read(self, proc: subprocess.Popen, q: queue.Queue) -> None:
        for line in proc.stdout:
            if line.startswith("@@PL "):
                try:
                    q.put(json.loads(base64.b64decode(line[5:].strip()).decode("utf-8")))
                except ValueError:
                    pass
            elif line.strip():
                self._write_log(line)
        q.put(None)  # driver exited

    def _write_log(self, text: str) -> None:
        with self._log_lock:
            if self._log:
                self._log.write(text)
                self._log.flush()

    @property
    def capabilities(self) -> dict:
        return self.info.get("capabilities", {})

    def request(self, action: str, args: dict, timeout: float = 300):
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                raise DriverError(f"PowerShell driver is not running (see {self.log_path})")
            self._id += 1
            msg = {"id": self._id, "action": action, "args": args}
            try:
                self.proc.stdin.write(_b64(json.dumps(msg)) + "\n")
                self.proc.stdin.flush()
            except OSError as e:
                raise DriverError(f"lost connection to PowerShell driver: {e}") from None
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # The driver is stuck inside a cmdlet; replace it.
                    self._kill()
                    self._restart_unlocked()
                    raise DriverError(f"{action} timed out after {timeout:.0f}s")
                try:
                    resp = self._responses.get(timeout=min(remaining, 5))
                except queue.Empty:
                    continue
                if resp is None:
                    raise DriverError(f"PowerShell driver exited during {action} (see {self.log_path})")
                if resp.get("id") != self._id:
                    continue  # late reply to a request that already timed out
                if not resp.get("ok"):
                    raise DriverError(f"{action}: {resp.get('error')}")
                return resp.get("result")

    def _restart_unlocked(self) -> None:
        # Called with the lock held; _start re-enters request(), so release temporarily.
        self.lock.release()
        try:
            self._start()
        finally:
            self.lock.acquire()

    def _kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.request("exit", {}, timeout=15)
            except DriverError:
                pass
            self._kill()
        with self._log_lock:
            if self._log:
                self._log.close()
                self._log = None


# ---------------------------------------------------------------- sandbox

class WindowsSandbox:
    def __init__(self, driver: PowerShellDriver, image: str, name: str, run_id: str, cfg: Config):
        self.driver = driver
        self.image = image
        self.name = name
        self.run_id = run_id
        self.cfg = cfg
        self.started = False
        self.guest_dir = r"C:\ProgramData\PatchLab Internal"

    @property
    def caps(self) -> dict:
        return self.driver.capabilities

    def gpath(self, *parts: str) -> str:
        sep = "\\" if (len(self.guest_dir) > 1 and self.guest_dir[1] == ":") else "/"
        return sep.join([self.guest_dir.rstrip("\\/"), *parts])

    def start(self) -> None:
        sb = self.cfg.sandbox
        info = self.driver.request("create", {
            "name": self.name, "image": self.image, "run_id": self.run_id,
            "memory_mb": _size_mb(sb.memory), "cpus": sb.cpus}, timeout=1800) or {}
        self.started = True
        self.guest_dir = info.get("guest_dir") or self.guest_dir

    def exec(self, script: str, timeout: int = 300, workdir: str | None = None) -> ExecResult:
        start = time.monotonic()
        r = self.driver.request("exec", {"name": self.name, "script": script, "timeout": int(timeout)},
                                timeout=timeout + 180) or {}
        return ExecResult(int(r.get("exit_code", 255)), r.get("stdout") or "", r.get("stderr") or "",
                          time.monotonic() - start, bool(r.get("timed_out")))

    def copy_in(self, src: Path, dest: str, exclude: list[str] | None = None) -> None:
        if exclude and src.is_dir():
            with tempfile.TemporaryDirectory(prefix="patchlab-internal-") as tmp:
                staged = Path(tmp) / src.name
                shutil.copytree(src, staged, ignore=shutil.ignore_patterns(*exclude))
                self.driver.request("copy_in", {"name": self.name, "src": str(staged), "dest": dest},
                                    timeout=3600)
            return
        self.driver.request("copy_in", {"name": self.name, "src": str(src), "dest": dest}, timeout=3600)

    def copy_out(self, src: str, dest: Path) -> bool:
        return bool(self.driver.request("copy_out", {"name": self.name, "src": src, "dest": str(dest)},
                                        timeout=600))

    def boot_time(self) -> str:
        res = self.exec("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",
                        timeout=60)
        if not res.ok:
            raise DriverError(f"guest not ready: {res.output.strip()[:200]}")
        return res.stdout.strip()

    def wait_ready(self, timeout: int, previous_boot: str | None = None, cancel=None) -> float:
        """Poll until the guest runs commands (and has rebooted, if previous_boot is given)."""
        start = time.monotonic()
        last_err = ""
        while time.monotonic() - start < timeout:
            if cancel is not None and cancel.is_set():
                raise DriverError("cancelled while waiting for the guest")
            try:
                bt = self.boot_time()
                if previous_boot is None or bt != previous_boot:
                    return time.monotonic() - start
            except DriverError as e:
                last_err = str(e)
            time.sleep(10)
        raise DriverError(f"guest did not become ready within {timeout}s ({last_err})")

    def reboot(self, timeout: int, cancel=None) -> float:
        before = self.boot_time()
        # p:2:17 = planned, Operating System: Hot fix
        self.exec("shutdown.exe /r /t 5 /f /d p:2:17", timeout=60)
        return self.wait_ready(timeout, previous_boot=before, cancel=cancel)

    def checkpoint(self, name: str) -> None:
        self.driver.request("checkpoint", {"name": self.name, "snapshot": name}, timeout=1800)

    def restore(self, name: str) -> None:
        self.driver.request("restore", {"name": self.name, "snapshot": name}, timeout=1800)

    def destroy(self) -> None:
        try:
            if self.started:
                self.driver.request("destroy", {"name": self.name}, timeout=900)
                self.started = False
        finally:
            self.driver.close()


def _size_mb(size: str) -> int:
    s = str(size).strip().lower().rstrip("b")
    mult = {"k": 1 / 1024, "m": 1, "g": 1024, "t": 1024 * 1024}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(float(s) / (1024 * 1024)) if float(s) > 1024 * 1024 else int(float(s))


# ---------------------------------------------------------------- probe parsing

def uninstall_is_default(patch: Patch) -> bool:
    """DISM can back out Windows updates (.msu/.cab); installers (.msi/.msp/.exe)
    need their own rollback script, so they get no default."""
    if patch.kind == "windows-update":
        return True
    return patch.kind == "package-file" and bool(patch.files) and all(
        f.suffix.lower() in (".msu", ".cab") for f in patch.files)


def parse_probe(data: dict, ignore_files: list[str] = ()) -> Snapshot:
    snap = Snapshot(
        os=data.get("os", ""), kernel=data.get("kernel", ""), pkgmgr="windows",
        packages={str(k): str(v) for k, v in (data.get("packages") or {}).items()},
        pkgdb_issues=_as_list(data.get("pkgdb_issues")),
        listening=sorted(int(p) for p in _as_list(data.get("listening"))),
        files={k: str(v) for k, v in (data.get("files") or {}).items()
               if not any(fnmatch(k, pat) for pat in ignore_files)},
        services_down=sorted(_as_list(data.get("services_down"))),
        problem_devices=sorted(_as_list(data.get("problem_devices"))),
        events=data.get("events") or {},
        pending_reboot=_as_list(data.get("pending_reboot")),
        last_boot=data.get("last_boot", ""),
    )
    errors = _as_list(data.get("errors"))
    if errors:
        snap.error = "; ".join(errors)[:500]
    return snap


# ---------------------------------------------------------------- platform

class WindowsPlatform:
    name = "windows"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.provider = cfg.sandbox.provider
        self.cloud = None
        from .cloud import CLOUD_PROVIDERS, CloudOps
        if self.provider in CLOUD_PROVIDERS:
            self.cloud = CloudOps(cfg)

    # -- helpers
    def _driver(self, log_path: Path | None = None) -> PowerShellDriver:
        return PowerShellDriver(self.provider, self.cfg.sandbox.provider_options,
                                self.cfg.sandbox.username, log_path)

    def available(self) -> str | None:
        if self.cloud:
            return self.cloud.available()
        if not find_powershell(self.provider):
            return "PowerShell not found (install PowerShell 7 or set PATCHLAB_INTERNAL_POWERSHELL)"
        if self.provider != "local" and not os.environ.get("PATCHLAB_INTERNAL_GUEST_PASSWORD"):
            return "set PATCHLAB_INTERNAL_GUEST_PASSWORD to the guest administrator password"
        if self.provider == "vsphere" and not (os.environ.get("PATCHLAB_INTERNAL_VCENTER_USER")
                                               and os.environ.get("PATCHLAB_INTERNAL_VCENTER_PASSWORD")):
            return "set PATCHLAB_INTERNAL_VCENTER_USER and PATCHLAB_INTERNAL_VCENTER_PASSWORD"
        return None

    def _run_guest(self, tr: "TargetRun", script: str, config: dict, timeout: int,
                   system: bool) -> ExecResult:
        body = with_config(script, config)
        if system and tr.box.caps.get("system_tasks"):
            return tr.box.exec(as_system(body, timeout), timeout=timeout + 120)
        return tr.box.exec(body, timeout=timeout)

    def _settle(self, tr: "TargetRun", why: str) -> None:
        secs = self.cfg.sandbox.settle_seconds
        if secs <= 0 or not tr.box.caps.get("reboot"):
            return
        with tr.stage("settle") as st:
            st.detail = f"waiting {secs}s for delayed-start services ({why})"
            end = time.monotonic() + secs
            while time.monotonic() < end:
                if tr.cancel.is_set():
                    break
                time.sleep(min(5, max(0, end - time.monotonic())))

    def _pending_reboot(self, tr: "TargetRun") -> list[str]:
        res = tr.box.exec(_ps("guest/pending-reboot.ps1"), timeout=120)
        return _as_list(extract_json(res.stdout))

    def _reboot_cycle(self, tr: "TargetRun", required: bool) -> bool:
        """Reboot until nothing is pending. Returns True if the guest was rebooted."""
        sb = self.cfg.sandbox
        if not tr.box.caps.get("reboot"):
            if required:
                tr.log("provider cannot reboot; skipping")
            return False
        rebooted = False
        for i in range(sb.max_reboots):
            # File-rename entries alone are too common to justify a reboot loop.
            reasons = [r for r in self._pending_reboot(tr) if r != "Pending file rename operations"]
            if not reasons and not (required and i == 0):
                break
            with tr.stage("reboot") as st:
                secs = tr.box.reboot(sb.boot_timeout, cancel=tr.cancel)
                tr.result.reboots.append(round(secs, 1))
                st.detail = f"{', '.join(reasons) or 'installer requested'}; back in {secs:.0f}s"
            rebooted = True
        return rebooted

    # -- platform interface
    def provision(self, tr: "TargetRun") -> None:
        sb = self.cfg.sandbox
        if self.cloud:
            self.cloud.provision(tr, "windows")
            self._setup_and_settle(tr)
            return
        with tr.stage("provision") as st:
            driver = self._driver(tr.logdir / "driver.log")
            name = tr.sandbox_name(60)
            tr.box = WindowsSandbox(driver, tr.image, name, tr.run_id, self.cfg)
            tr.box.start()
            st.detail = f"{self.provider} VM {name} ({driver.info.get('host', '')})"
        with tr.stage("boot") as st:
            secs = tr.box.wait_ready(sb.boot_timeout, cancel=tr.cancel)
            st.detail = f"guest ready after {secs:.0f}s"
        self._setup_and_settle(tr)

    def _setup_and_settle(self, tr: "TargetRun") -> None:
        from .runner import StageFailed
        sb, r = self.cfg.sandbox, tr.result
        if sb.setup:
            with tr.stage("setup"):
                for i, cmd in enumerate(sb.setup):
                    res = tr.box.exec(cmd, timeout=3600)
                    tr.write_log(f"setup/{i + 1:02d}.log", res, f"PS> {cmd}\n")
                    if not res.ok:
                        raise StageFailed(f"setup command failed: {cmd} (see {r.slug}/setup/{i + 1:02d}.log)",
                                          res.output.strip().splitlines()[-5:])
        self._settle(tr, "after boot")

    def upload_patch_files(self, tr: "TargetRun") -> None:
        for f in tr.patch.files:
            tr.box.copy_in(f, tr.box.gpath("files", f.name))

    def apply_patch(self, tr: "TargetRun") -> bool:
        p, r = tr.patch, tr.result
        if p.kind in ("windows-update", "package-file"):
            res = self._run_guest(tr, _ps("guest/cbs-baseline.ps1"), {}, 900, system=True)
            tr.write_log("cbs-baseline.log", res)
        if p.rollback == "checkpoint" and tr.opts.verify_rollback and tr.box.caps.get("checkpoint"):
            with tr.stage("checkpoint"):
                tr.box.checkpoint(PREPATCH_CHECKPOINT)

        passes = p.max_passes if p.kind == "windows-update" else 1
        rebooted = False
        for n in range(1, passes + 1):
            label = "apply-patch" if n == 1 else f"apply-patch (pass {n})"
            with tr.stage(label) as st:
                res = self._run_guest(tr, *self._patch_script(tr), timeout=p.timeout,
                                      system=p.run_as == "system")
                tr.write_log("patch.log" if n == 1 else f"patch-pass{n}.log", res, f"# {p.label}\n")
                summary = extract_json(res.stdout) or {}
                installed = [u for u in _as_list(summary.get("updates")) if u.get("selected")]
                for u in installed:
                    u["pass"] = n
                r.updates.extend(installed)
                if not res.ok:
                    st.status = "failed"
                    st.detail = f"installer exit code {res.exit_code} (see patch.log)"
                    failed = [f"{u.get('kb')} {u.get('title')}: {u.get('result')} {u.get('hresult')}"
                              for u in installed if u.get("result") not in (None, "Succeeded", "installed",
                                                                            "installed, reboot required",
                                                                            "already installed")]
                    r.findings.append(Finding("fail", "patch", "the patch failed to install",
                                              failed or res.output.strip().splitlines()[-15:]))
                    return False
                if p.kind == "windows-update":
                    st.detail = f"{len(installed)} update(s) installed"
                    if not installed:
                        if n == 1:
                            r.findings.append(Finding("warn", "patch", "Windows Update offered no "
                                                      "applicable updates: the golden image may already "
                                                      "be current, or the filters excluded everything"))
                        break
            rebooted |= self._reboot_cycle(tr, bool(summary.get("reboot_required")))
            if p.kind != "windows-update":
                break
        if rebooted:
            self._settle(tr, "after patch reboot")
        return True

    def _patch_script(self, tr: "TargetRun") -> tuple[str, dict]:
        p = tr.patch
        if p.kind == "windows-update":
            return _ps("guest/windows-update.ps1"), {
                "kbs": p.packages, "categories": p.categories,
                "include_preview": p.include_preview, "microsoft_update": p.microsoft_update}
        if p.kind == "package-file":
            return _ps("guest/install-files.ps1"), {
                "files": [tr.box.gpath("files", f.name) for f in p.files], "exe_args": p.exe_args}
        # script
        if p.files:
            body = "\n".join(f"& '{tr.box.gpath('files', f.name)}'\nif ($LASTEXITCODE) {{ exit $LASTEXITCODE }}"
                             for f in p.files)
        else:
            body = p.run or ""
        return body, {}

    def rollback(self, tr: "TargetRun") -> bool | None:
        p, r, box = tr.patch, tr.result, tr.box
        mode = p.rollback or ("uninstall" if uninstall_is_default(p) else None)
        if not mode:
            return None
        if mode == "checkpoint":
            if not box.caps.get("checkpoint"):
                return None
            box.restore(PREPATCH_CHECKPOINT)
            box.wait_ready(self.cfg.sandbox.boot_timeout, cancel=tr.cancel)
            self._settle(tr, "after checkpoint restore")
            return True
        if mode == "uninstall":
            res = self._run_guest(tr, _ps("guest/uninstall-updates.ps1"), {}, p.timeout, system=True)
        else:
            res = self._run_guest(tr, mode, {}, p.timeout, system=p.run_as == "system")
        tr.write_log("rollback.log", res, f"# rollback ({'uninstall' if mode == 'uninstall' else 'script'})\n")
        summary = extract_json(res.stdout) or {}
        if not res.ok:
            details = (_as_list(summary.get("failed")) or res.output.strip().splitlines()[-15:])
            msg = ("the patch could not be uninstalled" if mode == "uninstall"
                   else "the rollback procedure failed")
            r.findings.append(Finding("fail", "rollback", msg, details))
            return False
        if _as_list(summary.get("skipped")):
            r.findings.append(Finding("info", "rollback", "parts of the update cannot be uninstalled",
                                      _as_list(summary.get("skipped"))))
        if self._reboot_cycle(tr, True):
            self._settle(tr, "after rollback reboot")
        return True

    def capture(self, tr: "TargetRun") -> Snapshot:
        h = self.cfg.health
        cfg = {"watch_paths": h.watch_paths, "watch_registry": h.watch_registry,
               "ignore_ports_from": h.ignore_ports_from,
               "ignore_services": h.ignore_services or DEFAULT_IGNORE_SERVICES}
        res = tr.box.exec(with_config(_ps("guest/probe.ps1"), cfg), timeout=1200)
        data = extract_json(res.stdout)
        if data is None:
            snap = Snapshot(error=f"health probe produced no data (exit {res.exit_code}): "
                                  f"{res.output.strip()[-300:]}")
        else:
            snap = parse_probe(data, h.ignore_files)
        return snap

    def patch_changed_nothing(self, tr: "TargetRun") -> bool:
        return tr.patch.kind == "package-file"

    def gc(self, run_id: str | None = None, include_cache: bool = False) -> str:
        if self.cloud:
            return self.cloud.gc(run_id)
        driver = self._driver()
        try:
            names = [n for n in _as_list(driver.request("list", {"run_id": run_id}, timeout=300)) if n]
            for n in names:
                driver.request("destroy", {"name": n}, timeout=900)
        finally:
            driver.close()
        return f"removed {len(names)} {self.provider} VM(s)"

    def leftovers(self, run_id: str) -> list[str]:
        if self.cloud:
            return self.cloud.leftovers(run_id)
        driver = self._driver()
        try:
            return [n for n in _as_list(driver.request("list", {"run_id": run_id}, timeout=300)) if n]
        finally:
            driver.close()

    def remove(self, names: list[str]) -> None:
        if self.cloud:
            self.cloud.remove(names)
            return
        driver = self._driver()
        try:
            for n in names:
                driver.request("destroy", {"name": n}, timeout=900)
        finally:
            driver.close()

    def debug_hint(self, name: str) -> str:
        if self.cloud:
            return self.cloud.debug_hint(name)
        if self.provider == "hyperv":
            return f"Enter-PSSession -VMName {name}  (or vmconnect localhost {name})"
        if self.provider == "vsphere":
            return f"open the console of VM '{name}' in vCenter"
        return f"inspect the sandbox directory for {name}"
