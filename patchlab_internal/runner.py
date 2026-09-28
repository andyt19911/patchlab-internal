"""Orchestrate a patch test: provision -> baseline -> patch -> verify -> (rollback) -> teardown."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, results
from .compare import (CheckDelta, CheckResult, Finding, PackageChanges, compare_checks,
                      compare_snapshots, verdict_for, worst)
from .config import Config, Patch
from .probes import Snapshot
from .sandbox import ExecResult, SandboxError


class Cancelled(Exception):
    pass


class StageFailed(Exception):
    """A pipeline step failed in a way that makes the test inconclusive."""


@dataclass
class Options:
    out_dir: Path
    images: list[str] | None = None
    use_cache: bool = True
    keep_on_failure: bool = False
    verify_rollback: bool = False
    jobs: int | None = None
    quiet: bool = False
    run_id: str | None = None


@dataclass
class Stage:
    name: str
    status: str = "running"  # ok | failed | skipped | running
    duration: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "duration": round(self.duration, 2),
                "detail": self.detail}


@dataclass
class Phase:
    checks: dict[str, CheckResult] = field(default_factory=dict)
    services: list[tuple[str, bool]] = field(default_factory=list)
    snapshot: Snapshot | None = None

    def to_dict(self) -> dict:
        return {
            "checks": {k: v.to_dict() for k, v in self.checks.items()},
            "services": [{"command": c, "ok": ok} for c, ok in self.services],
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
        }


@dataclass
class TargetResult:
    image: str
    slug: str
    verdict: str = "ERROR"
    stages: list[Stage] = field(default_factory=list)
    baseline: Phase | None = None
    patched: Phase | None = None
    rollback: Phase | None = None
    deltas: list[CheckDelta] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    packages: PackageChanges = field(default_factory=PackageChanges)
    files: dict[str, list[str]] = field(default_factory=dict)
    os: str = ""
    cache_hit: bool = False
    kept_container: str | None = None
    duration: float = 0.0
    # Windows: updates the patch step reported, and reboot durations (seconds).
    updates: list[dict] = field(default_factory=list)
    reboots: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "image": self.image, "os": self.os, "verdict": self.verdict,
            "duration": round(self.duration, 1), "cache_hit": self.cache_hit,
            "kept_container": self.kept_container,
            "stages": [s.to_dict() for s in self.stages],
            "findings": [f.to_dict() for f in self.findings],
            "checks": [d.to_dict() for d in self.deltas],
            "packages": self.packages.to_dict(), "watched_files": self.files,
            "updates": self.updates, "reboots": self.reboots,
            "phases": {n: p.to_dict() for n, p in (("baseline", self.baseline),
                       ("patched", self.patched), ("rollback", self.rollback)) if p},
        }


@dataclass
class RunReport:
    run_id: str
    config: Config
    patch: Patch
    started: dt.datetime
    finished: dt.datetime | None = None
    targets: list[TargetResult] = field(default_factory=list)
    out_dir: Path | None = None
    cancelled: bool = False
    cleanup: str = ""

    @property
    def verdict(self) -> str:
        if self.cancelled:
            return "ERROR"
        return worst(t.verdict for t in self.targets)

    def to_dict(self) -> dict:
        p = self.patch
        return {
            "tool": f"patchlab_internal {__version__}", "run_id": self.run_id, "name": self.config.name,
            "verdict": self.verdict, "cancelled": self.cancelled,
            "started": self.started.isoformat(timespec="seconds"),
            "finished": self.finished.isoformat(timespec="seconds") if self.finished else None,
            "duration": round((self.finished - self.started).total_seconds(), 1) if self.finished else None,
            "platform": self.config.sandbox.platform, "provider": self.config.sandbox.provider,
            "patch": {"kind": p.kind, "label": p.label, "files": [f.name for f in p.files],
                      "packages": p.packages, "rollback": p.rollback or None},
            "cleanup": self.cleanup,
            "targets": [t.to_dict() for t in self.targets],
        }


class Logger:
    def __init__(self, quiet: bool = False):
        self.lock = threading.Lock()
        self.quiet = quiet

    def __call__(self, target: str, msg: str) -> None:
        if self.quiet:
            return
        with self.lock:
            print(f"{time.strftime('%H:%M:%S')} [{target}] {msg}", file=sys.stderr, flush=True)


def slugify(image: str) -> str:
    name = image
    if "\\" in image or re.search(r"\.(vhdx?|avhdx)$", image, re.I):
        # A disk path: name the target after the file, not the whole path.
        name = re.split(r"[\\/]", image)[-1]
        name = re.sub(r"\.(vhdx?|avhdx)$", "", name, flags=re.I)
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-")


def sandbox_name(run_id: str, slug: str, limit: int = 60) -> str:
    name = f"patchlab-internal-{run_id}-{slug}"
    if len(name) <= limit:
        return name
    digest = hashlib.sha1(slug.encode()).hexdigest()[:8]
    return f"{name[:limit - 9].rstrip('-.')}-{digest}"


def unique_slugs(images: list[str]) -> list[str]:
    """One slug per target, unique within the run (log folders and sandbox names use them)."""
    seen: dict[str, int] = {}
    out = []
    for img in images:
        base = slugify(img) or "target"
        n = seen.get(base, 0) + 1
        seen[base] = n
        out.append(base if n == 1 else f"{base}-{n}")
    return out


def make_platform(cfg: Config):
    if cfg.sandbox.platform == "windows":
        from .windows import WindowsPlatform
        return WindowsPlatform(cfg)
    from .linux import LinuxPlatform
    return LinuxPlatform(cfg)


# ---------------------------------------------------------------- per-target pipeline

class TargetRun:
    def __init__(self, cfg: Config, patch: Patch, image: str, run_id: str, opts: Options,
                 log: Logger, cancel: threading.Event, platform=None, slug: str | None = None):
        self.cfg, self.patch, self.image, self.run_id = cfg, patch, image, run_id
        self.opts, self.cancel = opts, cancel
        self.platform = platform or make_platform(cfg)
        self.result = TargetResult(image=image, slug=slug or slugify(image))
        self.kept_cleanup_name: str | None = None
        self.logdir = opts.out_dir / self.result.slug
        self._log = log
        self.box = None  # DockerSandbox or WindowsSandbox

    def log(self, msg: str) -> None:
        self._log(self.result.slug, msg)

    def sandbox_name(self, limit: int = 60) -> str:
        """patchlab-internal-<run>-<target>, shortened with a hash so it stays unique within `limit`."""
        return sandbox_name(self.run_id, self.result.slug, limit)

    @contextmanager
    def stage(self, name: str):
        if self.cancel.is_set():
            raise Cancelled()
        st = Stage(name)
        self.result.stages.append(st)
        self.log(f"{name} ...")
        start = time.monotonic()
        try:
            yield st
            if st.status == "running":
                st.status = "ok"
        except Exception as e:
            st.status = "failed"
            st.detail = st.detail or (str(e.args[0]) if e.args else type(e).__name__)
            raise
        finally:
            st.duration = time.monotonic() - start
            self.log(f"{name}: {st.status} ({st.duration:.1f}s){' - ' + st.detail if st.detail and st.status != 'ok' else ''}")

    def write_log(self, rel: str, res: ExecResult, header: str = "") -> str:
        path = self.logdir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{header}exit={res.exit_code} duration={res.duration:.2f}s"
                        f"{' TIMED OUT' if res.timed_out else ''}\n"
                        f"---- stdout ----\n{res.stdout}\n---- stderr ----\n{res.stderr}\n", encoding="utf-8")
        return str(path.relative_to(self.opts.out_dir))

    def run(self) -> TargetResult:
        r = self.result
        start = time.monotonic()
        try:
            self._pipeline()
        except Cancelled:
            r.findings.append(Finding("error", "run", "run was cancelled"))
        except StageFailed as e:
            r.findings.append(Finding("error", "setup", e.args[0], list(e.args[1])))
        except SandboxError as e:
            r.findings.append(Finding("error", "sandbox", f"sandbox failure: {e}"))
        except Exception as e:  # never let one target take down the whole run
            r.findings.append(Finding("error", "run", f"{type(e).__name__}: {e}"))
        finally:
            r.verdict = verdict_for(r.findings)
            self._teardown()
            r.duration = time.monotonic() - start
            self.log(f"verdict: {r.verdict}")
        return r

    def _pipeline(self) -> None:
        cfg, r, platform = self.cfg, self.result, self.platform

        platform.provision(self)

        with self.stage("deploy") as st:
            for d in cfg.deploy:
                self.box.copy_in(d.src, d.dest, d.exclude)
            platform.upload_patch_files(self)
            st.detail = (f"{len(cfg.deploy)} director{'y' if len(cfg.deploy) == 1 else 'ies'}, "
                         f"{len(self.patch.files)} patch file(s)")

        with self.stage("baseline"):
            r.baseline = self._phase("baseline")
            r.os = r.baseline.snapshot.os if r.baseline.snapshot else ""

        if not platform.apply_patch(self):
            return

        with self.stage("verify"):
            r.patched = self._phase("patched")

        self._compare(r.baseline, r.patched)

        if self.opts.verify_rollback:
            with self.stage("rollback") as st:
                ok = platform.rollback(self)
                if ok is None:
                    st.status = "skipped"
                    st.detail = "no rollback method defined for this patch"
                    r.findings.append(Finding("warn", "rollback", "rollback not verified: define "
                                              "[patch].rollback to test the back-out plan"))
                    return
                if not ok:
                    st.status = "failed"
                    return
            with self.stage("verify-rollback"):
                r.rollback = self._phase("rollback")
            self._compare_rollback(r.baseline, r.rollback)

    def _phase(self, phase: str) -> Phase:
        ph = Phase()
        for i, cmd in enumerate(self.cfg.services):
            res = self.box.exec(cmd, timeout=300)
            self.write_log(f"{phase}/service-{i + 1:02d}.log", res, f"$ {cmd}\n")
            ph.services.append((cmd, res.ok))
        for check in self.cfg.checks:
            if self.cancel.is_set():
                raise Cancelled()
            res = self.box.exec(check.run, timeout=check.timeout)
            logf = self.write_log(f"{phase}/{slugify(check.name)}.log", res, f"$ {check.run}\n")
            cr = CheckResult(check.name, res.ok, res.exit_code, res.duration, res.timed_out,
                             log_file=logf)
            if not res.ok:
                lines = [l for l in res.output.splitlines() if l.strip()]
                cr.tail = list(dict.fromkeys(lines))[-8:]
            try:
                if check.results == "tap":
                    cr.cases = results.parse_tap(res.stdout)
                elif check.results and check.results.startswith("junit:"):
                    local = self.logdir / phase / f"{slugify(check.name)}.junit.xml"
                    if self.box.copy_out(check.results[6:], local):
                        cr.cases = results.parse_junit(local.read_bytes())
                    else:
                        cr.note = "JUnit report was not produced"
            except Exception as e:
                cr.note = f"could not parse test results: {e}"
            ph.checks[check.name] = cr
            self.log(f"  {phase}: {check.name} {'PASS' if cr.passed else 'FAIL'} ({cr.duration:.1f}s)")
        if self.cfg.health.enabled:
            ph.snapshot = self.platform.capture(self)
        return ph

    def _compare(self, before: Phase, after: Phase) -> None:
        r = self.result
        for (cmd, ok_b), (_, ok_a) in zip(before.services, after.services):
            if ok_b and not ok_a:
                r.findings.append(Finding("fail", "services", f"service no longer starts: {cmd}"))
        r.deltas, fs = compare_checks(self.cfg.checks, before.checks, after.checks)
        r.findings.extend(fs)
        if before.snapshot and after.snapshot:
            r.packages, r.files, fs = compare_snapshots(before.snapshot, after.snapshot)
            r.findings.extend(fs)
            if self.platform.patch_changed_nothing(self) and not (
                    r.packages.upgraded or r.packages.added or r.packages.removed):
                r.findings.append(Finding("warn", "patch", "the patch changed no packages "
                                          "(already up to date, or it did not install)"))

    def _compare_rollback(self, baseline: Phase, rolled: Phase) -> None:
        r = self.result
        broken = [n for n, c in baseline.checks.items()
                  if c.passed and not rolled.checks.get(n, c).passed]
        if broken:
            r.findings.append(Finding("fail", "rollback", "checks still failing after rollback",
                                      broken))
        if baseline.snapshot and rolled.snapshot:
            pk, _, _ = compare_snapshots(baseline.snapshot, rolled.snapshot)
            diff = ([f"{n}: {o} -> {v}" for n, o, v in pk.upgraded] +
                    [f"+{n} {v}" for n, v in pk.added] + [f"-{n} {v}" for n, v in pk.removed])
            if diff:
                r.findings.append(Finding("warn", "rollback", "rollback did not restore the "
                                          "original package set", diff))
        if not broken:
            r.findings.append(Finding("info", "rollback", "rollback verified: all baseline "
                                      "checks pass again after backing the patch out"))

    def _teardown(self) -> None:
        if not self.box:
            return
        r = self.result
        if self.opts.keep_on_failure and r.verdict in ("FAIL", "ERROR") and self.box.started:
            r.kept_container = self.box.name
            self.kept_cleanup_name = getattr(self.box, "cleanup_name", self.box.name)
            self.log(f"kept for debugging: {self.platform.debug_hint(self.box.name)} "
                     f"(remove with: {self.gc_command()})")
            return
        st = Stage("teardown")
        start = time.monotonic()
        try:
            self.box.destroy()
            st.status = "ok"
        except Exception as e:
            # A clone left behind costs money and may hold production data: say so loudly.
            st.status, st.detail = "failed", str(e)
            r.findings.append(Finding("error", "cleanup", f"teardown failed; resources may be left "
                                      f"behind. Run: {self.gc_command()}", [str(e)[:500]]))
            r.verdict = verdict_for(r.findings)
            self.log(f"TEARDOWN FAILED: {e}")
        st.duration = time.monotonic() - start
        r.stages.append(st)

    def gc_command(self) -> str:
        return "python -m patchlab_internal gc" + (f" --config {self.cfg.path}"
                                          if self.cfg.sandbox.provider != "docker" else "")


# ---------------------------------------------------------------- whole run

def new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def run(cfg: Config, patch: Patch, opts: Options) -> RunReport:
    run_id = opts.run_id or new_run_id()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", run_id):
        raise ValueError(f"invalid run id: {run_id!r}")
    opts.out_dir = (opts.out_dir / run_id).resolve()
    opts.out_dir.mkdir(parents=True, exist_ok=True)
    images = opts.images or cfg.sandbox.images
    log = Logger(opts.quiet)
    cancel = threading.Event()
    report = RunReport(run_id, cfg, patch, dt.datetime.now().astimezone(), out_dir=opts.out_dir)

    log("run", f"{run_id}: testing '{patch.label}' on {', '.join(images)}")
    platform = make_platform(cfg)
    runs = [TargetRun(cfg, patch, img, run_id, opts, log, cancel, slug=slug)
            for img, slug in zip(images, unique_slugs(images))]

    prev_term = signal.getsignal(signal.SIGTERM)
    # Windows has no SIGTERM delivery for console apps; the web front end
    # cancels runs there with CTRL_BREAK_EVENT, which arrives as SIGBREAK.
    prev_break = signal.getsignal(signal.SIGBREAK) if hasattr(signal, "SIGBREAK") else None
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _raise_interrupt)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, _raise_interrupt)
    pool = ThreadPoolExecutor(max_workers=opts.jobs or len(runs))
    futures = [pool.submit(tr.run) for tr in runs]
    try:
        for f in futures:
            while not f.done():
                time.sleep(0.2)
    except KeyboardInterrupt:
        report.cancelled = True
        cancel.set()
        # A second Ctrl-C / cancel must not abort the clean-up half-way.
        if threading.current_thread() is threading.main_thread():
            for sig in _interrupt_signals():
                signal.signal(sig, lambda *_: log("run", "clean-up in progress; please wait"))
        log("run", "interrupted - tearing down sandboxes")
        try:
            platform.remove(platform.leftovers(run_id))
        except SandboxError as e:
            log("run", f"cleanup after interrupt failed: {e}")
    finally:
        pool.shutdown(wait=True)
        # After a cancel the handlers stay "please wait" until the final sweep is done.
        if not report.cancelled and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, prev_term)
            if hasattr(signal, "SIGBREAK"):
                signal.signal(signal.SIGBREAK, prev_break)

    report.targets = [tr.result for tr in runs]
    # Safety net: sweep anything labelled with this run that was not deliberately kept.
    # Compare provider-level names (e.g. GCP lower-cases them), not display names.
    kept = {tr.kept_cleanup_name for tr in runs if tr.kept_cleanup_name}
    try:
        leftovers = [c for c in platform.leftovers(run_id) if c not in kept]
        if leftovers:
            platform.remove(leftovers)
    except SandboxError as e:
        log("run", f"final cleanup sweep failed: {e} (run 'python -m patchlab_internal gc')")
    report.cleanup = (f"{len(kept)} sandbox(es) kept for debugging" if kept
                      else "all sandboxes removed")
    report.finished = dt.datetime.now().astimezone()
    if report.cancelled and threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, prev_term)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, prev_break)
    return report


def _interrupt_signals():
    sigs = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGBREAK"):
        sigs.append(signal.SIGBREAK)
    return sigs


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt()
