"""Compare baseline and patched phases and turn the differences into findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Check
from .probes import Snapshot
from .results import FAIL, PASS, SKIP

# Windows events that always mean trouble when they first appear after a patch.
CRITICAL_EVENTS = {
    "System/Microsoft-Windows-WER-SystemErrorReporting/1001",   # bugcheck (BSOD)
    "System/BugCheck/1001",
    "System/Microsoft-Windows-Kernel-Power/41",                # unexpected reboot
    "System/EventLog/6008",                                    # unexpected shutdown
    "System/Microsoft-Windows-WindowsUpdateClient/20",         # update install failure
    "Setup/Microsoft-Windows-Servicing/3",
}
CRITICAL_EVENT_PROVIDERS = ("Microsoft-Windows-WHEA-Logger",)  # hardware errors
# Superseded Windows hotfix entries disappear when a newer cumulative update lands.
_SUPERSEDABLE = re.compile(r"^KB\d+$")

# Verdicts, worst last.
VERDICTS = ("PASS", "WARN", "FAIL", "ERROR")
SEVERITY_VERDICT = {"info": "PASS", "warn": "WARN", "fail": "FAIL", "error": "ERROR"}


@dataclass
class CheckResult:
    name: str
    passed: bool
    exit_code: int
    duration: float
    timed_out: bool = False
    cases: dict[str, str] = field(default_factory=dict)
    log_file: str | None = None
    note: str | None = None
    tail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "passed": self.passed, "exit_code": self.exit_code,
            "duration": round(self.duration, 2), "timed_out": self.timed_out,
            "cases": self.cases, "log_file": self.log_file, "note": self.note,
            "tail": self.tail,
        }


@dataclass
class Finding:
    severity: str  # info | warn | fail | error
    area: str
    message: str
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"severity": self.severity, "area": self.area, "message": self.message,
                "details": self.details}


@dataclass
class CheckDelta:
    name: str
    category: str
    critical: bool
    before: CheckResult | None
    after: CheckResult | None
    transition: str  # ok | regressed | fixed | still-failing | missing
    case_regressions: list[str] = field(default_factory=list)
    case_fixes: list[str] = field(default_factory=list)
    case_still_failing: list[str] = field(default_factory=list)
    case_new: list[str] = field(default_factory=list)
    # Passed before, skipped after: a test that stopped running proves nothing.
    case_now_skipped: list[str] = field(default_factory=list)
    slowdown: float | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "category": self.category, "critical": self.critical,
            "transition": self.transition,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "case_regressions": self.case_regressions, "case_fixes": self.case_fixes,
            "case_still_failing": self.case_still_failing, "case_new": self.case_new,
            "case_now_skipped": self.case_now_skipped,
            "slowdown": self.slowdown,
        }


def worst(verdicts) -> str:
    return max(verdicts, key=VERDICTS.index, default="PASS")


def verdict_for(findings: list[Finding]) -> str:
    return worst(SEVERITY_VERDICT[f.severity] for f in findings)


def compare_checks(checks: list[Check], before: dict[str, CheckResult],
                   after: dict[str, CheckResult]) -> tuple[list[CheckDelta], list[Finding]]:
    deltas: list[CheckDelta] = []
    findings: list[Finding] = []
    for check in checks:
        b, a = before.get(check.name), after.get(check.name)
        if a is None:
            deltas.append(CheckDelta(check.name, check.category, check.critical, b, a, "missing"))
            continue
        if b is None:
            transition = "ok" if a.passed else "regressed"
        elif b.passed and a.passed:
            transition = "ok"
        elif b.passed and not a.passed:
            transition = "regressed"
        elif not b.passed and a.passed:
            transition = "fixed"
        else:
            transition = "still-failing"
        d = CheckDelta(check.name, check.category, check.critical, b, a, transition)

        bc, ac = (b.cases if b else {}), a.cases
        for case, status in ac.items():
            prev = bc.get(case)
            if status == FAIL and prev == PASS:
                d.case_regressions.append(case)
            elif status == FAIL and prev is None:
                d.case_regressions.append(case + " (new test)")
            elif status == PASS and prev == FAIL:
                d.case_fixes.append(case)
            elif status == FAIL and prev == FAIL:
                d.case_still_failing.append(case)
            elif status == SKIP and prev == PASS:
                d.case_now_skipped.append(case)
            elif prev is None:
                d.case_new.append(case)
        # A test that passed before and has vanished is as bad as a failure:
        # the suite may have crashed or the test was silently removed.
        for case, status in bc.items():
            if status == PASS and case not in ac and ac:
                d.case_regressions.append(case + " (no longer reported)")

        if b and b.passed and a.passed and check.perf_tolerance is not None and b.duration > 0.5:
            d.slowdown = (a.duration - b.duration) / b.duration
        deltas.append(d)

        sev = "fail" if check.critical else "warn"
        if transition == "regressed":
            what = "timed out" if a.timed_out else f"exit code {a.exit_code}"
            findings.append(Finding(sev, "checks", f"'{check.name}' passed before the patch "
                                    f"and fails after it ({what})", d.case_regressions or a.tail))
        elif d.case_regressions:
            findings.append(Finding(sev, "checks", f"'{check.name}': "
                                    f"{len(d.case_regressions)} test(s) regressed",
                                    d.case_regressions))
        if transition == "still-failing":
            findings.append(Finding("warn", "checks", f"'{check.name}' was already failing "
                                    "before the patch (pre-existing, not caused by it)",
                                    d.case_still_failing))
        if d.case_now_skipped:
            findings.append(Finding("warn", "checks", f"'{check.name}': "
                                    f"{len(d.case_now_skipped)} test(s) that passed before the "
                                    "patch are skipped after it", d.case_now_skipped))
        if d.case_fixes:
            n = len(d.case_fixes)
            findings.append(Finding("info", "checks", f"'{check.name}': the patch fixed "
                                    f"{n} previously failing test{'s' if n != 1 else ''}",
                                    d.case_fixes))
        elif transition == "fixed":
            findings.append(Finding("info", "checks", f"'{check.name}' failed before the "
                                    "patch and passes after it"))
        if d.slowdown is not None and d.slowdown > check.perf_tolerance:
            findings.append(Finding("warn", "performance",
                                    f"'{check.name}' is {d.slowdown:.0%} slower after the patch "
                                    f"({b.duration:.1f}s -> {a.duration:.1f}s)"))
    return deltas, findings


@dataclass
class PackageChanges:
    upgraded: list[tuple[str, str, str]] = field(default_factory=list)
    added: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "upgraded": [{"name": n, "from": o, "to": v} for n, o, v in self.upgraded],
            "added": [{"name": n, "version": v} for n, v in self.added],
            "removed": [{"name": n, "version": v} for n, v in self.removed],
        }


def compare_snapshots(before: Snapshot, after: Snapshot) -> tuple[PackageChanges, dict, list[Finding]]:
    findings: list[Finding] = []
    for snap, phase in ((before, "baseline"), (after, "patched")):
        if snap.error:
            findings.append(Finding("warn", "health", f"{phase} health probe incomplete: {snap.error}"))

    pk = PackageChanges()
    for name, ver in sorted(after.packages.items()):
        old = before.packages.get(name)
        if old is None:
            pk.added.append((name, ver))
        elif old != ver:
            pk.upgraded.append((name, old, ver))
    pk.removed = sorted((n, v) for n, v in before.packages.items() if n not in after.packages)
    superseded = [n for n, _ in pk.removed if _SUPERSEDABLE.match(n)]
    if superseded:
        findings.append(Finding("info", "packages", f"{len(superseded)} older update(s) superseded "
                                "by the new cumulative update", superseded))
    real_removed = [(n, v) for n, v in pk.removed if not _SUPERSEDABLE.match(n)]
    if real_removed:
        findings.append(Finding("warn", "packages", f"{len(real_removed)} package(s) were removed "
                                "by the patch", [f"{n} {v}" for n, v in real_removed]))

    new_db = [i for i in after.pkgdb_issues if i not in before.pkgdb_issues]
    if new_db:
        findings.append(Finding("fail", "packages", "package database reports new problems "
                                "(broken or half-installed packages)", new_db))

    new_libs = sorted(set(after.broken_libs) - set(before.broken_libs))
    if new_libs:
        findings.append(Finding("fail", "libraries", f"{len(new_libs)} binary/library "
                                "dependency(ies) no longer resolve", new_libs))
    fixed_libs = sorted(set(before.broken_libs) - set(after.broken_libs))
    if fixed_libs:
        findings.append(Finding("info", "libraries", "previously unresolved library "
                                "dependencies now resolve", fixed_libs))

    lost_ports = sorted(set(before.listening) - set(after.listening))
    if lost_ports:
        findings.append(Finding("fail", "services", "services stopped listening after the patch",
                                [f"tcp/{p}" for p in lost_ports]))
    new_ports = sorted(set(after.listening) - set(before.listening))
    if new_ports:
        findings.append(Finding("warn", "services", "new listening ports appeared after the patch",
                                [f"tcp/{p}" for p in new_ports]))

    findings.extend(_compare_windows(before, after))

    files = {
        "changed": sorted(p for p in after.files if p in before.files and before.files[p] != after.files[p]),
        "added": sorted(p for p in after.files if p not in before.files),
        "removed": sorted(p for p in before.files if p not in after.files),
    }
    if files["removed"]:
        findings.append(Finding("warn", "config", f"{len(files['removed'])} watched file(s) "
                                "were deleted", files["removed"]))
    if files["changed"]:
        findings.append(Finding("info", "config", f"{len(files['changed'])} watched file(s) were "
                                "modified; review for overwritten local configuration",
                                files["changed"]))
    return pk, files, findings


def _compare_windows(before: Snapshot, after: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    down = sorted(set(after.services_down) - set(before.services_down))
    if down:
        findings.append(Finding("fail", "services", f"{len(down)} automatic service(s) are no "
                                "longer running after the patch", down))
    recovered = sorted(set(before.services_down) - set(after.services_down))
    if recovered:
        findings.append(Finding("info", "services", "automatic services that were stopped "
                                "before the patch are now running", recovered))

    devices = sorted(set(after.problem_devices) - set(before.problem_devices))
    if devices:
        findings.append(Finding("fail", "drivers", f"{len(devices)} device(s) report driver "
                                "problems after the patch", devices))

    new_events = {k: v for k, v in after.events.items() if k not in before.events}
    crit = sorted(k for k, v in new_events.items()
                  if k in CRITICAL_EVENTS or v.get("level") == "Critical"
                  or any(p in k for p in CRITICAL_EVENT_PROVIDERS))
    other = sorted(k for k in new_events if k not in crit)

    def describe(k: str) -> str:
        e = new_events[k]
        return f"{k} x{e.get('count', 1)}: {e.get('message', '')}"[:300]

    if crit:
        findings.append(Finding("fail", "events", "critical events appeared after the patch "
                                "(crash, unexpected reboot, hardware or update failure)",
                                [describe(k) for k in crit]))
    if other:
        findings.append(Finding("warn", "events", f"{len(other)} new kind(s) of error event "
                                "logged after the patch", [describe(k) for k in other]))

    if after.pending_reboot and not before.pending_reboot:
        findings.append(Finding("warn", "reboot", "a reboot is still pending after the patch "
                                "and reboot cycles", after.pending_reboot))
    return findings
