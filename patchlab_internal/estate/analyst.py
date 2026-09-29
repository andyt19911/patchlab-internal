"""The analyst agent's tools (DESIGN.md §4.10): watch the work while it runs, and read what it did.

- ``Progress`` is written by the cycle as it goes (state/progress.json): which
  step is running on what, since when, and how long each finished step took.
- ``watch`` compares the running step with how long the same step took in
  earlier cycles and says whether it looks stuck.
- ``record_metrics`` appends one line per package per cycle to
  state/metrics.jsonl; ``trends`` reads it back and names what moved.
- ``explain`` gathers the evidence for a package's failures: the failing
  tests with their log excerpts, what changed since they last passed, and how
  often each has flaked before.
- ``save_report`` stores the analyst's write-up for the digest and the
  Estate page.

All of it reads and writes state/ only. The analyst never changes a decision;
the gate alone decides.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import statistics
from contextlib import contextmanager
from pathlib import Path

from . import state
from .manifest import Estate

PROGRESS = "progress.json"
METRICS = "metrics.jsonl"
ANALYSIS = "analysis"
# A step is stuck when it has run this many times longer than it usually takes,
# and at least STUCK_MIN_EXTRA longer; with no history, after STUCK_NO_HISTORY.
STUCK_FACTOR = 3.0
STUCK_MIN_EXTRA = dt.timedelta(minutes=20)
STUCK_NO_HISTORY = dt.timedelta(hours=2)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


# ---------------------------------------------------------------- progress

class Progress:
    """The cycle's live record: the step in hand and the steps done."""

    def __init__(self, estate: Estate, started: dt.datetime):
        self.path = estate.state_dir / PROGRESS
        self.data = {"started": _iso(started), "host": socket.gethostname(), "pid": os.getpid(),
                     "current": None, "done": [], "finished": None}
        self._write()

    def _write(self) -> None:
        state.write_json(self.path, self.data)

    @contextmanager
    def step(self, target: str, name: str):
        begun = _now()
        self.data["current"] = {"target": target, "step": name, "since": _iso(begun)}
        self._write()
        ok = False
        try:
            yield
            ok = True
        finally:
            self.data["done"].append({"target": target, "step": name, "ok": ok,
                                      "seconds": round((_now() - begun).total_seconds())})
            self.data["current"] = None
            self._write()

    def finish(self) -> None:
        self.data["finished"] = _iso(_now())
        self._write()


def _history(estate: Estate) -> dict[tuple[str, str], list[int]]:
    """Seconds each (target, step) took in earlier cycles."""
    out: dict[tuple[str, str], list[int]] = {}
    d = estate.state_dir / "cycles"
    for f in sorted(d.glob("*.json"))[-30:] if d.is_dir() else []:
        for s in (state.read_json(f) or {}).get("steps", []):
            if s.get("ok"):
                out.setdefault((s["target"], s["step"]), []).append(int(s["seconds"]))
    return out


def _alive(pid: int) -> bool:
    if os.name == "nt":
        return True        # os.kill(pid, 0) would terminate the process on Windows
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    return True


def watch(estate: Estate, now: dt.datetime | None = None) -> dict:
    """Is a cycle running, what is it doing, and does it look stuck?"""
    now = now or _now()
    p = state.read_json(estate.state_dir / PROGRESS)
    if not p:
        return {"running": False, "note": "no cycle has reported progress yet"}
    out = {"started": p["started"], "finished": p.get("finished"), "steps_done": len(p["done"]),
           "failed_steps": [s for s in p["done"] if not s["ok"]]}
    if p.get("finished"):
        return {"running": False, **out}
    same_host = p.get("host") == socket.gethostname()
    if same_host and not _alive(int(p.get("pid", 0))):
        return {"running": False, "died": True, **out,
                "note": f"the cycle's process ({p.get('pid')}) is gone without finishing"}
    cur = p.get("current")
    if not cur:
        return {"running": True, **out, "current": None}
    elapsed = now - dt.datetime.fromisoformat(cur["since"])
    past = _history(estate).get((cur["target"], cur["step"]), [])
    usual = dt.timedelta(seconds=statistics.median(past)) if past else None
    if usual is not None:
        stuck = elapsed > max(usual * STUCK_FACTOR, usual + STUCK_MIN_EXTRA)
    else:
        stuck = elapsed > STUCK_NO_HISTORY
    return {"running": True, **out, "current": cur, "elapsed_seconds": round(elapsed.total_seconds()),
            "usual_seconds": round(usual.total_seconds()) if usual else None, "looks_stuck": stuck}


# ---------------------------------------------------------------- metrics and trends

def record_metrics(estate: Estate, when: dt.datetime, steps: list[dict]) -> int:
    """One line per package for this cycle, from the state the cycle just wrote."""
    from . import digest
    seconds: dict[str, int] = {}
    for s in steps:
        seconds[s["target"]] = seconds.get(s["target"], 0) + int(s["seconds"])
    lines = []
    for r in digest.collect(estate):
        pkg, h, scan, code = r["package"], r["health"] or {}, r["scan"] or {}, r["code"] or {}
        vul = scan.get("scan", {}).get("vulnerable", [])
        lines.append({"when": _iso(when), "package": pkg.id, "commit": h.get("commit") or scan.get("commit"),
                      "health": h.get("status"), "passing": h.get("passing_tests"),
                      "failing": len(h.get("failing") or []), "flaky": h.get("flaky", []),
                      "advisories": len(vul), "advisories_production": sum(1 for v in vul if v.get("production")),
                      "code_high": (code.get("counts") or {}).get("high"),
                      "code_total": sum((code.get("counts") or {}).values()) if code else None,
                      "seconds": seconds.get(pkg.id)})
    path = estate.state_dir / METRICS
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")
    return len(lines)


def _metrics(estate: Estate) -> list[dict]:
    path = estate.state_dir / METRICS
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def trends(estate: Estate, days: int = 30, now: dt.datetime | None = None) -> dict:
    """Per package: the series, and plain statements of what moved since the previous cycle
    and against the usual."""
    now = now or _now()
    since = now - dt.timedelta(days=days)
    by: dict[str, list[dict]] = {}
    for m in _metrics(estate):
        if dt.datetime.fromisoformat(m["when"]) >= since:
            by.setdefault(m["package"], []).append(m)
    out = {}
    for pkg, rows in sorted(by.items()):
        rows.sort(key=lambda m: m["when"])
        last, prev = rows[-1], rows[-2] if len(rows) > 1 else None
        notes = []
        if prev:
            for key, what in (("failing", "failing tests"), ("advisories_production", "advisories in production code"),
                              ("advisories", "advisories"), ("code_high", "high code findings")):
                a, b = prev.get(key), last.get(key)
                if a is not None and b is not None and a != b:
                    notes.append(f"{what}: {a} -> {b}")
            if prev.get("passing") and last.get("passing") is not None and last["passing"] < prev["passing"]:
                notes.append(f"passing tests dropped: {prev['passing']} -> {last['passing']}")
            if prev.get("health") != last.get("health"):
                notes.append(f"health: {prev.get('health')} -> {last.get('health')}")
        durations = [m["seconds"] for m in rows[:-1] if m.get("seconds")]
        if durations and last.get("seconds"):
            usual = statistics.median(durations)
            if last["seconds"] > usual * 1.5 and last["seconds"] - usual > 120:
                notes.append(f"took {last['seconds']}s against a usual {round(usual)}s")
        flaky: dict[str, int] = {}
        for m in rows:
            for t in m.get("flaky") or []:
                flaky[t] = flaky.get(t, 0) + 1
        repeat = {t: n for t, n in flaky.items() if n > 1}
        if repeat:
            notes.append("flaky more than once: " + ", ".join(f"{t} ({n}x)" for t, n in sorted(repeat.items())))
        out[pkg] = {"cycles": len(rows), "last": last, "notes": notes,
                    "series": {k: [m.get(k) for m in rows] for k in ("passing", "failing", "advisories", "seconds")}}
    return out


# ---------------------------------------------------------------- explain

def explain(estate: Estate, package: str, lines: int = 40) -> dict:
    """The evidence for a package's current failures, for the analyst to reason over."""
    from . import repair
    pkg = estate.find(package)
    hdir = estate.state_dir / pkg.slug / "health"
    runs = state.history(hdir, "summary.json", limit=30)
    if not runs:
        return {"package": pkg.id, "note": "no health run yet"}
    h = runs[0]
    failing = h.get("failing", [])
    excerpts = {}
    if failing and h.get("report"):
        excerpts = repair.excerpts_from(Path(h["report"]), failing[:10], "before", lines)
    last_pass = {}
    for t in failing:
        for older in runs[1:]:
            if t not in older.get("failing", []) and older.get("status") in ("healthy", "failing"):
                last_pass[t] = {"when": older.get("when"), "commit": older.get("commit")}
                break
    flaky_before = {t: sum(1 for r in runs if t in (r.get("flaky") or [])) for t in failing}
    return {"package": pkg.id, "commit": h.get("commit"), "status": h.get("status"), "error": h.get("error"),
            "failing": failing, "newly_failing": h.get("newly_failing", []),
            "commits_since_last_pass": h.get("commits_since_last_pass", []),
            "last_passed": last_pass, "flaky_before": {t: n for t, n in flaky_before.items() if n},
            "excerpts": excerpts, "not_covered": pkg.not_covered,
            "recent": [{"when": r.get("when"), "status": r.get("status"), "failing": len(r.get("failing") or [])}
                       for r in runs[:10]]}


# ---------------------------------------------------------------- the write-up

def save_report(estate: Estate, text: str, day: dt.date | None = None) -> Path:
    text = text.strip()
    if not text or len(text) > 20000:
        raise RuntimeError("the analysis is 1 to 20000 characters")
    path = estate.state_dir / ANALYSIS / f"{(day or dt.date.today()).isoformat()}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def latest_report(estate: Estate) -> tuple[str, str] | None:
    d = estate.state_dir / ANALYSIS
    files = sorted(d.glob("*.md")) if d.is_dir() else []
    return (files[-1].stem, files[-1].read_text(encoding="utf-8")) if files else None
