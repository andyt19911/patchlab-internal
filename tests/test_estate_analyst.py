"""The analyst agent's tools: live progress and stuck steps, metrics and trends, failure evidence."""

import datetime as dt
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from patchlab_internal.estate import analyst, digest, manifest, operator, state

MANIFEST = textwrap.dedent("""\
    [estate]
    workdir = "work"
    [[repo]]
    name = "app"
    url = "https://github.com/Org/app"
      [[repo.package]]
      path = "backend"
      ecosystem = "npm"
      image = "node:24-bookworm"
        [[repo.package.checks]]
        name = "unit"
        run = "npm test"
""")
T0 = dt.datetime(2026, 9, 29, 2, 0, tzinfo=dt.timezone.utc)


def load() -> manifest.Estate:
    for k in ("PATCHLAB_INTERNAL_ESTATE_WORKDIR", "PATCHLAB_INTERNAL_CA_BUNDLE"):
        os.environ.pop(k, None)
    d = Path(tempfile.mkdtemp())
    (d / "estate.toml").write_text(MANIFEST)
    return manifest.load(d / "estate.toml")


def health(est, run: str, **summary) -> None:
    state.write_json(est.state_dir / "app-backend" / "health" / run / "summary.json",
                     {"package": "app/backend", "commit": "c" * 40, "failing": [], **summary})


class ProgressAndWatchTests(unittest.TestCase):
    def test_progress_records_steps_and_watch_reads_them(self):
        est = load()
        p = analyst.Progress(est, T0)
        with p.step("app/backend", "health"):
            w = analyst.watch(est)
            self.assertTrue(w["running"])
            self.assertEqual(w["current"]["step"], "health")
            self.assertFalse(w["looks_stuck"])
        with self.assertRaises(ValueError):
            with p.step("app/backend", "propose"):
                raise ValueError("boom")
        p.finish()
        w = analyst.watch(est)
        self.assertFalse(w["running"])
        self.assertEqual([s["ok"] for s in p.data["done"]], [True, False])
        self.assertEqual(w["failed_steps"][0]["step"], "propose")

    def test_a_step_far_past_its_usual_time_looks_stuck(self):
        est = load()
        for i, secs in enumerate((300, 320, 310)):
            operator.record_cycle(est, T0 - dt.timedelta(days=3 - i), {}, [],
                                  steps=[{"target": "app/backend", "step": "health", "ok": True, "seconds": secs}])
        state.write_json(est.state_dir / analyst.PROGRESS, {
            "started": T0.isoformat(), "host": "elsewhere", "pid": 1, "done": [], "finished": None,
            "current": {"target": "app/backend", "step": "health", "since": T0.isoformat()}})
        self.assertFalse(analyst.watch(est, T0 + dt.timedelta(minutes=20))["looks_stuck"])
        w = analyst.watch(est, T0 + dt.timedelta(minutes=40))
        self.assertTrue(w["looks_stuck"])
        self.assertEqual(w["usual_seconds"], 310)

    def test_no_history_waits_longer(self):
        est = load()
        state.write_json(est.state_dir / analyst.PROGRESS, {
            "started": T0.isoformat(), "host": "elsewhere", "pid": 1, "done": [], "finished": None,
            "current": {"target": "new/pkg", "step": "health", "since": T0.isoformat()}})
        self.assertFalse(analyst.watch(est, T0 + dt.timedelta(minutes=90))["looks_stuck"])
        self.assertTrue(analyst.watch(est, T0 + dt.timedelta(hours=3))["looks_stuck"])

    @unittest.skipIf(os.name == "nt", "liveness is POSIX-only")
    def test_a_dead_cycle_on_this_host_is_reported(self):
        est = load()
        import socket
        state.write_json(est.state_dir / analyst.PROGRESS, {
            "started": T0.isoformat(), "host": socket.gethostname(), "pid": 2 ** 22 + 7, "done": [],
            "finished": None, "current": None})
        self.assertTrue(analyst.watch(est).get("died"))


class TrendTests(unittest.TestCase):
    def test_metrics_then_trends(self):
        est = load()
        for i, (passing, failing, secs, flaky) in enumerate(
                ((650, 0, 300, []), (650, 0, 310, ["unit: a"]), (640, 2, 900, ["unit: a"]))):
            health(est, f"2026092{i}-000000-health", status="failing" if failing else "healthy",
                   passing_tests=passing, failing=[f"unit: t{j}" for j in range(failing)], flaky=flaky)
            analyst.record_metrics(est, T0 - dt.timedelta(days=2 - i),
                                   [{"target": "app/backend", "step": "health", "ok": True, "seconds": secs}])
        t = analyst.trends(est, now=T0 + dt.timedelta(hours=1))["app/backend"]
        self.assertEqual(t["cycles"], 3)
        self.assertEqual(t["series"]["passing"], [650, 650, 640])
        notes = " | ".join(t["notes"])
        for part in ("failing tests: 0 -> 2", "passing tests dropped: 650 -> 640", "health: healthy -> failing",
                     "took 900s", "flaky more than once: unit: a (2x)"):
            self.assertIn(part, notes)


class ExplainTests(unittest.TestCase):
    def test_gathers_failures_last_pass_and_flaky_history(self):
        est = load()
        report = Path(tempfile.mkdtemp())
        (report / "unit.log").write_text("ok 1\nFAIL  t1 > breaks\nexpected 1, got 2\n")
        state.write_json(report / "report.json", {"targets": [{"checks": [
            {"name": "unit", "before": {"log_file": "unit.log", "cases": {"t1 > breaks": "fail"}}}]}]})
        health(est, "20260927-000000-health", status="healthy", when="2026-09-27", flaky=["unit: t1 > breaks"])
        health(est, "20260928-000000-health", status="broken", failing=["unit: t1 > breaks"],
               newly_failing=["unit: t1 > breaks"], commits_since_last_pass=["abc fix things"],
               report=str(report))
        e = analyst.explain(est, "app/backend")
        self.assertEqual(e["failing"], ["unit: t1 > breaks"])
        self.assertIn("expected 1, got 2", e["excerpts"]["unit: t1 > breaks"])
        self.assertEqual(e["last_passed"]["unit: t1 > breaks"]["when"], "2026-09-27")
        self.assertEqual(e["flaky_before"], {"unit: t1 > breaks": 1})
        self.assertEqual(e["commits_since_last_pass"], ["abc fix things"])


class ReportTests(unittest.TestCase):
    def test_the_analysis_goes_in_todays_digest(self):
        est = load()
        with self.assertRaises(RuntimeError):
            analyst.save_report(est, "   ")
        analyst.save_report(est, "Two new failures in app/backend, both from commit abc.")
        self.assertIn("## Analysis", digest.render(est))
        self.assertEqual(analyst.latest_report(est)[0], dt.date.today().isoformat())

    def test_metrics_file_is_json_lines(self):
        est = load()
        health(est, "20260928-000000-health", status="healthy", passing_tests=3)
        self.assertEqual(analyst.record_metrics(est, T0, []), 1)
        line = json.loads((est.state_dir / analyst.METRICS).read_text().splitlines()[0])
        self.assertEqual((line["package"], line["passing"]), ("app/backend", 3))


if __name__ == "__main__":
    unittest.main()
