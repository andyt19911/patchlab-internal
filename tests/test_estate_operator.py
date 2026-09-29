"""The operator agent's tools: the cycle record, status, retry, briefs, discovery and the guard."""

import datetime as dt
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from patchlab_internal.estate import manifest, operator, state

MANIFEST = textwrap.dedent("""\
    [estate]
    workdir = "work"
    [[repo]]
    name = "app"
    url = "https://github.com/Org/app"
    not_managed = { "legacy" = "retired, kept for reference" }
      [[repo.package]]
      path = "backend"
      ecosystem = "npm"
      image = "node:24-bookworm"
        [[repo.package.checks]]
        name = "unit"
        run = "npm test"
      [[repo.package]]
      path = "."
      ecosystem = "cargo"
      image = "rust:1"
        [[repo.package.checks]]
        name = "unit"
        run = "cargo test"
""")


def load() -> manifest.Estate:
    for k in ("PATCHLAB_INTERNAL_ESTATE_WORKDIR", "PATCHLAB_INTERNAL_CA_BUNDLE"):
        os.environ.pop(k, None)
    d = Path(tempfile.mkdtemp())
    (d / "estate.toml").write_text(MANIFEST)
    return manifest.load(d / "estate.toml")


def decision(est, rel: str, verdict: str, gate_ok: bool = True) -> Path:
    run = est.state_dir / rel
    run.mkdir(parents=True)
    state.write_json(run / "decision.json", {"verdict": verdict, "summary": "s", "labels": [],
                                             "gate": [{"name": "g", "ok": gate_ok, "detail": "d"}]})
    return run


class CycleAndStatusTests(unittest.TestCase):
    def test_failures_are_recorded_and_classified(self):
        est = load()
        operator.record_cycle(est, dt.datetime(2026, 9, 29, 2, tzinfo=dt.timezone.utc), {"app": "a" * 40}, [
            {"target": "app/backend", "step": "health", "error": "TimeoutExpired: docker pull timed out"},
            {"target": "app/backend", "step": "propose", "error": "KeyError: 'advisories'"},
        ])
        _, cycle = operator.last_cycle(est)
        self.assertEqual([f["transient"] for f in cycle["failures"]], [True, False])
        needs = operator.status(est)["needs"]
        self.assertEqual([(n["step"], n["next"]) for n in needs if n["kind"] == "failed-step"],
                         [("health", "retry"), ("propose", "fix PatchLab")])

    def test_review_decisions_need_a_brief_until_they_have_one(self):
        est = load()
        run = decision(est, "app-backend/proposals/lodash/20260929-0000-p", "REVIEW")
        (est.state_dir / "app-backend" / "health").mkdir(parents=True)
        s = operator.status(est)
        self.assertEqual([n["kind"] for n in s["needs"]], ["review-brief"])
        operator.brief(est, s["needs"][0]["decision"], "A major upgrade: check the changelog's breaking list.")
        self.assertTrue((run / "review.md").is_file())
        self.assertEqual(operator.status(est)["needs"], [])
        self.assertEqual(state.read_json(run / "decision.json")["verdict"], "REVIEW")   # never changed

    def test_briefs_stay_inside_state_and_only_on_review(self):
        est = load()
        decision(est, "app-backend/proposals/x/1", "READY")
        for bad in ("../../etc", "/etc", "nope"):
            with self.assertRaises(RuntimeError):
                operator.brief(est, bad, "text")
        with self.assertRaisesRegex(RuntimeError, "only REVIEW"):
            operator.brief(est, "app-backend/proposals/x/1", "text")


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.est = load()
        operator.record_cycle(self.est, dt.datetime.now(dt.timezone.utc), {"app": "a" * 40}, [
            {"target": "app/backend", "step": "health", "error": "Could not resolve host: registry.npmjs.org"},
            {"target": "app/backend", "step": "propose", "error": "KeyError: 'advisories'"},
        ])

    def test_retries_a_passing_failure_once(self):
        with mock.patch("patchlab_internal.estate.pipeline.health", return_value={"status": "healthy"}) as h:
            res = operator.retry(self.est, "app/backend", "health")
        self.assertTrue(res["ok"])
        h.assert_called_once()
        self.assertEqual(h.call_args.args[2], "a" * 40)       # the commit the cycle ran on
        with self.assertRaisesRegex(RuntimeError, "already retried"):
            operator.retry(self.est, "app/backend", "health")
        needs = operator.status(self.est)["needs"]
        self.assertIn("already retried", needs[0]["next"])

    def test_refuses_what_a_retry_wont_fix(self):
        with self.assertRaisesRegex(RuntimeError, "won't fix"):
            operator.retry(self.est, "app/backend", "propose")
        with self.assertRaisesRegex(RuntimeError, "did not fail"):
            operator.retry(self.est, "app", "images")

    def test_the_agent_queues_and_the_runner_retries(self):
        operator.request_retry(self.est, "app/backend", "health")
        operator.request_retry(self.est, "app/backend", "health")          # once in the queue
        with self.assertRaisesRegex(RuntimeError, "won't fix"):
            operator.request_retry(self.est, "app/backend", "propose")
        with mock.patch("patchlab_internal.estate.pipeline.health", return_value={"status": "healthy"}) as h:
            self.assertEqual(len(operator.run_requests(self.est)), 1)
            self.assertEqual(operator.run_requests(self.est), [])          # done, not repeated
        h.assert_called_once()

    def test_a_failed_retry_is_recorded(self):
        with mock.patch("patchlab_internal.estate.pipeline.health", side_effect=RuntimeError("still down")):
            res = operator.retry(self.est, "app/backend", "health")
        self.assertFalse(res["ok"])
        _, cycle = operator.last_cycle(self.est)
        self.assertEqual(cycle["retries"][0]["error"], "RuntimeError: still down")


class ImportTests(unittest.TestCase):
    def test_only_briefs_and_valid_requests_come_back(self):
        import shutil
        est = load()
        operator.record_cycle(est, dt.datetime.now(dt.timezone.utc), {"app": "a" * 40}, [
            {"target": "app/backend", "step": "health", "error": "HTTP 503 from registry"}])
        decision(est, "app-backend/proposals/x/1", "REVIEW")
        decision(est, "app-backend/proposals/y/1", "BLOCKED")
        copy = Path(tempfile.mkdtemp())
        shutil.copytree(est.state_dir, copy / "state")
        cs = copy / "state"
        (cs / "app-backend/proposals/x/1/review.md").write_text("check the changelog")
        (cs / "app-backend/proposals/y/1/review.md").write_text("sneaky")
        state.write_json(cs / "app-backend/proposals/y/1/decision.json", {"verdict": "READY"})   # tampered
        (cs / "planted.json").write_text("{}")
        cyc = sorted((cs / "cycles").glob("*.json"))[0]
        data = state.read_json(cyc)
        data["requested"] = [{"target": "app/backend", "step": "health"}, {"target": "app", "step": "sync"}]
        data["failures"].append({"target": "app", "step": "sync", "error": "timed out", "transient": True})
        state.write_json(cyc, data)
        res = operator.import_results(est, copy)
        self.assertEqual(res["briefs"], ["app-backend/proposals/x/1"])
        self.assertEqual(res["requests"], [{"target": "app/backend", "step": "health"}])
        self.assertEqual(len(res["refused"]), 2)
        self.assertEqual(state.read_json(est.state_dir / "app-backend/proposals/y/1/decision.json")["verdict"],
                         "BLOCKED")
        self.assertFalse((est.state_dir / "planted.json").exists())
        self.assertFalse((est.state_dir / "app-backend/proposals/y/1/review.md").exists())


class DiscoverTests(unittest.TestCase):
    def test_lists_what_the_manifest_leaves_out(self):
        est = load()
        src = Path(tempfile.mkdtemp())
        for f in ("backend/package.json", "sdk-js/package.json", "sdk-js/node_modules/x/package.json",
                  "crates/auth/Cargo.toml", "Cargo.toml", "legacy/package.json", "docs/package.json",
                  "sdk-js/Dockerfile", "backend/Dockerfile", "demo-sample/package.json"):
            (src / f).parent.mkdir(parents=True, exist_ok=True)
            (src / f).write_text("{}")
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"]
        subprocess.run([*git, "init", "-q"], cwd=src, check=True)
        subprocess.run([*git, "add", "-A"], cwd=src, check=True)
        subprocess.run([*git, "commit", "-qm", "x"], cwd=src, check=True)
        est.repos_dir.mkdir(parents=True)
        subprocess.run(["git", "clone", "-q", "--bare", str(src), str(est.repos_dir / "app.git")], check=True)
        found = {(f["kind"], f.get("path")) for f in operator.discover(est)}
        self.assertEqual(found, {("package", "sdk-js"), ("dockerfile", "sdk-js/Dockerfile"),
                                 ("dockerfile", "backend/Dockerfile")})


class ToolTests(unittest.TestCase):
    def test_compares_pins_with_releases(self):
        def fetch(url):
            if "pypi" in url:
                return {"info": {"version": "9.0.0"}}
            if "gitleaks" in url:
                raise OSError("offline")
            return {"tag_name": "v0.0.1"}
        rows = {r["tool"]: r for r in operator.tool_releases(fetch)}
        self.assertTrue(rows["bandit"]["behind"])
        self.assertIsNone(rows["gitleaks"]["latest"])
        self.assertFalse(rows["trivy"]["behind"])


class GuardTests(unittest.TestCase):
    def test_protected_files(self):
        for f in (".github/workflows/estate-nightly.yml", "patchlab_internal/estate/triage.py",
                  "patchlab_internal/estate/publish.py", "patchlab_internal/estate/operator.py",
                  "tests/test_estate_triage.py", "pyproject.toml", "CLAUDE.md", ".claude/settings.json"):
            self.assertTrue(operator.guard([f]), f)
        self.assertEqual(operator.guard(["patchlab_internal/estate/npm.py", "tests/test_estate_npm.py",
                                         "estate.toml"]), [])

    def test_manifest_may_gain_packages_only(self):
        added = MANIFEST + textwrap.dedent("""\
              [[repo.package]]
              path = "sdk-js"
              ecosystem = "npm"
              image = "node:24-bookworm"
                [[repo.package.checks]]
                name = "unit"
                run = "npm test"
        """)
        self.assertEqual(operator.guard(["estate.toml"], MANIFEST, added), [])
        for bad, why in (
            (MANIFEST.replace('workdir = "work"', 'workdir = "work"\npublish = "draft-pr"'), "[estate]"),
            (MANIFEST + '[repair]\nimage = "x"\ncommand = "y"\n', "[repair]"),
            (MANIFEST.replace("Org/app", "Evil/app"), "re-point"),
            (MANIFEST.replace('run = "npm test"', 'run = "true"'), "not change existing"),
            (added.replace('path = "sdk-js"\n', 'path = "sdk-js"\n  check_network = "open"\n'), "check_network"),
            (MANIFEST.replace('not_managed = { "legacy" = "retired, kept for reference" }\n', ""), None),
        ):
            problems = operator.guard(["estate.toml"], MANIFEST, bad)
            if why:
                self.assertTrue(any(why in p for p in problems), (why, problems))

    def test_new_packages_default_to_isolated_checks(self):
        est = load()
        self.assertEqual(est.find("app/backend").check_network, "isolated")
        self.assertEqual(est.repos[0].not_managed, {"legacy": "retired, kept for reference"})


class CliTests(unittest.TestCase):
    def test_status_is_json(self):
        est = load()
        from patchlab_internal import cli
        with mock.patch("sys.stdout.write") as out:
            code = cli.main(["estate", "-m", str(est.path), "operator", "status"])
        self.assertEqual(code, 0)
        text = "".join(c.args[0] for c in out.call_args_list)
        self.assertEqual(json.loads(text)["needs"], [])


if __name__ == "__main__":
    unittest.main()
