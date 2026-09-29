"""Tests for the optional PatchLab Internal front end (patchlab_internal_web).

Run from the repository root:  python -m unittest discover -s web/tests -t web
"""

import json
import os
import shutil
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "web")]

from patchlab_internal import settings as core_settings  # noqa: E402
from patchlab_internal_web import server  # noqa: E402
from patchlab_internal_web.runs import RunManager  # noqa: E402

TOKEN = "t0ken-for-tests"

# Stands in for `python -m patchlab_internal`: prints progress, writes a report, and
# on SIGINT (cancel) writes a cancelled report, like the real CLI.
FAKE_PATCHLAB = r'''
import json, os, signal, sys, time
if hasattr(signal, "SIGBREAK"):   # Windows: the front end cancels with CTRL_BREAK_EVENT
    def _brk(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGBREAK, _brk)
args = sys.argv[1:]
if args[0] == "gc":
    print("removed 0 clone(s)"); sys.exit(0)
out, run_id = args[args.index("--out") + 1], args[args.index("--run-id") + 1]
delay = float(os.environ.get("FAKE_DELAY", "0.2"))
def report(verdict, cancelled=False):
    d = os.path.join(out, run_id); os.makedirs(d, exist_ok=True)
    json.dump({"name": "fake", "verdict": verdict, "cancelled": cancelled, "run_id": run_id,
               "started": "2026-09-26T10:00:00+00:00", "duration": 1.0, "platform": "linux", "provider": "docker",
               "patch": {"label": " ".join(args)}, "cleanup": "all sandboxes removed",
               "guest_password_seen": bool(os.environ.get("PATCHLAB_INTERNAL_GUEST_PASSWORD")),
               "targets": [{"image": "alpine:3", "verdict": verdict, "findings": [], "checks": [], "stages": []}]},
              open(os.path.join(d, "report.json"), "w"))
try:
    for i in range(5):
        print(f"step {i}", flush=True); time.sleep(delay)
    report("PASS"); print("done", flush=True)
except KeyboardInterrupt:
    print("interrupted - tearing down sandboxes", flush=True); report("ERROR", cancelled=True); sys.exit(2)
'''


class WebTestCase(unittest.TestCase):
    max_parallel = 2

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.reports = self.tmp / "reports"
        self.configs = self.tmp / "configs"
        (self.configs / "shared").mkdir(parents=True)
        (self.configs / "linux.toml").write_text(textwrap.dedent("""
            name = "Linux smoke"
            [sandbox]
            images = ["alpine:3", "debian:12"]
            [[checks]]
            name = "smoke"
            run = "true"
            [patch]
            kind = "os-packages"
        """))
        (self.configs / "broken.toml").write_text("[sandbox]\nimages = []\n")
        (self.configs / "shared" / "checks.toml").write_text('[[checks]]\nname = "x"\nrun = "true"\n')
        fake = self.tmp / "fake_patchlab.py"
        fake.write_text(FAKE_PATCHLAB)
        s = core_settings.Settings(reports_dir=str(self.reports), configs_dir=str(self.configs))
        s.web.max_parallel_runs = self.max_parallel
        runs = RunManager(self.reports.resolve(), self.configs.resolve(), self.max_parallel,
                          command=[sys.executable, str(fake)])
        self.httpd, self.app = server.make_server(s, "127.0.0.1", 0, token=TOKEN, runs=runs)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.app.runs.shutdown(wait_seconds=10)
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, path, method="GET", body=None, token=TOKEN, csrf=True, headers=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if csrf and method != "GET":
            req.add_header("X-PatchLabInternal-Request", "1")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json" else raw), r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, (json.loads(raw) if raw.startswith(b"{") else raw), e.headers

    def wait_finished(self, run_id, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, d, _ = self.call(f"/api/runs/{run_id}")
            if not d["active"]:
                return d
            time.sleep(0.2)
        self.fail("run did not finish")


class SecurityTest(WebTestCase):
    def test_token_required_and_exchanged_for_cookie(self):
        self.assertEqual(self.call("/api/runs", token=None)[0], 401)
        self.assertEqual(self.call("/api/runs", token="wrong")[0], 401)
        opener = urllib.request.build_opener(NoRedirect)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(f"{self.base}/?token={TOKEN}")
        self.assertEqual(cm.exception.code, 303)
        cookie = cm.exception.headers["Set-Cookie"]
        for part in ("HttpOnly", "SameSite=Strict", f"patchlab_internal_token={TOKEN}"):
            self.assertIn(part, cookie)
        status, _, _ = self.call("/api/runs", token=None, headers={"Cookie": f"patchlab_internal_token={TOKEN}"})
        self.assertEqual(status, 200)

    def test_host_header_and_csrf_header_enforced(self):
        self.assertEqual(self.call("/api/runs", headers={"Host": "attacker.example"})[0], 421)
        self.assertEqual(self.call("/api/runs", "POST", {"config": "linux.toml"}, csrf=False)[0], 403)

    def test_pages_have_strict_csp(self):
        status, _, headers = self.call("/", token=None)
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        for asset in ("app.js", "app.css", "icon.svg"):
            self.assertEqual(self.call(f"/static/{asset}", token=None)[0], 200)

    def test_path_traversal_is_refused(self):
        (self.reports / "20260926-100000-abcd").mkdir(parents=True)
        for path in ("/files/20260926-100000-abcd/..%2F..%2Fconfigs%2Flinux.toml", "/files/..%2Fsecret/x",
                     "/api/config?path=../../etc/passwd", "/api/runs/..", "/static/../server.py"):
            self.assertEqual(self.call(path)[0], 404, path)
        status, body, _ = self.call("/api/runs", "POST", {"config": "../outside.toml"})
        self.assertEqual(status, 400)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class DataTest(WebTestCase):
    def test_existing_reports_are_listed(self):
        d = self.reports / "20260101-120000-beef"
        d.mkdir(parents=True)
        (d / "report.json").write_text(json.dumps({"name": "old run", "verdict": "FAIL", "patch": {"label": "p"},
                                                   "targets": [{"image": "x", "verdict": "FAIL",
                                                                "findings": [{"severity": "fail"}]}]}))
        (d / "x").mkdir()
        (d / "x" / "patch.log").write_text("log text")
        _, data, _ = self.call("/api/runs")
        run = data["runs"][0]
        self.assertEqual((run["run_id"], run["verdict"], run["finding_counts"]), ("20260101-120000-beef", "FAIL", {"fail": 1}))
        _, detail, _ = self.call("/api/runs/20260101-120000-beef")
        self.assertIn("x/patch.log", detail["files"])
        status, body, headers = self.call("/files/20260101-120000-beef/x/patch.log")
        self.assertEqual((status, body), (200, b"log text"))
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))

    def test_configs_listing_skips_include_files_and_flags_invalid(self):
        _, data, _ = self.call("/api/configs")
        by_path = {c["path"]: c for c in data["configs"]}
        self.assertEqual(sorted(by_path), ["broken.toml", "linux.toml"])
        self.assertTrue(by_path["linux.toml"]["valid"])
        self.assertIn("os-packages", by_path["linux.toml"]["patch_kinds"])
        self.assertNotIn("windows-update", by_path["linux.toml"]["patch_kinds"])
        self.assertFalse(by_path["broken.toml"]["valid"])
        _, detail, _ = self.call("/api/config?path=linux.toml")
        self.assertIn('name = "Linux smoke"', detail["text"])

    def test_environment_and_session(self):
        os.environ["PATCHLAB_INTERNAL_GUEST_PASSWORD"] = "Very-Secret-Value"
        try:
            _, env, _ = self.call("/api/environment")
        finally:
            del os.environ["PATCHLAB_INTERNAL_GUEST_PASSWORD"]
        self.assertIn("docker", [t["name"] for t in env["tools"]])
        self.assertTrue(env["secrets"]["PATCHLAB_INTERNAL_GUEST_PASSWORD"])        # presence only...
        self.assertNotIn("Very-Secret-Value", json.dumps(env))              # ...never the value
        _, session, _ = self.call("/api/session")
        self.assertEqual(Path(session["reports_dir"]), self.reports.resolve())


class RunTest(WebTestCase):
    max_parallel = 1

    def test_run_lifecycle_and_console(self):
        status, started, _ = self.call("/api/runs", "POST", {"config": "linux.toml", "images": ["debian:12", "nope"],
                                                               "guest_password": "s3cret!"})
        self.assertEqual(status, 201)
        rid = started["run_id"]
        detail = self.wait_finished(rid)
        self.assertEqual((detail["verdict"], detail["job"]["status"], detail["job"]["exit_code"]), ("PASS", "finished", 0))
        argv = detail["report"]["patch"]["label"]
        self.assertIn("--image debian:12", argv)
        self.assertNotIn("nope", argv)                      # only images from the config are passed on
        self.assertTrue(detail["report"]["guest_password_seen"])
        _, console, _ = self.call(f"/api/runs/{rid}/console?offset=0")
        self.assertIn("step 4", console["text"])
        self.assertNotIn("s3cret", console["text"])
        _, tail, _ = self.call(f"/api/runs/{rid}/console?offset={console['offset']}")
        self.assertEqual(tail["text"], "")

    def test_cancel_busy_and_delete(self):
        os.environ["FAKE_DELAY"] = "2"
        try:
            _, started, _ = self.call("/api/runs", "POST", {"config": "linux.toml"})
            rid = started["run_id"]
            time.sleep(0.5)
            self.assertEqual(self.call("/api/runs", "POST", {"config": "linux.toml"})[0], 409)   # max_parallel = 1
            self.assertEqual(self.call(f"/api/runs/{rid}", "DELETE")[0], 409)                  # still running
            self.assertEqual(self.call(f"/api/runs/{rid}/cancel", "POST", {})[0], 200)
            detail = self.wait_finished(rid)
        finally:
            os.environ.pop("FAKE_DELAY", None)
        self.assertEqual(detail["job"]["status"], "cancelled")
        self.assertTrue(detail["report"]["cancelled"])
        _, console, _ = self.call(f"/api/runs/{rid}/console?offset=0")
        self.assertIn("tearing down sandboxes", console["text"])
        self.assertEqual(self.call(f"/api/runs/{rid}", "DELETE")[0], 200)
        self.assertFalse((self.reports / rid).exists())

    def test_cleanup_refused_and_cancel_sent_once_while_running(self):
        os.environ["FAKE_DELAY"] = "2"
        try:
            _, started, _ = self.call("/api/runs", "POST", {"config": "linux.toml"})
            rid = started["run_id"]
            time.sleep(0.5)
            self.assertEqual(self.call("/api/gc", "POST", {"config": "linux.toml"})[0], 409)
            for _ in range(3):        # repeated clicks must not re-interrupt the clean-up
                self.assertEqual(self.call(f"/api/runs/{rid}/cancel", "POST", {})[0], 200)
            self.wait_finished(rid)
        finally:
            os.environ.pop("FAKE_DELAY", None)
        _, console, _ = self.call(f"/api/runs/{rid}/console?offset=0")
        self.assertEqual(console["text"].count("interrupted"), 1)
        self.assertEqual(self.call("/api/gc", "POST", {"config": "linux.toml"})[0], 200)

    def test_invalid_requests(self):
        self.assertEqual(self.call("/api/runs", "POST", {"config": "broken.toml"})[0], 400)
        self.assertEqual(self.call("/api/runs", "POST", {"config": "linux.toml", "patch": "windows-update"})[0], 400)
        self.assertEqual(self.call("/api/runs", "POST", {"config": "missing.toml"})[0], 400)
        status, _, _ = self.call("/api/gc", "POST", {"config": "linux.toml"})
        self.assertEqual(status, 200)


class ServeTest(unittest.TestCase):
    def test_package_entry_point_passes_every_option(self):
        # The CLI calls patchlab_internal_web.serve, a thin wrapper over server.serve.
        import inspect
        import patchlab_internal_web
        self.assertEqual(list(inspect.signature(patchlab_internal_web.serve).parameters)[1:],
                         list(inspect.signature(server.serve).parameters)[1:])

    def test_refuses_public_address_without_opt_in(self):
        s = core_settings.Settings(reports_dir=tempfile.mkdtemp())
        self.assertEqual(server.serve(s, host="0.0.0.0", port=0), 64)


ESTATE = """
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
"""


def write_estate_state(configs: Path) -> Path:
    """A small estate: one healthy package, one READY proposal with a hostile title, one digest."""
    (configs / "estate.toml").write_text(ESTATE)
    st = configs / "work" / "state"
    health = st / "app-backend" / "health" / "20260101-000000-health-aaaa"
    health.mkdir(parents=True)
    (health / "summary.json").write_text(json.dumps({"status": "healthy", "passing_tests": 12, "commit": "c" * 40}))
    (st / "app-backend" / "scan.json").write_text(json.dumps({"commit": "c" * 40, "scan": {"vulnerable": [
        {"name": "nodemailer", "production": True}]}}))
    run = st / "app-backend" / "proposals" / "nodemailer" / "20260101-000100-proposal-bbbb"
    run.mkdir(parents=True)
    (run / "decision.json").write_text(json.dumps({"verdict": "READY", "summary": "safe", "labels": ["security"],
        "gate": [{"name": "checks pass", "ok": True, "detail": "12 of 12", "details": [], "kind": "blocker"}]}))
    (run / "proposal.json").write_text(json.dumps({"commit": "c" * 40,
                                                   "plan": {"title": "<img src=x onerror=alert(1)> bump"}}))
    (run / "pr.md").write_text("## Why\nnodemailer advisory\n")
    (run / "change.patch").write_text("--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-\"6.9.0\"\n+\"9.1.1\"\n")
    (st / "digest").mkdir()
    (st / "digest" / "2026-01-01.md").write_text("# Estate digest, 2026-01-01\n")
    (st / "outside.json").write_text("{}")
    return run


class EstateTest(WebTestCase):
    def setUp(self):
        super().setUp()
        self.run = write_estate_state(self.configs)
        # The front end found estate.toml in the configs folder at start-up.
        self.app.estate_manifest = self.configs / "estate.toml"

    def test_overview_lists_packages_and_decisions(self):
        status, e, _ = self.call("/api/estate")
        self.assertEqual(status, 200)
        self.assertEqual([p["id"] for p in e["packages"]], ["app/backend"])
        self.assertEqual(e["packages"][0]["health"], "healthy")
        self.assertEqual(e["packages"][0]["advisories_production"], 1)
        [d] = e["decisions"]
        self.assertEqual((d["verdict"], d["kind"], d["has_patch"]), ("READY", "dependency", True))
        self.assertEqual(e["digests"], ["2026-01-01"])
        self.assertEqual(e["publish"], "report-only")

    def test_decision_and_digest(self):
        _, e, _ = self.call("/api/estate")
        status, x, _ = self.call(f"/api/estate/decision?id={urllib.parse.quote(e['decisions'][0]['id'])}")
        self.assertEqual(status, 200)
        self.assertIn("+\"9.1.1\"", x["patch"])
        self.assertIn("nodemailer advisory", x["pr"])
        status, x, _ = self.call("/api/estate/digest?date=2026-01-01")
        self.assertEqual((status, x["text"].splitlines()[0]), (200, "# Estate digest, 2026-01-01"))

    def test_reads_stay_inside_the_state_folder(self):
        for bad in ("../estate.toml", "../../configs", "/etc", "outside.json", "app-backend"):
            self.assertEqual(self.call(f"/api/estate/decision?id={urllib.parse.quote(bad)}")[0], 404, bad)
        for bad in ("../../estate", "..%2F..%2Festate", "2026-01-02"):
            self.assertEqual(self.call(f"/api/estate/digest?date={bad}")[0], 404, bad)
        self.assertEqual(self.call("/api/estate", token=None)[0], 401)

    def test_no_manifest_is_explained(self):
        self.app.estate_manifest = None
        status, body, _ = self.call("/api/estate")
        self.assertEqual(status, 404)
        self.assertIn("--estate", body["error"])

    def test_manifest_lookup_order(self):
        from patchlab_internal_web import estate_view
        self.assertEqual(estate_view.find_manifest(None, self.configs), self.configs / "estate.toml")
        self.assertEqual(estate_view.find_manifest(str(self.tmp / "x.toml"), self.configs), (self.tmp / "x.toml").resolve())
        self.assertIsNone(estate_view.find_manifest(None, self.tmp))


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
CHROMIUM = os.environ.get("PATCHLAB_INTERNAL_TEST_CHROMIUM")   # default: Playwright's own Chromium


@unittest.skipUnless(sync_playwright, "playwright not installed")
class BrowserTest(WebTestCase):
    def test_pages_render_without_errors(self):
        d = self.reports / "20260101-120000-beef"
        d.mkdir(parents=True)
        (d / "report.json").write_text(json.dumps({"name": "Nightly", "verdict": "WARN", "patch": {"label": "p"},
                                                   "targets": [{"image": "alpine:3", "verdict": "WARN", "stages": [],
                                                                "checks": [], "findings": [{"severity": "warn", "area": "checks",
                                                                                            "message": "<img src=x onerror=alert(1)>", "details": []}]}]}))
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(executable_path=CHROMIUM, args=["--no-sandbox"])
            except Exception as e:  # browsers not downloaded (`python -m playwright install chromium`)
                self.skipTest(f"cannot start Chromium: {e}")
            page = browser.new_page(viewport={"width": 390, "height": 800})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("dialog", lambda dlg: (errors.append("dialog opened"), dlg.dismiss()))
            page.goto(f"{self.base}/?token={TOKEN}#/runs")
            page.wait_for_selector("tr.link")
            for route, sel in (("/runs/20260101-120000-beef", ".finding"), ("/new", "form"), ("/configs", "tr.link"),
                               ("/environment", "table")):
                page.goto(f"{self.base}/#{route}")
                page.wait_for_selector(sel)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390, route)
            page.goto(f"{self.base}/#/runs/20260101-120000-beef")
            page.wait_for_selector(".finding")
            self.assertIn("<img src=x onerror=alert(1)>", page.inner_text(".finding"))   # shown as text, not HTML
            write_estate_state(self.configs)
            self.app.estate_manifest = self.configs / "estate.toml"
            page.goto(f"{self.base}/#/estate")
            page.wait_for_selector("tr.link")
            self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390, "estate")
            page.click("tr.link")
            page.wait_for_selector("pre.diff .add")
            self.assertIn("<img src=x onerror=alert(1)>", page.inner_text("h1"))
            page.goto(f"{self.base}/#/estate/digest?date=2026-01-01")
            page.wait_for_selector("pre.prose")
            browser.close()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
