"""Estate layer: manifest, npm planning, lockfile analysis, the triage gate, health and digest."""

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from patchlab_internal.config import ConfigError
from patchlab_internal.estate import (advisories, digest, fixers, gitops, manifest, npm, pipeline, repair,
                                      state, triage)
from patchlab_internal.linux import sandbox_env
from patchlab_internal.estate import bridge

ROOT = Path(__file__).resolve().parent.parent

MINIMAL = """
[estate]
workdir = "work"

[[mirror]]
name = "core"
url = "https://github.com/Org/core"

[[repo]]
name = "app"
url = "https://github.com/Org/app"

  [[repo.package]]
  path = "backend"
  ecosystem = "npm"
  image = "node:20-bookworm"
  install = ["npm ci"]
  mirrors = ["core"]
  env = { NODE_ENV = "test" }

    [[repo.package.sidecars]]
    name = "postgres"
    image = "postgres:16"
    health = "pg_isready"

    [[repo.package.checks]]
    name = "tests"
    run = "npm test"

  [[repo.package]]
  path = "sdk-ios"
  ecosystem = "swift"
  unsupported = "macOS only"
"""


def write_manifest(text: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "estate.toml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


class ManifestTests(unittest.TestCase):
    def setUp(self):
        for k in ("PATCHLAB_INTERNAL_ESTATE_WORKDIR", "PATCHLAB_INTERNAL_CA_BUNDLE"):
            os.environ.pop(k, None)

    def test_loads_packages_sidecars_and_mirrors(self):
        est = manifest.load(write_manifest(MINIMAL))
        self.assertEqual([p.id for p in est.packages()], ["app/backend", "app/sdk-ios"])
        be = est.find("app/backend")
        self.assertEqual(be.sidecars[0].name, "postgres")
        self.assertEqual(be.check_network, "isolated", "checks are isolated unless a package opts out")
        self.assertEqual(est.find("app/sdk-ios").unsupported, "macOS only")
        self.assertEqual(est.workdir, est.path.parent / "work")

    def test_the_committed_manifest_is_valid(self):
        est = manifest.load(ROOT / "estate.toml")
        self.assertEqual({r.name for r in est.repos},
                         {"subsovereign", "latticeiq", "streamly-security-core", "caer", "sentinel", "sentry"})
        for pkg in est.packages():
            if not pkg.unsupported:
                self.assertTrue(pkg.checks, pkg.id)

    def test_real_credentials_are_refused(self):
        for value in ("ghp_" + "a" * 36, "github_pat_" + "B" * 40, "AKIA" + "A" * 16,
                      "-----BEGIN RSA PRIVATE KEY-----", "sk-ant-" + "x" * 30):
            with self.subTest(value=value[:12]):
                text = MINIMAL.replace('NODE_ENV = "test"', f'TOKEN = "{value}"')
                with self.assertRaisesRegex(ConfigError, "look like real credentials"):
                    manifest.load(write_manifest(text))

    def test_throwaway_values_are_allowed(self):
        text = MINIMAL.replace('NODE_ENV = "test"', 'ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"')
        manifest.load(write_manifest(text))

    def test_unknown_mirror_and_bad_paths_are_refused(self):
        with self.assertRaisesRegex(ConfigError, "unknown mirror"):
            manifest.load(write_manifest(MINIMAL.replace('mirrors = ["core"]', 'mirrors = ["nope"]')))
        with self.assertRaisesRegex(ConfigError, "inside the repository"):
            manifest.load(write_manifest(MINIMAL.replace('path = "backend"', 'path = "../x"')))
        with self.assertRaisesRegex(ConfigError, "image is required"):
            manifest.load(write_manifest(MINIMAL.replace('image = "node:20-bookworm"\n', '')))

    def test_mirror_rewrites_cover_the_spellings_npm_uses(self):
        urls = manifest.MirrorSpec("core", "https://github.com/Org/core").rewrite_urls()
        for form in ("ssh://git@github.com/Org/core.git", "https://github.com/Org/core.git",
                     "git@github.com:Org/core.git"):
            self.assertIn(form, urls)

    def test_mirrors_become_git_insteadof_rules_without_credentials(self):
        est = manifest.load(write_manifest(MINIMAL))
        pkg = est.find("app/backend")
        (est.mirrors_dir / "core.git").mkdir(parents=True)
        env = sandbox_env(bridge.sandbox_for(est, pkg))
        keys = [env[f"GIT_CONFIG_KEY_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))]
        values = [env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))]
        self.assertTrue(all(k.startswith("url.file:///opt/patchlab/mirrors/") for k in keys[:-1]))
        self.assertIn("ssh://git@github.com/Org/core.git", values)
        self.assertFalse(any("x-access-token" in v or "github_pat_" in v or "ghp_" in v for v in values),
                         "no credential in any rewrite")


AUDIT = {
    "vulnerabilities": {
        "nodemailer": {"name": "nodemailer", "severity": "high", "isDirect": True,
                       "via": [{"source": 1, "title": "Email to an unintended domain", "severity": "moderate",
                                "url": "https://github.com/advisories/GHSA-1", "range": "<7.0.7"},
                               {"source": 2, "title": "addressparser DoS", "severity": "high",
                                "url": "https://github.com/advisories/GHSA-2", "range": "<9.1.0"}],
                       "fixAvailable": {"name": "nodemailer", "version": "10.0.12", "isSemVerMajor": True}},
        "qs": {"name": "qs", "severity": "moderate", "isDirect": False,
               "via": [{"source": 3, "title": "qs DoS", "severity": "moderate", "range": "<6.16.0"}],
               "fixAvailable": True},
        "express": {"name": "express", "severity": "moderate", "isDirect": True, "via": ["qs"],
                    "fixAvailable": True},
        "@vitest/mocker": {"name": "@vitest/mocker", "severity": "moderate", "isDirect": False,
                           "via": [{"source": 4, "title": "path traversal", "severity": "moderate", "range": ">=2"}],
                           "fixAvailable": {"name": "vitest", "version": "4.1.11", "isSemVerMajor": True}},
        "ip": {"name": "ip", "severity": "high", "isDirect": False,
               "via": [{"source": 5, "title": "SSRF", "severity": "high", "range": "*"}], "fixAvailable": False},
        "deep": {"name": "deep", "severity": "low", "isDirect": False,
                 "via": [{"source": 6, "title": "x", "severity": "low", "range": "*"}],
                 "fixAvailable": {"name": "parent-not-direct", "version": "2.0.0", "isSemVerMajor": True}},
    },
    "metadata": {"vulnerabilities": {"high": 2, "moderate": 3, "low": 1}},
}


class NpmPlanTests(unittest.TestCase):
    def scan(self):
        return npm.parse_audit(json.dumps(AUDIT), production={"nodemailer", "qs", "express", "ip"})

    def test_parse(self):
        s = self.scan()
        nm = s.by_name()["nodemailer"]
        self.assertEqual((nm.fix, nm.fix_name, nm.fix_version), ("major", "nodemailer", "10.0.12"))
        self.assertTrue(nm.production)
        self.assertEqual(s.by_name()["express"].via, ["qs"])
        self.assertEqual(len(s.advisory_ids()), 6)

    def test_failed_audit_is_an_error_not_a_clean_bill(self):
        s = npm.parse_audit('{"error": {"summary": "ENOLOCK"}}')
        self.assertIsNotNone(s.error)
        self.assertEqual(npm.parse_audit("not json").vulnerable, [])
        self.assertIsNotNone(npm.parse_audit("not json").error)

    def test_plan_groups_majors_in_range_and_manual(self):
        plans, blocked = npm.plan(self.scan(), {"nodemailer", "express", "vitest"})
        keys = [p.key for p in plans]
        self.assertEqual(keys[0], "nodemailer", "production + high first")
        self.assertIn("in-range-fixes", keys)
        self.assertIn("vitest", keys)
        ir = next(p for p in plans if p.key == "in-range-fixes")
        self.assertEqual(sorted(ir.covers), ["express", "qs"])
        reasons = {b.name: b.reason for b in blocked}
        self.assertIn("no fixed version", reasons["ip"])
        self.assertIn("not a direct dependency", reasons["deep"])

    def test_ignore_list(self):
        plans, blocked = npm.plan(self.scan(), {"nodemailer", "express", "vitest"}, {"vitest": "v4 needs node 22"})
        self.assertNotIn("vitest", [p.key for p in plans])
        self.assertIn("v4 needs node 22", " ".join(b.reason for b in blocked))


class ManifestEditTests(unittest.TestCase):
    ORIGINAL = ('{\n  "description": "A \\u2014 B",\n  "dependencies": {\n    "nodemailer": "^6.10.1",\n'
                '    "pg": "^8.11.3"\n  },\n  "devDependencies": {\n    "vitest": "^3.2.6"\n  }\n}\n')

    def test_only_the_spec_changes(self):
        rewritten = json.dumps({"description": "A \u2014 B", "dependencies": {"nodemailer": "^9.1.1", "pg": "^8.11.3"},
                                "devDependencies": {"vitest": "^3.2.6"}}, indent=2, ensure_ascii=False)
        out = npm.minimal_manifest_edit(self.ORIGINAL, rewritten)
        self.assertEqual(out, self.ORIGINAL.replace('"^6.10.1"', '"^9.1.1"'))

    def test_added_or_removed_dependencies_are_refused(self):
        added = json.dumps({"description": "x", "dependencies": {"nodemailer": "^6.10.1", "pg": "^8.11.3", "new": "1"},
                            "devDependencies": {"vitest": "^3.2.6"}})
        with self.assertRaisesRegex(ValueError, "added new"):
            npm.minimal_manifest_edit(self.ORIGINAL, added)
        removed = json.dumps({"dependencies": {"nodemailer": "^6.10.1"}, "devDependencies": {"vitest": "^3.2.6"}})
        with self.assertRaisesRegex(ValueError, "removed pg"):
            npm.minimal_manifest_edit(self.ORIGINAL, removed)


def lock(pkgs):
    return {"lockfileVersion": 3, "packages": {"": {"name": "x"}, **pkgs}}


def entry(v, resolved=None, integrity="sha512-x", **kw):
    return {"version": v, "resolved": resolved or f"https://registry.npmjs.org/p/-/p-{v}.tgz",
            "integrity": integrity, **kw}


class LockDiffTests(unittest.TestCase):
    def test_upgrade_add_remove(self):
        d = npm.lock_diff(lock({"node_modules/a": entry("1.0.0"), "node_modules/b": entry("1.0.0")}),
                          lock({"node_modules/a": entry("2.0.0"), "node_modules/c": entry("1.0.0")}))
        self.assertEqual(d.upgraded, [("a", "1.0.0", "2.0.0")])
        self.assertEqual(d.added, [("c", "1.0.0")])
        self.assertEqual(d.removed, [("b", "1.0.0")])
        self.assertEqual(d.new_names, ["c"])

    def test_supply_chain_signals(self):
        d = npm.lock_diff(
            lock({"node_modules/a": entry("1.0.0")}),
            lock({"node_modules/a": entry("1.0.1", hasInstallScript=True),
                  "node_modules/evil": entry("1.0.0", resolved="https://evil.example/evil.tgz"),
                  "node_modules/core": entry("1.0.0", resolved="git+ssh://git@github.com/Org/core.git#abc"),
                  "node_modules/nohash": entry("1.0.0", integrity=None)}),
            allowed_git=("git+ssh://git@github.com/Org/core",))
        self.assertEqual(d.new_install_scripts, ["a@1.0.1"])
        self.assertEqual(d.unusual_sources, ["evil@1.0.0 from https://evil.example/evil.tgz"])
        self.assertEqual(d.missing_integrity, ["nohash@1.0.0"])

    def test_hoisting_is_not_add_and_remove(self):
        d = npm.lock_diff(lock({"node_modules/x/node_modules/a": entry("1.0.0")}),
                          lock({"node_modules/a": entry("1.0.0")}))
        self.assertEqual((d.added, d.removed), ([], []))


def check(name, transition, cases_before=None, cases_after=None, **kw):
    return {"name": name, "transition": transition,
            "before": {"passed": transition in ("ok", "regressed"), "cases": cases_before or {}, "note": None},
            "after": {"passed": transition in ("ok", "fixed"), "cases": cases_after or {}, "note": None},
            "case_regressions": [], "case_still_failing": [], "case_now_skipped": [], **kw}


def report(checks, verdict="PASS", findings=None):
    rb = [{"severity": "info", "area": "rollback", "message": "rollback verified", "details": []}]
    return {"verdict": verdict, "targets": [{"verdict": verdict, "checks": checks,
                                              "findings": rb + (findings or [])}]}


GOOD_PROPOSAL = {"plan": {"kind": "major", "dependency": "nodemailer"}, "audit_after": {"error": None},
                 "fixed_advisories": ["1", "2"], "remaining_advisories": [], "introduced_advisories": [],
                 "unexpected_files": [], "lock_diff": {}}


class GateTests(unittest.TestCase):
    def test_ready_needs_every_item_green(self):
        d = triage.decide(report([check("tests", "ok")]), GOOD_PROPOSAL)
        self.assertEqual(d.verdict, triage.READY, d.summary)
        self.assertIn("breaking-risk", d.labels)

    def test_regression_blocks(self):
        c = check("tests", "ok", case_regressions=["mail.test > sends"])
        d = triage.decide(report([c], "FAIL"), GOOD_PROPOSAL)
        self.assertEqual(d.verdict, triage.BLOCKED)
        self.assertIn("tests: mail.test > sends", next(g for g in d.gate if g.name == "no regressions").details)

    def test_pre_existing_failures_do_not_block_but_are_noted(self):
        c = check("tests", "still-failing", case_still_failing=["cors > preflight"])
        d = triage.decide(report([c], "WARN"), GOOD_PROPOSAL)
        self.assertEqual(d.verdict, triage.READY)
        self.assertTrue(any("cors > preflight" in n for n in d.notes))

    def test_missing_rollback_blocks(self):
        rep = report([check("tests", "ok")])
        rep["targets"][0]["findings"] = []
        self.assertEqual(triage.decide(rep, GOOD_PROPOSAL).verdict, triage.BLOCKED)

    def test_skipped_or_unparsed_tests_block(self):
        c = check("tests", "ok", case_now_skipped=["a > b"])
        self.assertEqual(triage.decide(report([c]), GOOD_PROPOSAL).verdict, triage.BLOCKED)
        c = check("tests", "ok")
        c["after"]["note"] = "JUnit report was not produced"
        self.assertEqual(triage.decide(report([c]), GOOD_PROPOSAL).verdict, triage.BLOCKED)

    def test_advisory_not_fixed_or_introduced_blocks(self):
        for change in ({"remaining_advisories": ["2"]}, {"introduced_advisories": ["9"]},
                       {"audit_after": None}, {"unexpected_files": ["src/x.ts"]}):
            with self.subTest(change=change):
                d = triage.decide(report([check("tests", "ok")]), {**GOOD_PROPOSAL, **change})
                self.assertEqual(d.verdict, triage.BLOCKED)

    def test_partial_in_range_fix_needs_review(self):
        partial = dict(GOOD_PROPOSAL, partial=True, deferred_advisories=["GHSA-rr"])
        d = triage.decide(report([check("tests", "ok")]), partial)
        self.assertEqual(d.verdict, triage.REVIEW)
        nothing = dict(partial, fixed_advisories=[])
        self.assertEqual(triage.decide(report([check("tests", "ok")]), nothing).verdict, triage.BLOCKED)

    def test_supply_chain_flags_need_review(self):
        prop = {**GOOD_PROPOSAL, "lock_diff": {"new_install_scripts": ["x@1"], "new_packages": ["x"]}}
        self.assertEqual(triage.decide(report([check("tests", "ok")]), prop).verdict, triage.REVIEW)

    def test_error_and_missing_report_are_inconclusive(self):
        self.assertEqual(triage.decide(None, GOOD_PROPOSAL).verdict, triage.INCONCLUSIVE)
        rep = report([], "ERROR", [{"severity": "error", "area": "sandbox", "message": "boom", "details": []}])
        self.assertEqual(triage.decide(rep, GOOD_PROPOSAL).verdict, triage.INCONCLUSIVE)

    def test_failures_that_do_not_reproduce_are_flaky(self):
        first = report([check("tests", "ok", case_regressions=["a"])], "FAIL")
        second = report([check("tests", "ok")])
        self.assertEqual(triage.decide(first, GOOD_PROPOSAL, confirm=second).verdict, triage.INCONCLUSIVE)
        again = report([check("tests", "ok", case_regressions=["a"])], "FAIL")
        self.assertEqual(triage.decide(first, GOOD_PROPOSAL, confirm=again).verdict, triage.BLOCKED)


class AdvisoryParserTests(unittest.TestCase):
    def test_pip_audit(self):
        out = json.dumps({"dependencies": [
            {"name": "jinja2", "version": "3.1.2", "vulns": [
                {"id": "GHSA-h5c8-rqwp-cp95", "fix_versions": ["3.1.3"], "description": "XSS"},
                {"id": "PYSEC-2024-1", "fix_versions": ["3.1.10", "3.1.4"], "description": "more"}]},
            {"name": "fastapi", "version": "0.139.0", "vulns": []}], "fixes": []})
        scan = advisories.parse_pip_audit(out)
        self.assertIsNone(scan.error)
        self.assertEqual([v.name for v in scan.vulnerable], ["jinja2"])
        v = scan.vulnerable[0]
        self.assertEqual((v.fix_version, v.severity), ("3.1.4", "unknown"),
                         "no severity is invented when the tool gives none")
        self.assertEqual(scan.advisory_ids(), {"GHSA-h5c8-rqwp-cp95", "PYSEC-2024-1"})
        self.assertEqual(scan.counts["audited"], 2, "a clean result says how much was audited")

    def test_garbage_is_an_error_not_a_clean_bill(self):
        for parse in (advisories.parse_pip_audit, advisories.parse_govulncheck,
                      advisories.parse_cargo_audit):
            self.assertIsNotNone(parse("Traceback (most recent call last)").error, parse.__name__)

    def test_govulncheck_counts_only_called_code(self):
        stream = "\n".join(json.dumps(o, indent=2) for o in [
            {"config": {"scanner_name": "govulncheck"}},
            {"osv": {"id": "GO-2025-0001", "summary": "called"}},
            {"osv": {"id": "GO-2025-0002", "summary": "imported only"}},
            {"finding": {"osv": "GO-2025-0001", "fixed_version": "v0.9.0", "trace": [
                {"module": "golang.org/x/net", "version": "v0.8.0", "package": "golang.org/x/net/html",
                 "function": "Parse"}]}},
            {"finding": {"osv": "GO-2025-0002", "trace": [
                {"module": "golang.org/x/text", "version": "v0.3.0", "package": "golang.org/x/text/unicode"}]}},
        ])
        scan = advisories.parse_govulncheck(stream)
        self.assertIsNone(scan.error)
        self.assertEqual([v.name for v in scan.vulnerable], ["golang.org/x/net"])
        self.assertEqual(scan.vulnerable[0].fix_version, "v0.9.0")
        self.assertEqual(advisories.parse_govulncheck("").vulnerable, [])

    def test_cargo_audit_vulnerabilities_and_warnings(self):
        out = json.dumps({
            "vulnerabilities": {"found": True, "count": 1, "list": [
                {"advisory": {"id": "RUSTSEC-2024-0001", "title": "overflow"},
                 "versions": {"patched": [">=1.2.3"]}, "package": {"name": "foo", "version": "1.2.0"}}]},
            "warnings": {"unmaintained": [
                {"kind": "unmaintained", "advisory": {"id": "RUSTSEC-2024-0002", "title": "gone"},
                 "package": {"name": "bar", "version": "0.1.0"}}]}})
        scan = advisories.parse_cargo_audit(out)
        by = scan.by_name()
        self.assertEqual((by["foo"].severity, by["foo"].fix_version), ("unknown", ">=1.2.3"))
        self.assertEqual(by["bar"].severity, "info")
        self.assertIn("unmaintained", by["bar"].advisories[0].title)


class FixerTests(unittest.TestCase):
    def test_lowest_fix_clears_every_advisory(self):
        self.assertEqual(advisories.lowest_fix("1.0", [["1.2", "2.0"], ["1.1", "1.10"]]), "1.2")
        self.assertIsNone(advisories.lowest_fix("1.0", [["1.2"], []]), "an advisory with no fix blocks")
        self.assertTrue(advisories.is_major("49.0.0", "50.0.0"))
        self.assertFalse(advisories.is_major("1.2.0", "1.9.0"))
        self.assertTrue(advisories.is_major("0.3.1", "0.4.0"), "0.x minors are breaking")

    def test_repin_changes_only_exact_pins_of_that_project(self):
        text = "# pinned\nCryptography==49.0.0  # why\ncryptography-extra==1.0\nfoo[bar]==1 ; python_version<'4'\n"
        new, n = fixers.repin(text, "cryptography", "50.0.0")
        self.assertEqual(n, 1)
        self.assertEqual(new, text.replace("Cryptography==49.0.0", "Cryptography==50.0.0"))
        new, n = fixers.repin(text, "Foo", "2")
        self.assertIn("foo[bar]==2 ; python_version<'4'", new)

    def test_tree_diff_flags_new_and_unusual_sources(self):
        d = fixers.tree_diff({"a": "1", "b": "1"}, {"a": "2", "c": "1", "d": "@ git+https://x/y"})
        self.assertEqual(d["upgraded"], [{"name": "a", "from": "1", "to": "2"}])
        self.assertEqual(d["new_packages"], ["c", "d"])
        self.assertEqual(d["removed"], [{"name": "b", "version": "1"}])
        self.assertEqual(d["unusual_sources"], ["d git+https://x/y"])

    def test_non_npm_scans_become_upgrade_plans(self):
        scan = advisories.parse_pip_audit(json.dumps({"dependencies": [
            {"name": "cryptography", "version": "49.0.0", "vulns": [{"id": "PYSEC-1", "fix_versions": ["50.0.0"]}]},
            {"name": "nofix", "version": "1", "vulns": [{"id": "PYSEC-2", "fix_versions": []}]}]}))
        plans, blocked = pipeline.upgrade_plans(scan, {})
        self.assertEqual([(p.kind, p.key, p.suggested_version) for p in plans],
                         [("upgrade", "cryptography", "50.0.0")])
        self.assertEqual([b.name for b in blocked], ["nofix"])


class RepairTests(unittest.TestCase):
    def test_test_paths(self):
        for p in ("backend/src/__tests__/a.test.ts", "tests/test_x.py", "pkg/x_test.go", "vitest.config.ts",
                  "apps/proxy/tests/conftest.py", "web/login.spec.tsx"):
            self.assertTrue(repair.TEST_PATH.search(p), p)
        for p in ("backend/src/services/allowed-origins.ts", "src/testing_utils.py", "README.md"):
            self.assertFalse(repair.TEST_PATH.search(p), p)

    def _report(self, fixes, regress=()):
        c = {"name": "unit", "transition": "ok", "case_fixes": list(fixes), "case_regressions": list(regress),
             "before": {"passed": False}, "after": {"passed": True}}
        return report([c])

    def test_gate_needs_every_target_fixed(self):
        prop = {"kind": "repair", "targets": ["unit: a", "unit: b"], "test_files_changed": [],
                "dependency_files_changed": []}
        rep = self._report(["a", "b"])
        self.assertEqual(triage.decide(rep, prop).verdict, triage.READY)
        rep2 = self._report(["a"])
        self.assertEqual(triage.decide(rep2, prop).verdict, triage.BLOCKED)
        touched = dict(prop, test_files_changed=["src/__tests__/a.test.ts"])
        self.assertEqual(triage.decide(rep, touched).verdict, triage.REVIEW)

    def test_blocked_upgrade_goes_to_repair_only_when_regressions_are_all_that_block(self):
        broken = report([check("tests", "ok", case_regressions=["a"])], "FAIL")
        d = triage.decide(broken, GOOD_PROPOSAL, confirm=broken)
        self.assertTrue(pipeline.only_regressions_block(d))
        still_vulnerable = dict(GOOD_PROPOSAL, remaining_advisories=["1"])
        self.assertFalse(pipeline.only_regressions_block(triage.decide(broken, still_vulnerable, confirm=broken)))
        self.assertFalse(pipeline.only_regressions_block(triage.decide(report([check("tests", "ok")]),
                                                                      GOOD_PROPOSAL)))

    def test_an_adapted_upgrade_is_judged_on_the_agents_own_edits(self):
        adapted = dict(GOOD_PROPOSAL, repaired_by_agent=True, test_files_changed=[],
                       dependency_files_changed=[])
        self.assertEqual(triage.decide(report([check("tests", "ok")]), adapted).verdict, triage.READY)
        touched = dict(adapted, test_files_changed=["src/__tests__/mail.test.ts"])
        self.assertEqual(triage.decide(report([check("tests", "ok")]), touched).verdict, triage.REVIEW)
        relocked = dict(adapted, dependency_files_changed=["backend/package-lock.json"])
        self.assertEqual(triage.decide(report([check("tests", "ok")]), relocked).verdict, triage.REVIEW)

    def test_repair_agent_config_names_credentials_only(self):
        base = MINIMAL + '\n[repair]\nimage = "node:22"\ncommand = "claude -p x"\nenv = ["ANTHROPIC_API_KEY"]\n'
        est = manifest.load(write_manifest(base))
        self.assertEqual(est.repair.env, ["ANTHROPIC_API_KEY"])
        with self.assertRaises(ConfigError):
            manifest.load(write_manifest(base.replace('["ANTHROPIC_API_KEY"]', '["ANTHROPIC_API_KEY=sk-x"]')))
        with self.assertRaises(ConfigError):
            manifest.load(write_manifest(base.replace("claude -p x", "ANTHROPIC_API_KEY=sk-ant-" + "a" * 30 + " claude")))


class SyncTests(unittest.TestCase):
    def test_one_unreachable_repo_does_not_stop_the_others(self):
        os.environ.pop("PATCHLAB_INTERNAL_ESTATE_WORKDIR", None)
        est = manifest.load(write_manifest(MINIMAL + '\n[[repo]]\nname = "other"\nurl = "https://github.com/Org/other"\n'))
        calls = []

        def fake_sync(url, dest):
            calls.append(url)
            if url.endswith("/app"):
                raise gitops.GitError("could not read from remote")

        real_sync, real_head = gitops.sync_mirror, gitops.head
        gitops.sync_mirror, gitops.head = fake_sync, lambda m, b: "f" * 40
        try:
            heads, errors = pipeline.sync(est)
        finally:
            gitops.sync_mirror, gitops.head = real_sync, real_head
        self.assertEqual(heads, {"other": "f" * 40})
        self.assertEqual(list(errors), ["app"])
        self.assertIn("https://github.com/Org/other", calls)

    def test_a_limited_sync_skips_other_repos_and_their_mirrors(self):
        os.environ.pop("PATCHLAB_INTERNAL_ESTATE_WORKDIR", None)
        est = manifest.load(write_manifest(MINIMAL + '\n[[repo]]\nname = "other"\nurl = "https://github.com/Org/other"\n'))
        calls = []
        real_sync, real_head = gitops.sync_mirror, gitops.head
        gitops.sync_mirror, gitops.head = (lambda url, dest: calls.append(url)), (lambda m, b: "f" * 40)
        try:
            heads, errors = pipeline.sync(est, ["other"])
        finally:
            gitops.sync_mirror, gitops.head = real_sync, real_head
        self.assertEqual((heads, errors), ({"other": "f" * 40}, {}))
        self.assertEqual(calls, ["https://github.com/Org/other"])      # not app, not app's mirror "core"


class HealthAndDigestTests(unittest.TestCase):
    def test_health_summary_tracks_new_and_fixed_failures(self):
        est = manifest.load(write_manifest(MINIMAL))
        pkg = est.find("app/backend")

        def rep(cases):
            c = {"name": "tests", "transition": "still-failing" if "fail" in cases.values() else "ok",
                 "before": {"passed": "fail" not in cases.values(), "cases": cases}}
            return {"targets": [{"checks": [c], "findings": []}]}

        first = pipeline.summarise_health(pkg, "a" * 40, rep({"t1": "pass", "t2": "fail"}), None)
        self.assertEqual((first["failing"], first["newly_failing"]), (["tests: t2"], []))
        second = pipeline.summarise_health(pkg, "b" * 40, rep({"t1": "fail", "t2": "pass"}), first)
        self.assertEqual(second["newly_failing"], ["tests: t1"])
        self.assertEqual(second["fixed_since_last"], ["tests: t2"])
        self.assertIsNone(second["error"])

    def test_digest_lists_what_needs_a_person(self):
        est = manifest.load(write_manifest(MINIMAL))
        pkg = est.find("app/backend")
        run = est.state_dir / pkg.slug / "proposals" / "nodemailer" / "20260928-000000-proposal-ab12"
        state.write_json(run / "decision.json", triage.decide(report([check("tests", "ok")]), GOOD_PROPOSAL).to_dict())
        state.write_json(run / "proposal.json", GOOD_PROPOSAL)
        state.write_json(est.state_dir / pkg.slug / "health" / "20260928-000000-health-ab12" / "summary.json",
                         {"status": "broken", "commit": "c" * 40, "failing": ["tests: t1"],
                          "newly_failing": ["tests: t1"], "commits_since_last_pass": ["abc123 Mark: change"]})
        text = digest.render(est)
        self.assertIn("review the nodemailer change (READY)", text)
        self.assertIn("app/backend: health broken", text)
        self.assertIn("abc123 Mark: change", text)
        self.assertIn("not verified: macOS only", text)


if __name__ == "__main__":
    unittest.main()
