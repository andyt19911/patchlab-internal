"""Engine support for code with dependencies and services: install step, sidecars,
mirrors, isolated checks, baseline-only runs, and tests that stop running.

No Docker needed: the sandbox is a recording fake. The e2e-linux CI job runs
examples/services/patchlab.toml on real Docker.
"""

import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

from patchlab_internal import compare, config, runner
from patchlab_internal.compare import CheckResult
from patchlab_internal.config import Check
from patchlab_internal.linux import LinuxPlatform, sandbox_env
from patchlab_internal.sandbox import ExecResult


def load(text: str, extra_dirs=("app",)) -> config.Config:
    d = Path(tempfile.mkdtemp())
    for x in extra_dirs:
        (d / x).mkdir(parents=True, exist_ok=True)
    p = d / "patchlab.toml"
    p.write_text(textwrap.dedent(text))
    return config.load(p)


BASE = """
    [sandbox]
    images = ["node:20-bookworm"]
    install = ["npm ci"]
    workdir = "/src/app"
    check_network = "isolated"
    [[sidecars]]
    name = "postgres"
    image = "postgres:16"
    health = "pg_isready"
    [[mirrors]]
    path = "mirror.git"
    urls = ["ssh://git@github.com/Org/core.git"]
    [[deploy]]
    src = "app"
    dest = "/src/app"
    [[checks]]
    name = "tests"
    run = "npm test"
    """


class ServiceConfigTests(unittest.TestCase):
    def test_parses_install_sidecars_mirrors(self):
        cfg = load(BASE, ("app", "mirror.git"))
        sb = cfg.sandbox
        self.assertEqual(sb.install, ["npm ci"])
        self.assertEqual(sb.workdir, "/src/app")
        self.assertEqual(sb.sidecars[0].name, "postgres")
        self.assertEqual(sb.mirrors[0].urls, ["ssh://git@github.com/Org/core.git"])
        env = sandbox_env(sb)
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "url.file:///opt/patchlab/mirrors/01-mirror.git.insteadOf")
        self.assertEqual(env["GIT_CONFIG_VALUE_0"], "ssh://git@github.com/Org/core.git")

    def test_missing_mirror_and_bad_values_are_refused(self):
        with self.assertRaisesRegex(config.ConfigError, "mirror not found"):
            load(BASE)
        with self.assertRaisesRegex(config.ConfigError, "check_network"):
            load(BASE.replace('"isolated"', '"sometimes"'), ("app", "mirror.git"))
        with self.assertRaisesRegex(config.ConfigError, "host name"):
            load(BASE.replace('name = "postgres"', 'name = "Post Gres"'), ("app", "mirror.git"))

    def test_windows_targets_refuse_linux_only_features(self):
        text = BASE.replace('images = ["node:20-bookworm"]', 'images = ["x.vhdx"]\n    platform = "windows"')
        with self.assertRaisesRegex(config.ConfigError, "Linux targets only"):
            load(text, ("app", "mirror.git"))


class FakeBox:
    """Records every command; `fail` maps a command substring to a failing exit."""

    def __init__(self, fail=()):
        self.commands, self.fail = [], list(fail)
        self.network, self.private_network = "bridge", "run-net"
        self.connected = {"bridge", "run-net"}
        self.events = []
        self.started, self.name, self.sidecars = True, "box", []
        self.caps = {}

    def exec(self, command, timeout=300, workdir=None):
        self.commands.append((command, workdir, frozenset(self.connected)))
        bad = any(f in command for f in self.fail)
        return ExecResult(1 if bad else 0, "", "boom" if bad else "", 0.01)

    def connect(self, net, alias=None):
        self.connected.add(net)
        self.events.append(("connect", net))

    def disconnect(self, net):
        self.connected.discard(net)
        self.events.append(("disconnect", net))

    def copy_in(self, *a, **k):
        pass

    def copy_out(self, *a, **k):
        return False

    def destroy(self):
        self.started = False


def target_run(cfg, patch, box):
    tmp = Path(tempfile.mkdtemp())
    tr = runner.TargetRun(cfg, patch, cfg.sandbox.images[0], "t1", runner.Options(out_dir=tmp),
                          runner.Logger(quiet=True), threading.Event(), platform=LinuxPlatform(cfg))
    tr.box = box
    return tr


class InstallStepTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load(BASE, ("app", "mirror.git"))
        self.patch = config.Patch(kind="script", run="bump", rollback="unbump")

    def test_reinstalls_after_patch_and_rollback_with_network_only_while_installing(self):
        box = FakeBox()
        tr = target_run(self.cfg, self.patch, box)
        plat = tr.platform
        self.assertIsNone(plat.install(tr, "deploy"))
        self.assertTrue(plat.apply_patch(tr))
        self.assertTrue(plat.rollback(tr))
        cmds = [c for c, _, _ in box.commands]
        self.assertEqual([c for c in cmds if c in ("npm ci", "bump", "unbump")],
                         ["npm ci", "bump", "npm ci", "unbump", "npm ci"])
        for cmd, workdir, nets in box.commands:
            if cmd == "npm ci":
                self.assertIn("bridge", nets, "installs reach the registries")
                self.assertEqual(workdir, "/src/app")
        self.assertNotIn("bridge", box.connected, "checks never run with the outside network")

    def test_install_failure_after_the_patch_is_a_regression(self):
        box = FakeBox()
        tr = target_run(self.cfg, self.patch, box)
        box.fail = ["npm ci"]
        self.assertFalse(tr.platform.apply_patch(tr))
        f = tr.result.findings[-1]
        self.assertEqual((f.severity, f.area), ("fail", "install"))
        self.assertNotIn("bridge", box.connected, "isolation restored even after a failed install")


class BaselineOnlyTests(unittest.TestCase):
    def test_no_patch_reports_failures_as_they_are(self):
        cfg = load(BASE, ("app", "mirror.git"))
        tr = target_run(cfg, None, FakeBox(fail=["npm test"]))
        ph = runner.Phase(checks={"tests": CheckResult("tests", False, 1, 1.0, cases={"a": "fail", "b": "pass"})})
        tr._baseline_findings(ph)
        self.assertEqual(tr.result.findings[0].details, ["a"])
        self.assertEqual(compare.verdict_for(tr.result.findings), "FAIL")


class NowSkippedTests(unittest.TestCase):
    def test_a_test_that_stops_running_is_reported(self):
        checks = [Check("tests", "npm test")]
        before = {"tests": CheckResult("tests", True, 0, 1.0, cases={"a": "pass", "b": "pass"})}
        after = {"tests": CheckResult("tests", True, 0, 1.0, cases={"a": "pass", "b": "skip"})}
        deltas, findings = compare.compare_checks(checks, before, after)
        self.assertEqual(deltas[0].case_now_skipped, ["b"])
        self.assertEqual(compare.verdict_for(findings), "WARN")


if __name__ == "__main__":
    unittest.main()
