"""Unit tests for the parts of PatchLab Internal that do not need Docker.

Run with:  python -m unittest discover -s tests
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from patchlab_internal import compare, config, probes, results, runner, windows
from patchlab_internal.compare import CheckResult
from patchlab_internal.config import Check


class TapTests(unittest.TestCase):
    def test_statuses_and_directives(self):
        cases = results.parse_tap(textwrap.dedent("""\
            TAP version 13
            ok 1 - first
            not ok 2 - second
            ok 3 - third # SKIP no network
            not ok 4 - fourth # TODO not implemented
            1..4
            """))
        self.assertEqual(cases, {"first": "pass", "second": "fail",
                                 "third": "skip", "fourth": "skip"})

    def test_crash_before_plan_completes_counts_as_failure(self):
        cases = results.parse_tap("1..3\nok 1 - a\n")
        self.assertEqual(cases["a"], "pass")
        self.assertEqual([s for s in cases.values()].count("fail"), 2)

    def test_duplicate_names_are_kept_apart(self):
        cases = results.parse_tap("ok 1 - same\nnot ok 2 - same\n")
        self.assertEqual(len(cases), 2)


class JUnitTests(unittest.TestCase):
    def test_parse(self):
        cases = results.parse_junit("""<testsuites><testsuite>
            <testcase classname="api" name="login"/>
            <testcase classname="api" name="logout"><failure message="boom"/></testcase>
            <testcase name="slow"><skipped/></testcase>
            <testcase name="crash"><error/></testcase>
        </testsuite></testsuites>""")
        self.assertEqual(cases, {"api.login": "pass", "api.logout": "fail",
                                 "slow": "skip", "crash": "fail"})


def cr(name, passed, cases=None, duration=1.0):
    return CheckResult(name, passed, 0 if passed else 1, duration, cases=cases or {})


class CompareChecksTests(unittest.TestCase):
    def test_transitions(self):
        checks = [Check("a", "true"), Check("b", "true"), Check("c", "true"), Check("d", "true")]
        before = {"a": cr("a", True), "b": cr("b", True), "c": cr("c", False), "d": cr("d", False)}
        after = {"a": cr("a", True), "b": cr("b", False), "c": cr("c", True), "d": cr("d", False)}
        deltas, findings = compare.compare_checks(checks, before, after)
        self.assertEqual([d.transition for d in deltas], ["ok", "regressed", "fixed", "still-failing"])
        self.assertEqual(compare.verdict_for(findings), "FAIL")

    def test_non_critical_regression_only_warns(self):
        checks = [Check("lint", "true", critical=False)]
        _, findings = compare.compare_checks(checks, {"lint": cr("lint", True)},
                                             {"lint": cr("lint", False)})
        self.assertEqual(compare.verdict_for(findings), "WARN")

    def test_case_level_regression_inside_already_failing_suite(self):
        checks = [Check("unit", "true")]
        before = {"unit": cr("unit", False, {"x": "pass", "y": "fail"})}
        after = {"unit": cr("unit", False, {"x": "fail", "y": "fail"})}
        deltas, findings = compare.compare_checks(checks, before, after)
        self.assertEqual(deltas[0].transition, "still-failing")
        self.assertEqual(deltas[0].case_regressions, ["x"])
        self.assertEqual(compare.verdict_for(findings), "FAIL")

    def test_vanished_and_new_failing_tests_are_regressions(self):
        checks = [Check("unit", "true")]
        before = {"unit": cr("unit", True, {"kept": "pass", "gone": "pass"})}
        after = {"unit": cr("unit", False, {"kept": "pass", "added": "fail"})}
        deltas, _ = compare.compare_checks(checks, before, after)
        self.assertIn("added (new test)", deltas[0].case_regressions)
        self.assertIn("gone (no longer reported)", deltas[0].case_regressions)

    def test_slowdown_warning(self):
        checks = [Check("perf", "true", perf_tolerance=0.2)]
        _, findings = compare.compare_checks(checks, {"perf": cr("perf", True, duration=10)},
                                             {"perf": cr("perf", True, duration=15)})
        self.assertEqual([f.area for f in findings], ["performance"])

    def test_clean_run_passes(self):
        checks = [Check("a", "true")]
        _, findings = compare.compare_checks(checks, {"a": cr("a", True)}, {"a": cr("a", True)})
        self.assertEqual(compare.verdict_for(findings), "PASS")


PROBE_OUTPUT = """@@os
Ubuntu 24.04 LTS
@@kernel
6.8.0
@@pkgmgr
dpkg
@@packages
libc6\t2.39-0ubuntu8
openssl\t3.0.13-0ubuntu3
@@pkgdb
@@brokenlibs
/usr/bin/foo: libbar.so.1 => not found
@@listening
00000000:1F90
00000000:0016
@@watch
abc123  /etc/app.conf
@@end
"""


class ProbeTests(unittest.TestCase):
    def test_parse(self):
        s = probes.parse(PROBE_OUTPUT)
        self.assertEqual(s.os, "Ubuntu 24.04 LTS")
        self.assertEqual(s.packages["openssl"], "3.0.13-0ubuntu3")
        self.assertEqual(s.broken_libs, ["/usr/bin/foo: libbar.so.1"])
        self.assertEqual(s.listening, [22, 8080])
        self.assertEqual(s.files, {"/etc/app.conf": "abc123"})
        self.assertIsNone(s.error)

    def test_truncated_output_is_flagged(self):
        self.assertIsNotNone(probes.parse("@@os\nx\n").error)

    def test_snapshot_diff(self):
        before = probes.parse(PROBE_OUTPUT)
        after = probes.parse(PROBE_OUTPUT
                             .replace("openssl\t3.0.13-0ubuntu3", "openssl\t3.0.13-0ubuntu3.1")
                             .replace("libc6\t2.39-0ubuntu8\n", "")
                             .replace("00000000:1F90\n", "")
                             .replace("abc123", "def456")
                             .replace("@@listening", "/usr/bin/baz: libqux.so.2 => not found\n@@listening"))
        pk, files, findings = compare.compare_snapshots(before, after)
        self.assertEqual(pk.upgraded, [("openssl", "3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1")])
        self.assertEqual(pk.removed, [("libc6", "2.39-0ubuntu8")])
        self.assertEqual(files["changed"], ["/etc/app.conf"])
        areas = {(f.severity, f.area) for f in findings}
        self.assertIn(("fail", "libraries"), areas)
        self.assertIn(("fail", "services"), areas)   # port 8080 went away
        self.assertIn(("warn", "packages"), areas)


class ConfigTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "app").mkdir()
        p = d / "patchlab.toml"
        p.write_text(textwrap.dedent(text))
        return p

    def test_minimal_config(self):
        cfg = config.load(self.write("""
            [sandbox]
            images = ["alpine:3.20"]
            [[deploy]]
            src = "app"
            dest = "/opt/app"
            [[checks]]
            name = "smoke"
            run = "true"
            """))
        self.assertEqual(cfg.sandbox.images, ["alpine:3.20"])
        self.assertEqual(cfg.deploy[0].dest, "/opt/app")
        self.assertIsNone(cfg.patch)

    def test_rejects_duplicate_checks(self):
        with self.assertRaises(config.ConfigError):
            config.load(self.write("""
                [sandbox]
                images = ["x"]
                [[checks]]
                name = "a"
                run = "true"
                [[checks]]
                name = "a"
                run = "true"
                """))

    def test_patch_specs(self):
        p = config.parse_patch_spec("os-packages:openssl,libssl3", None)
        self.assertEqual(p.packages, ["openssl", "libssl3"])
        self.assertIn("openssl", p.label)
        with self.assertRaises(config.ConfigError):
            config.parse_patch_spec("source:/does/not/exist.patch", "/opt/app")
        with self.assertRaises(config.ConfigError):
            config.parse_patch_spec("magic", None)


class ExampleConfigTest(unittest.TestCase):
    def test_bundled_example_is_valid(self):
        root = Path(__file__).resolve().parent.parent
        cfg = config.load(root / "examples" / "urlkit" / "patchlab.toml")
        self.assertIn("unit-tests", [c.name for c in cfg.checks])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- Windows

class NUnitTests(unittest.TestCase):
    def test_pester_nunit_output(self):
        cases = results.parse_junit(b"""<?xml version="1.0" encoding="utf-8"?>
            <test-results><test-suite><results>
              <test-case name="Core.services running" executed="True" result="Success" success="True"/>
              <test-case name="Core.WMI answers" executed="True" result="Failure" success="False"/>
              <test-case name="IIS responds" executed="False" result="Ignored"/>
            </results></test-suite></test-results>""")
        self.assertEqual(cases, {"Core.services running": "pass", "Core.WMI answers": "fail",
                                 "IIS responds": "skip"})


WIN_PROBE = {
    "os": "Microsoft Windows Server 2022 Standard (build 20348.2700)", "kernel": "20348.2700",
    "packages": {"Windows OS build": "20348.2700", "KB5041160": "installed",
                 "CBS Package_for_RollupFix": "20348.2700.1.9", "Contoso Payroll": "4.2"},
    "pkgdb_issues": [], "listening": [80, 135, 445], "files": {"reg:HKEY_LOCAL_MACHINE\\X\\Enabled": "1"},
    "services_down": [], "problem_devices": [],
    "events": {"System/Service Control Manager/7000": {"level": "Error", "count": 1, "message": "x"}},
    "pending_reboot": [], "errors": [],
}


def win_snapshot(**changes):
    data = json.loads(json.dumps(WIN_PROBE))
    for k, v in changes.items():
        data[k] = v
    return windows.parse_probe(data)


class WindowsCompareTests(unittest.TestCase):
    def test_monthly_update_happy_path(self):
        before = win_snapshot()
        after = win_snapshot(kernel="20348.2762", packages={
            "Windows OS build": "20348.2762", "KB5044281": "installed",
            "CBS Package_for_RollupFix": "20348.2762.1.11", "Contoso Payroll": "4.2"})
        pk, _, findings = compare.compare_snapshots(before, after)
        self.assertIn(("Windows OS build", "20348.2700", "20348.2762"), pk.upgraded)
        self.assertIn(("KB5044281", "installed"), pk.added)
        # The superseded KB is informational, not a "package removed" warning.
        self.assertEqual(compare.verdict_for(findings), "PASS")

    def test_service_device_event_and_registry_regressions(self):
        before = win_snapshot()
        after = win_snapshot(
            services_down=["W3SVC (World Wide Web Publishing Service)"],
            problem_devices=["Microsoft Hyper-V Network Adapter [Net]: Error"],
            events={**WIN_PROBE["events"],
                    "System/Microsoft-Windows-Kernel-Power/41": {"level": "Critical", "count": 1, "message": "rebooted"},
                    "Application/Application Error/1000": {"level": "Error", "count": 3, "message": "w3wp.exe crashed"}},
            files={"reg:HKEY_LOCAL_MACHINE\\X\\Enabled": "0"},
            listening=[135, 445])
        _, files, findings = compare.compare_snapshots(before, after)
        by_area = {(f.severity, f.area) for f in findings}
        self.assertIn(("fail", "services"), by_area)      # W3SVC down and port 80 gone
        self.assertIn(("fail", "drivers"), by_area)
        self.assertIn(("fail", "events"), by_area)        # Kernel-Power 41
        self.assertIn(("warn", "events"), by_area)        # application crash
        self.assertEqual(files["changed"], ["reg:HKEY_LOCAL_MACHINE\\X\\Enabled"])
        self.assertEqual(compare.verdict_for(findings), "FAIL")

    def test_existing_errors_are_not_blamed_on_the_patch(self):
        noisy = {"System/DCOM/10016": {"level": "Error", "count": 40, "message": "permissions"}}
        _, _, findings = compare.compare_snapshots(win_snapshot(events=noisy, services_down=["sppsvc"]),
                                                   win_snapshot(events=noisy, services_down=["sppsvc"]))
        self.assertEqual(compare.verdict_for(findings), "PASS")

    def test_pending_reboot_after_patch_warns(self):
        _, _, findings = compare.compare_snapshots(win_snapshot(), win_snapshot(pending_reboot=["Windows Update"]))
        self.assertEqual(compare.verdict_for(findings), "WARN")


class WindowsConfigTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent

    def test_bundled_windows_configs(self):
        for name, provider in (("hyperv.toml", "hyperv"), ("vsphere.toml", "vsphere"), ("local-dev.toml", "local")):
            cfg = config.load(self.root / "examples" / "windows" / name)
            self.assertEqual((cfg.sandbox.platform, cfg.sandbox.provider), ("windows", provider))
        cfg = config.load(self.root / "examples" / "windows" / "hyperv.toml")
        self.assertIn("platform-tests", [c.name for c in cfg.checks])      # from the include
        self.assertEqual(cfg.patch.kind, "windows-update")
        self.assertEqual(cfg.sandbox.provider_options["switch"], "PatchLabInternal-NAT")
        self.assertTrue(cfg.health.watch_registry)                         # Windows defaults

    def test_windows_patch_specs(self):
        p = config.parse_patch_spec("windows-update:kb5044281", None, "windows")
        self.assertEqual(p.packages, ["KB5044281"])
        with self.assertRaises(config.ConfigError):
            config.parse_patch_spec("windows-update:5044281", None, "windows")
        with self.assertRaises(config.ConfigError):
            config.parse_patch_spec("os-packages", None, "windows")
        with self.assertRaises(config.ConfigError):
            config.parse_patch_spec("windows-update", None, "linux")

    def test_target_names_and_sizes(self):
        self.assertEqual(runner.slugify(r"D:\PatchLabInternal\Golden\ws2022-std.vhdx"), "ws2022-std")
        self.assertEqual(runner.slugify("ubuntu:24.04"), "ubuntu-24.04")
        self.assertEqual(windows._size_mb("4g"), 4096)
        self.assertEqual(windows._size_mb("512MB"), 512)


class WindowsScriptTests(unittest.TestCase):
    def test_extract_json_and_system_wrapper(self):
        self.assertEqual(windows.extract_json("noise\n@@PLJSON {\"a\": 1}\nmore"), {"a": 1})
        self.assertIsNone(windows.extract_json("nothing here"))
        wrapped = windows.as_system("Write-Output hi", 600)
        self.assertNotIn("__PAYLOAD__", wrapped)
        self.assertIn("$timeout = 600", wrapped)


PWSH = shutil.which("pwsh")


@unittest.skipUnless(PWSH, "PowerShell 7 (pwsh) not installed")
class WindowsPipelineIntegrationTest(unittest.TestCase):
    """Runs the Windows pipeline end to end with the local provider."""

    root = Path(__file__).resolve().parent.parent

    def run_patch(self, script: str) -> int:
        out = Path(tempfile.mkdtemp())
        proc = subprocess.run(
            [sys.executable, "-m", "patchlab_internal", "run", "examples/windows/local-dev.toml",
             "--patch", f"script:examples/windows/local/patches/{script}", "--out", str(out), "-q"],
            cwd=self.root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        report = json.loads(next(out.glob("*/report.json")).read_text())
        return proc.returncode, report

    def test_good_and_bad_hotfix(self):
        code, report = self.run_patch("good-hotfix.ps1")
        self.assertEqual((code, report["verdict"]), (0, "PASS"))
        code, report = self.run_patch("bad-hotfix.ps1")
        self.assertEqual((code, report["verdict"]), (1, "FAIL"))
        details = [d for f in report["targets"][0]["findings"] for d in f["details"]]
        self.assertIn("Kerberos authentication in use", details)
        self.assertEqual(report["cleanup"], "all sandboxes removed")


@unittest.skipUnless(PWSH, "PowerShell 7 (pwsh) not installed")
class PowerShellSyntaxTest(unittest.TestCase):
    def test_all_scripts_parse(self):
        root = Path(__file__).resolve().parent.parent
        script = r"""
$bad = 0
foreach ($f in Get-ChildItem -Recurse -Filter *.ps1 -Path $args) {
  $t = $null; $e = $null
  $text = (Get-Content -Raw $f.FullName).Replace('__TIMEOUT__', '60').Replace('__PAYLOAD__', '')
  [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
  foreach ($err in $e) { $bad++; "$($f.Name):$($err.Extent.StartLineNumber) $($err.Message)" }
}
exit $bad
"""
        proc = subprocess.run([PWSH, "-NoProfile", "-Command", script,
                               str(root / "patchlab_internal" / "ps"), str(root / "examples" / "windows")],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


@unittest.skipUnless(PWSH, "PowerShell 7 (pwsh) not installed")
class RunAsSystemWrapperTest(unittest.TestCase):
    """Exercises run-as-system.ps1 with stubbed ScheduledTasks cmdlets."""

    def run_payload(self, payload: str, timeout: int = 60) -> subprocess.CompletedProcess:
        stubs = Path(__file__).resolve().parent / "fixtures" / "scheduledtask-stubs.ps1"
        tmp = Path(tempfile.mkdtemp())
        shim = tmp / "bin"
        shim.mkdir()
        if not shutil.which("powershell.exe"):
            (shim / "powershell.exe").symlink_to(PWSH)
        self.guest = tmp / "guest"
        env = {**os.environ, "PATCHLAB_INTERNAL_GUEST_DIR": str(self.guest),
               "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}"}
        script = f". '{stubs}'\n" + windows.as_system(payload, timeout)
        return subprocess.run([PWSH, "-NoProfile", "-Command", script], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", env=env, timeout=120)

    def test_output_exit_code_and_config_are_relayed(self):
        p = self.run_payload(windows.with_config(
            "Write-Output \"kbs=$($PatchLabInternalConfig.kbs -join ',')\"\n"
            "'@@PLJSON ' + (@{ok=$true} | ConvertTo-Json -Compress)\nexit 3", {"kbs": ["KB1", "KB2"]}))
        self.assertEqual(p.returncode, 3)
        self.assertIn("kbs=KB1,KB2", p.stdout)
        self.assertEqual(windows.extract_json(p.stdout), {"ok": True})
        self.assertEqual(list(self.guest.iterdir()), [])   # temp files cleaned up

    def test_timeout_and_crash(self):
        self.assertEqual(self.run_payload("Start-Sleep 30", timeout=3).returncode, 124)
        p = self.run_payload("throw 'payload blew up'")
        self.assertEqual(p.returncode, 1)
        self.assertIn("payload blew up", p.stdout)


class ReviewRegressionTest(unittest.TestCase):
    def test_sandbox_names_are_unique_and_bounded(self):
        slugs = runner.unique_slugs(["rg/vm", "rg-vm", "x" * 80, "x" * 80 + "y"])
        self.assertEqual(len(set(slugs)), 4)
        names = [runner.sandbox_name("20260926-120000-abcd", s, 60) for s in slugs]
        self.assertEqual(len(set(names)), 4)
        self.assertTrue(all(len(n) <= 60 for n in names))

    def test_uninstall_is_only_the_default_for_update_files(self):
        tmp = Path(tempfile.mkdtemp())
        for name in ("kb1.msu", "pkg.cab", "app.msi"):
            (tmp / name).write_text("x")
        spec = lambda *names: config.parse_patch_spec("package-file:" + ",".join(str(tmp / n) for n in names), None, "windows")
        self.assertTrue(windows.uninstall_is_default(spec("kb1.msu", "pkg.cab")))
        self.assertFalse(windows.uninstall_is_default(spec("app.msi")))
        self.assertFalse(windows.uninstall_is_default(spec("kb1.msu", "app.msi")))
        self.assertTrue(windows.uninstall_is_default(config.parse_patch_spec("windows-update", None, "windows")))

    def test_no_powershell_wraps_a_json_array_in_at_parens(self):
        # In Windows PowerShell 5.1, @(... | ConvertFrom-Json) turns an array into ONE element.
        import re
        root = Path(__file__).resolve().parent.parent
        bad = []
        for p in root.rglob("*.ps1"):
            if {"build", ".venv"} & set(p.relative_to(root).parts):
                continue
            code = "\n".join(l for l in p.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
            if re.search(r"@\([^)]*ConvertFrom-Json", code):
                bad.append(str(p))
        self.assertEqual(bad, [])


@unittest.skipUnless(PWSH and sys.platform != "win32", "needs pwsh and POSIX signals")
class DoubleInterruptTest(unittest.TestCase):
    """A second Ctrl-C during clean-up must not stop the report or the final sweep."""

    def test_second_interrupt_is_ignored(self):
        import signal
        import time
        tmp = Path(tempfile.mkdtemp())
        (tmp / "slow.toml").write_text(textwrap.dedent("""
            [sandbox]
            platform = "windows"
            provider = "local"
            images = ["dev"]
            [[checks]]
            name = "slow"
            run = "Start-Sleep 30"
            [health]
            enabled = false
            """))
        (tmp / "p.ps1").write_text("Write-Output patched\n")
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.Popen([sys.executable, "-m", "patchlab_internal", "run", str(tmp / "slow.toml"), "--patch",
                                 f"script:{tmp / 'p.ps1'}", "--out", str(tmp / "r"), "--run-id", "dbl", "-q"],
                                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        time.sleep(6)
        proc.send_signal(signal.SIGINT)
        time.sleep(0.5)
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=120)
        report = json.loads((tmp / "r" / "dbl" / "report.json").read_text())
        self.assertTrue(report["cancelled"], out)
        self.assertEqual(report["cleanup"], "all sandboxes removed")
        self.assertEqual(proc.returncode, 2, out)
