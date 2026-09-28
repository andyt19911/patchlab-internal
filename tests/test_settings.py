"""Tests for `patchlab-internal setup` / `patchlab-internal web ...` and the settings file."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patchlab_internal import cli, settings


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        patcher = mock.patch.dict(os.environ, {"PATCHLAB_INTERNAL_HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_defaults_without_a_settings_file(self):
        s = settings.load()
        self.assertFalse(s.exists)
        self.assertFalse(s.web.enabled)
        self.assertEqual(s.reports_path(), Path("reports"))

    def test_round_trip_keeps_awkward_paths(self):
        s = settings.Settings(reports_dir=r"C:\Users\o'brien\PatchLab Internal reports", configs_dir="/srv/patch lab")
        s.web.enabled, s.web.port = True, 9000
        settings.save(s)
        back = settings.load()
        self.assertEqual((back.reports_dir, back.configs_dir), (s.reports_dir, s.configs_dir))
        self.assertEqual((back.web.enabled, back.web.port), (True, 9000))

    def test_setup_flags_then_enable_disable(self):
        code, out = self.run_cli("setup", "--no-web", "--reports-dir", str(self.home / "r"), "--configs-dir", str(self.home))
        self.assertEqual(code, 0, out)
        self.assertFalse(settings.load().web.enabled)

        code, out = self.run_cli("web")                       # disabled: refuses and says how to enable
        self.assertEqual(code, 64)
        self.assertIn("patchlab-internal web enable", out)

        self.assertEqual(self.run_cli("web", "enable", "--port", "8801")[0], 0)
        s = settings.load()
        self.assertEqual((s.web.enabled, s.web.port), (True, 8801))
        self.assertEqual(s.reports_dir, str((self.home / "r").resolve()))   # untouched by enable

        code, out = self.run_cli("web", "status")
        self.assertIn("enabled", out)
        self.assertEqual(self.run_cli("web", "disable")[0], 0)
        self.assertFalse(settings.load().web.enabled)

    def test_setup_is_interactive_only_on_a_terminal(self):
        answers = iter(["/tmp/pl-reports", "/tmp/pl-configs", "y", "127.0.0.1", "8802"])
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", lambda _: next(answers)):
            code, _ = self.run_cli("setup")
        self.assertEqual(code, 0)
        s = settings.load()
        self.assertEqual((s.reports_dir, s.web.enabled, s.web.port), ("/tmp/pl-reports", True, 8802))

    def test_core_never_imports_the_front_end(self):
        root = Path(__file__).resolve().parent.parent / "patchlab_internal"
        offenders = [p.name for p in root.rglob("*.py")
                     if "import patchlab_internal_web" in p.read_text(encoding="utf-8") and p.name != "settings.py"]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
