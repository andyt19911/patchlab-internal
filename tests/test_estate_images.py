"""Estate container images: Dockerfile parsing, runtime support, the runtime move and its gate."""

import datetime as dt
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from patchlab_internal.config import ConfigError
from patchlab_internal.estate import images, manifest, triage

TODAY = dt.date(2026, 9, 28)

DOCKERFILE = textwrap.dedent("""\
    ARG BASE=node
    FROM node:20-alpine AS build
    RUN npm ci
    FROM --platform=linux/amd64 node:20-alpine
    COPY --from=build /app/dist ./dist
    FROM build AS again
    FROM ${BASE}:22
    FROM python:3.11.9-slim@sha256:abc
    """)


def _no_network(*a, **k):
    raise OSError("blocked")


class ParseTests(unittest.TestCase):
    def test_bases_skip_stages_and_arg_images(self):
        self.assertEqual(images.dockerfile_bases(DOCKERFILE),
                         ["node:20-alpine", "python:3.11.9-slim@sha256:abc"])

    def test_parse_base(self):
        b = images.parse_base("docker.io/library/node:20-bookworm-slim")
        self.assertEqual((b.runtime, b.line, b.variant), ("node", "20", "-bookworm-slim"))
        b = images.parse_base("python:3.11.9-slim@sha256:abc")
        self.assertEqual((b.runtime, b.line, b.variant), ("python", "3.11", "-slim"))
        b = images.parse_base("registry.example:5000/team/node:20")
        self.assertEqual((b.repo, b.line), ("registry.example:5000/team/node", "20"))
        self.assertIsNone(images.parse_base("alpine").line)

    def test_rewrite_moves_only_the_runtime_line(self):
        text, n = images.rewrite_dockerfile(DOCKERFILE, "node", "20", "24")
        self.assertEqual(n, 2)
        self.assertIn("FROM node:24-alpine AS build\n", text)
        self.assertIn("FROM --platform=linux/amd64 node:24-alpine\n", text)
        self.assertIn("FROM ${BASE}:22", text)
        self.assertIn("python:3.11.9-slim", text)

    def test_moving_a_pinned_patch_drops_the_pin_with_the_line(self):
        self.assertEqual(images.moved("python:3.11.9-slim@sha256:abc", "python", "3.11", "3.13"),
                         "python:3.13-slim")


@mock.patch("urllib.request.urlopen", _no_network)
class SupportTests(unittest.TestCase):
    def test_node_20_is_eol_and_moves_to_the_next_lts_with_a_year_left(self):
        s = images.support(images.parse_base("node:20-alpine"), TODAY)
        self.assertEqual(s["status"], "eol")
        self.assertEqual(s["target"], "24")       # 22 ends 2027-04, under a year away
        self.assertIn("table", s["source"])

    def test_supported_line_has_no_target(self):
        s = images.support(images.parse_base("python:3.11-slim"), TODAY)
        self.assertEqual(s["status"], "ok")
        self.assertNotIn("target", s)

    def test_unknown_runtime(self):
        self.assertEqual(images.support(images.parse_base("golang:1.27"), TODAY)["status"], "unknown")

    def test_odd_node_majors_are_never_proposed(self):
        dates = {"20": "2026-04-30", "23": "2030-01-01", "24": "2028-04-30"}
        self.assertEqual(images.next_line("node", "20", dates, TODAY), "24")

    def test_endoflife_date_wins_when_reachable(self):
        body = json.dumps([{"cycle": "20", "eol": "2026-04-30"}, {"cycle": "26", "eol": "2030-04-30"}])

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return body.encode()

        with mock.patch("urllib.request.urlopen", lambda *a, **k: R()):
            s = images.support(images.parse_base("node:20"), TODAY)
        self.assertEqual((s["source"], s["target"]), ("endoflife.date", "26"))


class CompanionTests(unittest.TestCase):
    def test_single_ci_pins_move_and_matrices_do_not(self):
        text = "  node-version: 20\n  node-version: '20.x'  # pinned\n  node-version: [20, 22]\n"
        out, n = images.companion_edits(text, "node", "20", "24")
        self.assertEqual(n, 2)
        self.assertEqual(out, "  node-version: 24\n  node-version: '24.x'  # pinned\n  node-version: [20, 22]\n")

    def test_apply_touches_only_this_packages_workflows(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "backend").mkdir()
            (root / "backend/Dockerfile").write_text("FROM node:20-alpine\n")
            (root / "backend/.nvmrc").write_text("v20\n")
            wf = root / ".github/workflows"
            wf.mkdir(parents=True)
            (wf / "backend.yml").write_text(textwrap.dedent("""\
                jobs:
                  test:
                    defaults:
                      run:
                        working-directory: backend
                    steps:
                      - with:
                          node-version: 20
                  sdk:
                    steps:
                      - with:
                          node-version: 20
                      - run: cd sdk-js && npm test
                """))
            (wf / "sdk.yml").write_text("jobs:\n  a:\n    working-directory: sdk-js\n    node-version: 20\n")
            img = manifest.Image(dockerfile="backend/Dockerfile", package="backend")
            changed = images.apply_runtime_move(root, img, "node", "20", "24")
            self.assertEqual(sorted(changed), [".github/workflows/backend.yml", "backend/.nvmrc", "backend/Dockerfile"])
            self.assertIn("node-version: 20", (wf / "sdk.yml").read_text())
            text = (wf / "backend.yml").read_text()
            self.assertEqual((text.count("node-version: 24"), text.count("node-version: 20")), (1, 1))
            self.assertEqual((root / "backend/.nvmrc").read_text(), "24\n")


class TrivyTests(unittest.TestCase):
    def test_summary_counts_and_fixable(self):
        data = {"Metadata": {"OS": {"Family": "debian", "Name": "12.5", "EOSL": False}},
                "Results": [{"Class": "os-pkgs", "Target": "x", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "libc", "Severity": "HIGH", "FixedVersion": "2"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "Severity": "LOW"}]}]}
        s = images.summarise_trivy("img", json.dumps(data))
        self.assertEqual((s["os"], s["counts"], s["fixable_high"]), ("debian 12.5", {"high": 1, "low": 1}, 1))
        self.assertIn("error", images.summarise_trivy("img", "not json"))
        self.assertTrue(images.summarise_trivy("img", "not json")["error"])


def _prop(**over):
    p = {"dockerfile": "backend/Dockerfile", "changed_files": ["backend/Dockerfile"],
         "move": {"runtime": "node", "from": "20", "to": "24", "eol": "2026-04-30", "status": "eol"},
         "build": {"before": {"ok": True, "tail": ""}, "after": {"ok": True, "tail": ""}},
         "scans_before": [{"fixable_high": 3}], "scans_after": [{"fixable_high": 0}],
         "tests": {"status": "ran", "sandbox_image": "node:24-bookworm", "broken": [], "passing_after": 900}}
    p.update(over)
    return p


class GateTests(unittest.TestCase):
    def test_ready(self):
        d = images.decide(_prop())
        self.assertEqual(d.verdict, triage.READY, d.summary)
        self.assertIn("breaking-risk", d.labels)

    def test_broken_test_blocks(self):
        d = images.decide(_prop(tests={"status": "ran", "sandbox_image": "n", "broken": ["unit: a"],
                                       "passing_after": 1}))
        self.assertEqual(d.verdict, triage.BLOCKED)

    def test_build_that_worked_and_now_fails_blocks(self):
        d = images.decide(_prop(build={"before": {"ok": True, "tail": ""}, "after": {"ok": False, "tail": "x"}}))
        self.assertEqual(d.verdict, triage.BLOCKED)

    def test_unlinked_image_needs_review(self):
        d = images.decide(_prop(tests={"status": "not-linked"}))
        self.assertEqual(d.verdict, triage.REVIEW)

    def test_more_fixable_vulnerabilities_blocks(self):
        self.assertEqual(images.decide(_prop(scans_after=[{"fixable_high": 5}])).verdict, triage.BLOCKED)

    def test_failed_scan_is_never_a_pass(self):
        d = images.decide(_prop(scans_after=[{"error": "pull failed"}]))
        self.assertEqual(d.verdict, triage.INCONCLUSIVE)

    def test_other_files_block(self):
        d = images.decide(_prop(changed_files=["backend/Dockerfile", "backend/src/app.ts"]))
        self.assertEqual(d.verdict, triage.BLOCKED)


class ManifestImageTests(unittest.TestCase):
    BASE = textwrap.dedent("""\
        [[repo]]
        name = "app"
        url = "https://github.com/Org/app"
          [[repo.package]]
          path = "backend"
          ecosystem = "npm"
          image = "node:20"
          checks = [{ name = "unit", run = "npm test" }]
        """)

    def load(self, extra: str):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "estate.toml"
            p.write_text(self.BASE + textwrap.dedent(extra))
            return manifest.load(p)

    def test_image_entries(self):
        est = self.load('  [[repo.image]]\n  dockerfile = "backend/Dockerfile"\n  package = "backend"\n'
                        '  [[repo.image]]\n  dockerfile = "Dockerfile"\n  context = "."\n')
        imgs = est.repos[0].images
        self.assertEqual([(i.dockerfile, i.package, i.context) for i in imgs],
                         [("backend/Dockerfile", "backend", None), ("Dockerfile", None, ".")])

    def test_unknown_package_and_escaping_paths_are_refused(self):
        with self.assertRaises(ConfigError):
            self.load('  [[repo.image]]\n  dockerfile = "x/Dockerfile"\n  package = "nope"\n')
        with self.assertRaises(ConfigError):
            self.load('  [[repo.image]]\n  dockerfile = "../Dockerfile"\n')


if __name__ == "__main__":
    unittest.main()
