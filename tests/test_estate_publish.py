"""Estate publishing: what becomes a draft PR, and the guards around it."""

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from patchlab_internal.estate import manifest, publish, state

MANIFEST = textwrap.dedent("""\
    [estate]
    workdir = "work"
    [[repo]]
    name = "app"
    url = "https://github.com/Org/app"
      [[repo.package]]
      path = "backend"
      ecosystem = "npm"
      image = "node:24"
      checks = [{ name = "unit", run = "npm test" }]
    """)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "estate.toml").write_text(MANIFEST)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PATCHLAB_INTERNAL_ESTATE_WORKDIR", None)
            self.est = manifest.load(root / "estate.toml")

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, key, run, verdict, commit="c1", patch="diff --git a/x b/x\n"):
        d = self.est.state_dir / "app-backend" / "proposals" / key / run
        d.mkdir(parents=True)
        state.write_json(d / "decision.json", {"verdict": verdict, "labels": ["security"]})
        state.write_json(d / "proposal.json", {"commit": commit, "plan": {"title": f"fix {key}"}})
        (d / "change.patch").write_text(patch)
        (d / "pr.md").write_text("body")

    def test_only_ready_and_review_with_a_patch_on_the_current_head(self):
        self.add("a", "1", "READY")
        self.add("b", "1", "BLOCKED")
        self.add("c", "1", "REVIEW", commit="old")
        self.add("d", "1", "READY", patch="")
        steps = publish.plan(self.est, {"app": "c1"})
        self.assertEqual({s["branch"]: s["action"] for s in steps},
                         {"patchlab/app-backend/a": "open", "patchlab/app-backend/c": "skip"})

    def test_newest_run_wins_and_published_patches_are_skipped(self):
        self.add("a", "1", "BLOCKED")
        self.add("a", "2", "READY")
        steps = publish.plan(self.est, {"app": "c1"})
        self.assertEqual([s["action"] for s in steps], ["open"])
        it = steps[0]["item"]
        state.write_json(self.est.state_dir / "published.json", {it.branch: {"patch": it.patch_hash, "url": "u"}})
        self.assertEqual(publish.plan(self.est, {"app": "c1"})[0]["action"], "skip")

    def test_apply_is_refused_unless_turned_on(self):
        self.add("a", "1", "READY")
        with self.assertRaisesRegex(RuntimeError, "publishing is off"):
            publish.run(self.est, {"app": "c1"}, apply=True)
        self.est.publish = "draft-pr"
        with mock.patch.dict(os.environ, {publish.TOKEN_ENV: "", publish.TOKEN_ENV + "_ORG": ""}):
            with self.assertRaisesRegex(RuntimeError, publish.TOKEN_ENV):
                publish.run(self.est, {"app": "c1"}, apply=True)

    def test_a_branch_someone_else_pushed_to_is_left_alone(self):
        gh = mock.Mock()
        gh.call.return_value = {"commits": [{"commit": {"author": {"email": "person@example.com"}}}]}
        self.add("a", "1", "READY")
        it = publish.plan(self.est, {"app": "c1"})[0]["item"]
        res = publish.publish_one(self.est, gh, it)
        self.assertEqual(res["status"], "skipped")

    def test_token_per_owner_and_never_on_a_command_line(self):
        from patchlab_internal.estate import gitops
        with mock.patch.dict(os.environ, {"PATCHLAB_INTERNAL_GITHUB_TOKEN_MIIMAGINELABS": "secret-token",
                                          "PATCHLAB_INTERNAL_GITHUB_TOKEN": ""}):
            env = gitops.auth_env("https://github.com/MIIMAGINELabs/caer")
            self.assertEqual(gitops.auth_env("https://github.com/StreamlyApps/subsovereign"), {})
        self.assertNotIn("secret-token", json.dumps(env))      # base64 in a header, via environment only
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")

    def test_owner_repo(self):
        self.assertEqual(publish.owner_repo(self.est.repos[0]), "Org/app")


if __name__ == "__main__":
    unittest.main()
