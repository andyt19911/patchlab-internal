"""Estate CI workflows: finding unpinned actions and script injection, and pinning."""

import textwrap
import unittest

from patchlab_internal.estate import workflows

WF = textwrap.dedent("""\
    on: [pull_request_target, push]
    jobs:
      test:
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - uses: "github/codeql-action/init@v3"  # scan
          - uses: ./local-action
          - uses: docker://alpine:3
          - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567 # v4
          - name: greet
            run: |
              echo "hello"
              echo "${{ github.event.issue.title }}"
          - run: echo ${{ github.sha }}
    """)


class ScanTests(unittest.TestCase):
    def test_findings(self):
        fs = workflows.scan_text("ci.yml", WF)
        rules = sorted((f["rule"], f["line"]) for f in fs)
        self.assertEqual(rules, [("no-permissions", 1), ("pr-target-checkout", 5), ("script-injection", 15),
                                 ("unpinned-action", 5), ("unpinned-action", 8)])

    def test_permissions_block_silences_that_finding(self):
        fs = workflows.scan_text("ci.yml", "permissions:\n  contents: read\njobs: {}\n")
        self.assertEqual(fs, [])


class PinTests(unittest.TestCase):
    def test_pins_and_keeps_comments(self):
        calls = []

        def resolve(repo, version):
            calls.append((repo, version))
            return {"actions/checkout": "a" * 40}.get(repo)
        text, pins = workflows.pin_text(WF, resolve)
        self.assertIn(f"- uses: actions/checkout@{'a' * 40} # v4\n", text)
        # unresolved stays as it was, and is reported
        self.assertIn('uses: "github/codeql-action/init@v3"  # scan', text)
        self.assertEqual(calls, [("actions/checkout", "v4"), ("github/codeql-action", "v3")])
        self.assertEqual([p["sha"] for p in pins], ["a" * 40, None])
        again, more = workflows.pin_text(text, resolve)
        self.assertEqual(len(more), 1)          # only the unresolved one is tried again

    def test_parse_uses(self):
        self.assertEqual(workflows.parse_uses("github/codeql-action/init@v3"),
                         ("github/codeql-action", "init", "v3"))
        self.assertIsNone(workflows.parse_uses("./x"))


class PermissionsTests(unittest.TestCase):
    def test_added_before_jobs(self):
        text, changed, writes = workflows.add_permissions("on: push\njobs:\n  a:\n    steps: []\n")
        self.assertTrue(changed)
        self.assertIn("permissions:\n  contents: read\n\njobs:", text)
        self.assertEqual(writes, [])

    def test_existing_block_is_kept_and_writers_are_flagged(self):
        self.assertFalse(workflows.add_permissions("permissions: {}\njobs: {}\n")[1])
        _, _, writes = workflows.add_permissions("jobs:\n  a:\n    steps:\n      - run: git push origin x\n")
        self.assertEqual(writes, ["git push"])


if __name__ == "__main__":
    unittest.main()
