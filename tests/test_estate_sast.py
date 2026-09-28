"""Estate code scanning: tool output parsing, fix plans, the brief and the gate."""

import json
import unittest

from patchlab_internal.estate import sast, triage


OPENGREP = {"results": [
    {"check_id": "rules.0.rulesets.opengrep.caer-py-eval-exec", "path": "/src/app/run.py",
     "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "Dynamic  code\n execution",
                                      "lines": "    eval(expr)", "metadata": {"cwe": "CWE-95: x"}}},
    {"check_id": "caer-js-math-random", "path": "/src/web/__tests__/a.test.ts",
     "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "m", "lines": "Math.random()"}},
    {"check_id": "caer-py-weak-hash", "path": "/src/app/h.py",
     "start": {"line": 4}, "extra": {"severity": "WARNING", "message": "md5", "lines": "md5(x)"}}]}

BANDIT = {"results": [
    {"test_id": "B602", "filename": "./svc/x.py", "line_number": 7, "issue_severity": "HIGH",
     "issue_confidence": "HIGH", "issue_text": "shell=True", "code": "6 a\n7 subprocess.call(c, shell=True)\n",
     "issue_cwe": {"id": 78}},
    {"test_id": "B105", "filename": "./svc/y.py", "line_number": 2, "issue_severity": "HIGH",
     "issue_confidence": "LOW", "issue_text": "maybe", "code": "2 p = 'x'\n"}]}

GOSEC = {"Issues": [{"rule_id": "G204", "file": "/src/latticeiq/scanner-agent/main.go", "line": "40-41",
                     "severity": "HIGH", "confidence": "HIGH", "details": "cmd", "code": "exec.Command(x)",
                     "cwe": {"id": "78"}}]}


class ParseTests(unittest.TestCase):
    def test_opengrep(self):
        fs = sast.parse_opengrep(json.dumps(OPENGREP))
        f = fs[0]
        self.assertEqual((f.rule, f.file, f.line, f.severity, f.message), ("caer-py-eval-exec", "app/run.py", 12,
                                                                          "high", "Dynamic code execution"))
        self.assertTrue(f.blocking)
        self.assertFalse(fs[1].blocking)        # test code
        self.assertFalse(fs[2].blocking)        # not high

    def test_bandit_demotes_low_confidence_high(self):
        fs = sast.parse_bandit(json.dumps(BANDIT), "/src/app")
        self.assertEqual([(f.rule, f.severity, f.code) for f in fs],
                         [("B602", "high", "subprocess.call(c, shell=True)"), ("B105", "medium", "p = 'x'")])
        self.assertEqual(fs[0].cwe, "CWE-78")

    def test_gosec(self):
        f = sast.parse_gosec(json.dumps(GOSEC), "/src/latticeiq")[0]
        self.assertEqual((f.file, f.line, f.cwe), ("scanner-agent/main.go", 40, "CWE-78"))

    def test_fingerprint_survives_moved_lines_and_whitespace(self):
        a = sast.Finding("t", "r", "f.py", 10, "high", "m", "eval(x)")
        b = sast.Finding("t", "r", "f.py", 30, "high", "m", "  eval(x)   ")
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, sast.Finding("t", "r", "g.py", 10, "high", "m", "eval(x)").fingerprint)


class PlanTests(unittest.TestCase):
    def test_one_plan_per_rule_and_file(self):
        r = sast.Result(sast.parse_opengrep(json.dumps(OPENGREP)), {"opengrep": "ok"})
        r.findings.append(sast.Finding("opengrep", "caer-py-eval-exec", "app/run.py", 20, "high", "m", "exec(y)"))
        plans = sast.plans(r)
        self.assertEqual(len(plans), 1)
        self.assertEqual(len(plans[0]["fingerprints"]), 2)

    def test_round_trip(self):
        r = sast.Result(sast.parse_opengrep(json.dumps(OPENGREP)), {"opengrep": "ok"})
        back = sast.result_from(r.to_dict())
        self.assertEqual([f.fingerprint for f in back.findings], [f.fingerprint for f in r.findings])
        self.assertTrue(back.complete)
        self.assertFalse(sast.Result([], {"opengrep": "build failed"}).complete)

    def test_suppressions(self):
        patch = "+++ b/x.py\n+    eval(x)  # nosec\n-    old\n+ // eslint-disable-next-line\n+ fine()\n"
        self.assertEqual(len(sast.suppressions_added(patch)), 2)


def _report(regressed=False):
    return {"verdict": "PASS", "targets": [{"verdict": "PASS", "checks": [
        {"name": "unit", "transition": "regressed" if regressed else "still-passing", "before": {"passed": True},
         "after": {"passed": not regressed}}],
        "findings": [{"area": "rollback", "severity": "info", "message": "restored"}]}]}


def _prop(**over):
    p = {"kind": "code", "code_plan": {"fingerprints": ["a", "b"]}, "rescan_complete": True,
         "remaining_findings": [], "introduced_findings": [], "suppressions_added": [],
         "test_files_changed": [], "dependency_files_changed": []}
    p.update(over)
    return p


class GateTests(unittest.TestCase):
    def test_ready(self):
        d = triage.decide(_report(), _prop())
        self.assertEqual(d.verdict, triage.READY, d.summary)
        self.assertIn("code", d.labels)

    def test_still_reported_blocks(self):
        self.assertEqual(triage.decide(_report(), _prop(remaining_findings=["a"])).verdict, triage.BLOCKED)

    def test_suppression_blocks(self):
        self.assertEqual(triage.decide(_report(), _prop(suppressions_added=["# nosec"])).verdict, triage.BLOCKED)

    def test_incomplete_rescan_is_never_a_pass(self):
        self.assertEqual(triage.decide(_report(), _prop(rescan_complete=False)).verdict, triage.INCONCLUSIVE)

    def test_regression_blocks(self):
        self.assertEqual(triage.decide(_report(True), _prop()).verdict, triage.BLOCKED)

    def test_test_edit_needs_review(self):
        self.assertEqual(triage.decide(_report(), _prop(test_files_changed=["a.test.ts"])).verdict, triage.REVIEW)



class GitleaksTests(unittest.TestCase):
    def test_parse_is_redacted_and_high(self):
        text = json.dumps([{"RuleID": "aws-access-token", "File": "/src/app/cfg.py", "StartLine": 3,
                            "Description": "AWS", "Match": "key = REDACTED"}])
        f = sast.parse_gitleaks(text, "/src")[0]
        self.assertEqual((f.file, f.severity, f.cwe, f.code), ("app/cfg.py", "high", "CWE-798", "key = REDACTED"))
        self.assertIn("rotated", f.message)
        self.assertEqual(sast.parse_gitleaks("", "/src"), [])


if __name__ == "__main__":
    unittest.main()
