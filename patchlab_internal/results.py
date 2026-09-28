"""Parse per-test results (TAP, JUnit XML) so regressions can be reported per test case."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

PASS, FAIL, SKIP = "pass", "fail", "skip"

_TAP_LINE = re.compile(r"^(not ok|ok)\b\s*(\d+)?\s*(?:-\s*)?(.*?)\s*(?:#\s*(SKIP|TODO)\b.*)?$",
                       re.IGNORECASE)
_TAP_PLAN = re.compile(r"^1\.\.(\d+)")


def parse_tap(text: str) -> dict[str, str]:
    """Return {test name: pass|fail|skip}. Planned tests that never ran count as failures."""
    cases: dict[str, str] = {}
    planned = None
    seen = 0
    for raw in text.splitlines():
        line = raw.strip()
        plan = _TAP_PLAN.match(line)
        if plan:
            planned = int(plan.group(1))
            continue
        m = _TAP_LINE.match(line)
        if not m:
            continue
        seen += 1
        ok_word, num, desc, directive = m.groups()
        name = desc or f"test {num or seen}"
        if name in cases:
            name = f"{name} (#{num or seen})"
        if directive and directive.upper() == "SKIP":
            status = SKIP
        elif directive and directive.upper() == "TODO":
            status = SKIP  # TODO tests are expected to fail and must not gate a patch
        else:
            status = PASS if ok_word.lower() == "ok" else FAIL
        cases[name] = status
    if planned is not None and seen < planned:
        for i in range(seen + 1, planned + 1):
            cases[f"test {i} (planned but never ran)"] = FAIL
    return cases


_NUNIT_STATUS = {"success": PASS, "passed": PASS, "failure": FAIL, "failed": FAIL, "error": FAIL,
                 "ignored": SKIP, "skipped": SKIP, "inconclusive": SKIP, "notrunnable": SKIP}


def parse_junit(xml: str | bytes) -> dict[str, str]:
    """Parse JUnit XML, or NUnit 2/3 XML (what Pester 3.x/4.x write by default)."""
    cases: dict[str, str] = {}
    # Bytes let the parser honour the XML encoding declaration (Windows tools
    # often write UTF-16 or a BOM).
    root = ET.fromstring(xml if isinstance(xml, bytes) else xml.lstrip("\ufeff"))
    for tc in root.iter("test-case"):
        name = tc.get("fullname") or tc.get("name", "?")
        result = (tc.get("result") or "").lower()
        if tc.get("executed", "True").lower() == "false":
            result = "skipped"
        cases[name] = _NUNIT_STATUS.get(result, FAIL if tc.get("success", "").lower() == "false" else PASS)
    for tc in root.iter("testcase"):
        cls = tc.get("classname", "")
        name = f"{cls}.{tc.get('name', '?')}" if cls else tc.get("name", "?")
        if tc.find("failure") is not None or tc.find("error") is not None:
            status = FAIL
        elif tc.find("skipped") is not None:
            status = SKIP
        else:
            status = PASS
        cases[name] = status
    return cases
