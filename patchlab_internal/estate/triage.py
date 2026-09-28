"""Triage: turn a tested proposal into a decision, through a gate that fails closed.

A proposal becomes a pull request only when every gate item is green. Any item
that could not be evaluated counts as red, never as a pass: a missing report,
an unparsed test result or an audit that didn't run blocks the change.

Decisions
  READY         every gate item passed; a draft PR may be opened.
  REVIEW        tests and audits are clean, but something needs a person's eyes
                first (a new install script, a package from outside the registry).
                A draft PR may be opened, flagged at the top.
  BLOCKED       the change breaks something or does not fix what it set out to.
                No PR; the digest names what broke and why.
  INCONCLUSIVE  the test could not complete, or a failure did not reproduce
                (flaky). No PR; retried on the next cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field

READY, REVIEW, BLOCKED, INCONCLUSIVE = "READY", "REVIEW", "BLOCKED", "INCONCLUSIVE"
PUBLISHABLE = (READY, REVIEW)


@dataclass
class GateItem:
    name: str
    ok: bool
    detail: str = ""
    details: list[str] = field(default_factory=list)
    # "blocker" items make a change BLOCKED, "review" items make it REVIEW,
    # "inconclusive" items make it INCONCLUSIVE.
    kind: str = "blocker"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Decision:
    verdict: str
    summary: str
    gate: list[GateItem]
    labels: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "summary": self.summary, "labels": self.labels,
                "notes": self.notes, "gate": [g.to_dict() for g in self.gate]}


def _target(report: dict) -> dict | None:
    targets = report.get("targets") or []
    return targets[0] if len(targets) == 1 else None


def regressions(report: dict) -> list[str]:
    """Checks and tests that passed before the change and fail (or vanished) after it."""
    t = _target(report)
    out = []
    for c in (t or {}).get("checks", []):
        if c["transition"] == "regressed":
            out.append(f"{c['name']}: passed before, fails after")
        out += [f"{c['name']}: {case}" for case in c.get("case_regressions", [])]
    return out


def gate_for(report: dict | None, proposal: dict, unsupported: str | None = None) -> list[GateItem]:
    g: list[GateItem] = []
    t = _target(report) if report else None

    # 1. The test itself completed.
    if t is None:
        g.append(GateItem("tested", False, "no test report", kind="inconclusive"))
        return g
    if report.get("verdict") == "ERROR" or t.get("verdict") == "ERROR":
        errs = [f["message"] for f in t.get("findings", []) if f["severity"] == "error"]
        g.append(GateItem("tested", False, "the test could not complete", errs, kind="inconclusive"))
        return g
    g.append(GateItem("tested", True, f"{len(t.get('checks', []))} check(s) ran before and after the change"))

    # 2. Nothing that passed before fails after.
    regs = regressions(report)
    patch_failed = [f["message"] for f in t.get("findings", [])
                    if f["severity"] == "fail" and f["area"] in ("patch", "install")]
    g.append(GateItem("no regressions", not regs and not patch_failed,
                      "every check and test that passed before still passes" if not (regs or patch_failed)
                      else f"{len(regs) + len(patch_failed)} regression(s)", patch_failed + regs))

    # 3. Every check produced results in both phases, and no test quietly stopped running.
    missing = [c["name"] for c in t.get("checks", []) if c["transition"] == "missing"]
    skipped = [f"{c['name']}: {case}" for c in t.get("checks", []) for case in c.get("case_now_skipped", [])]
    unparsed = [f"{c['name']} ({ph}): {c[ph]['note']}" for c in t.get("checks", []) for ph in ("before", "after")
                if c.get(ph) and c[ph].get("note")]
    g.append(GateItem("no tests lost", not (missing or skipped or unparsed),
                      "every check and test ran in both phases" if not (missing or skipped or unparsed)
                      else "some checks or tests did not run", missing + skipped + unparsed))

    # 4. The back-out plan works.
    fs = t.get("findings", [])
    rolled = any(f["area"] == "rollback" and f["severity"] == "info" for f in fs)
    rb_fail = [f["message"] for f in fs if f["area"] == "rollback" and f["severity"] != "info"]
    g.append(GateItem("rollback verified", rolled and not rb_fail,
                      "reverting the change restores every baseline check" if rolled and not rb_fail
                      else "rollback not verified", rb_fail))

    if proposal.get("kind") == "repair":
        g += _repair_items(report, proposal)
        if unsupported:
            g.append(GateItem("platform coverage", False, f"not verified: {unsupported}", kind="review"))
        return g

    # 5-6. The advisories are gone and none were introduced.
    remaining = proposal.get("remaining_advisories", [])
    introduced = proposal.get("introduced_advisories", [])
    audited = proposal.get("audit_after") is not None and not proposal.get("audit_after", {}).get("error")
    if proposal.get("partial") and not proposal.get("fixed_advisories"):
        remaining = remaining or ["npm reported a partial fix but nothing it targeted was fixed"]
    g.append(GateItem("advisories fixed", audited and not remaining,
                      (f"{len(proposal.get('fixed_advisories', []))} advisory(ies) no longer reported"
                       if audited and not remaining else
                       "re-audit did not run" if not audited else "still reported after the change"),
                      remaining))
    g.append(GateItem("no new advisories", audited and not introduced,
                      "the re-audit reports nothing new" if audited and not introduced
                      else "re-audit did not run" if not audited else "the change brings in new advisories",
                      introduced))

    deferred = proposal.get("deferred_advisories", [])
    if deferred:
        g.append(GateItem("partial fix", False, f"{len(deferred)} advisory(ies) need a breaking change "
                          "and are left for a person", deferred, kind="review"))

    if proposal.get("repaired_by_agent"):
        g += [item for item in _repair_items(report, {**proposal, "targets": []})
              if item.name != "targets fixed"]

    # 7. The change is only what it claims to be.
    stray = proposal.get("unexpected_files", [])
    g.append(GateItem("change scope", not stray, "only the manifest and lockfile changed" if not stray
                      else "the proposer changed files it should not have", stray))

    # 8. Supply chain: things a test run cannot judge.
    ld = proposal.get("lock_diff", {})
    flags = ([f"new install script: {x}" for x in ld.get("new_install_scripts", [])] +
             [f"not from the npm registry: {x}" for x in ld.get("unusual_sources", [])] +
             [f"no integrity hash: {x}" for x in ld.get("missing_integrity", [])])
    g.append(GateItem("supply chain", not flags, "no new install scripts or unusual sources" if not flags
                      else "needs a person to look", flags, kind="review"))
    new_pkgs = ld.get("new_packages", [])
    if new_pkgs:
        g.append(GateItem("new packages", False, f"{len(new_pkgs)} package(s) not previously in the tree",
                          new_pkgs, kind="review"))

    if unsupported:
        g.append(GateItem("platform coverage", False, f"not verified: {unsupported}", kind="review"))
    return g


def _repair_items(report: dict, proposal: dict) -> list[GateItem]:
    from .repair import fixed_targets
    g = []
    targets = proposal.get("targets", [])
    fixed, not_fixed = fixed_targets(report, targets)
    g.append(GateItem("targets fixed", bool(targets) and not not_fixed,
                      f"{len(fixed)} of {len(targets)} failing test(s) now pass" if targets
                      else "no failing test was targeted", not_fixed))
    tests = proposal.get("test_files_changed", [])
    g.append(GateItem("tests untouched", not tests, "no test or test configuration changed" if not tests
                      else "the change edits tests or their configuration; a person must confirm it "
                           "fixes the cause rather than the test", tests, kind="review"))
    deps = proposal.get("dependency_files_changed", [])
    if deps:
        g.append(GateItem("dependencies untouched", False, "the change edits dependency manifests",
                          deps, kind="review"))
    return g


def decide(report: dict | None, proposal: dict, unsupported: str | None = None,
           confirm: dict | None = None) -> Decision:
    """``confirm`` is a second run of the same change, made when the first one
    showed regressions: failures present in both are real, the rest flaky."""
    gate = gate_for(report, proposal, unsupported)
    labels = ["repair", "agent-written"] if proposal.get("kind") == "repair" else ["security"]
    plan = proposal.get("plan", {})
    if plan.get("kind") == "major" or proposal.get("major"):
        labels.append("breaking-risk")
    notes = list(proposal.get("notes", []))
    t = _target(report) if report else None
    if t:
        pre = [f"{c['name']}: {case}" for c in t.get("checks", []) for case in c.get("case_still_failing", [])]
        pre += [c["name"] for c in t.get("checks", []) if c["transition"] == "still-failing"
                and not c.get("case_still_failing")]
        if pre:
            notes.append(f"{len(pre)} check(s)/test(s) already failed before the change and still do; "
                         "they are not caused by it: " + "; ".join(pre[:10]))

    if confirm is not None:
        first, second = set(regressions(report)), set(regressions(confirm))
        flaky = sorted(first ^ second)
        if flaky and not (first & second):
            for item in gate:
                if item.name == "no regressions":
                    item.ok, item.kind = False, "inconclusive"
                    item.detail = "failures did not reproduce on a second run (flaky)"
                    item.details = flaky
        elif flaky:
            notes.append("Some failures did not reproduce on a second run: " + "; ".join(flaky[:10]))

    failed = [g for g in gate if not g.ok]
    if any(g.kind == "inconclusive" for g in failed):
        verdict = INCONCLUSIVE
    elif any(g.kind == "blocker" for g in failed):
        verdict = BLOCKED
    elif failed:
        verdict = REVIEW
    else:
        verdict = READY
    summary = {
        READY: ("Tested and safe to review: the failing tests now pass, nothing regressed, rollback verified."
                if proposal.get("kind") == "repair" else
                "Tested and safe to review: nothing regressed, rollback verified, advisories fixed."),
        REVIEW: "The checks pass, but a person needs to look first: "
                + "; ".join(g.name for g in failed) + ".",
        BLOCKED: "Not proposed: " + "; ".join(f"{g.name} ({g.detail})" for g in failed if g.kind == "blocker") + ".",
        INCONCLUSIVE: "Could not be decided: " + "; ".join(f"{g.name} ({g.detail})" for g in failed
                                                          if g.kind == "inconclusive") + ".",
    }[verdict]
    return Decision(verdict, summary, gate, labels, notes)
