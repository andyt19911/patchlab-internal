"""Repair: hand a failing test to a coding agent, and put its change through the same gate as any update.

The flow, per package:

1. The latest health run names the failing tests (``failing`` in its summary).
2. A brief is written: the tests, how they fail (from the health run's logs),
   how to run them, and the rules (fix the cause; never skip, weaken or delete
   a test).
3. The agent ([repair] in estate.toml) runs in its own tool container with a
   copy of the checkout. Only the credentials [repair] names are passed to it,
   from the runner's environment. Its edits are captured as a diff.
4. The diff is tested exactly like a dependency update: baseline, apply,
   verify, roll back, verify, in the package's sandbox with its services.
5. The gate decides. READY needs every targeted test to go from failing to
   passing, nothing else to regress, the rollback to restore the failure, and
   no test file to be touched; a change to tests or dependency manifests is
   REVIEW, so a person always sees an agent's edit to what judges it.

Nothing here writes to a managed repository; publishing is M4.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shlex
from pathlib import Path

from . import bridge, gitops, state, triage
from .manifest import Estate, Package

BRIEF_PATH = "/tmp/patchlab-brief.md"

# Paths that hold tests or decide how they run. An agent editing these could
# make a test pass without fixing anything, so such a change needs a person.
TEST_PATH = re.compile(
    r"(^|/)(__tests__|tests?|spec|testdata|fixtures?)/|"
    r"\.(test|spec)\.[cm]?[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.(py|go)$|"
    r"(^|/)(vitest|jest|playwright|pytest|karma)\.config\.|(^|/)(conftest\.py|pytest\.ini|tox\.ini|setup\.cfg)$")
DEP_MANIFEST = re.compile(r"(^|/)(package(-lock)?\.json|requirements[^/]*\.txt|pyproject\.toml|go\.(mod|sum)|"
                          r"Cargo\.(toml|lock)|pnpm-lock\.yaml|yarn\.lock)$")


def latest_failures(estate: Estate, pkg: Package, sha: str) -> tuple[list[str], dict | None]:
    _, h = state.latest(estate.state_dir / pkg.slug / "health", "summary.json")
    if not h or h.get("commit") != sha:
        return [], h
    return list(h.get("failing", [])), h


def failure_excerpts(health: dict, targets: list[str], lines: int = 40) -> dict[str, str]:
    """For each target test, the lines of its check's log around its name (or the log's tail)."""
    out: dict[str, str] = {}
    report_dir = Path(health.get("report") or "")
    rep = state.read_json(report_dir / "report.json") or {}
    t = triage._target(rep) or {}
    checks = {c["name"]: c for c in t.get("checks", [])}
    for target in targets:
        check_name, _, case = target.partition(": ")
        c = checks.get(check_name, {})
        before = c.get("before") or {}
        text = ""
        log = before.get("log_file")
        if log and (report_dir / log).is_file():
            raw = (report_dir / log).read_text(encoding="utf-8", errors="replace")
            raw = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            # Vitest and pytest print a failure summary block with the test's last words.
            key = case.split(" > ")[-1].strip() if case else check_name
            hits = [i for i, line in enumerate(raw.splitlines()) if key and key[:60] in line]
            body = raw.splitlines()
            if hits:
                i = hits[-1]
                text = "\n".join(body[max(0, i - 5): i + lines])
            else:
                text = "\n".join(body[-lines:])
        else:
            text = "\n".join(before.get("tail") or [])
        out[target] = text.strip()
    return out


def write_brief(pkg: Package, sha: str, targets: list[str], excerpts: dict[str, str]) -> str:
    checks = {c.name: c for c in pkg.checks}
    L = [f"# Make these failing tests pass in {pkg.id}", "",
         f"Repository {pkg.repo.url}, commit {sha[:12]}. The package is `{pkg.path}` in this checkout "
         "(your working directory is the repository root).", "",
         "## The failing tests", ""]
    for t in targets:
        check = checks.get(t.partition(": ")[0])
        L += [f"### {t}", ""]
        if check:
            L += [f"Run by the `{check.name}` check: `{check.run}` (from `{pkg.path}`).", ""]
        if excerpts.get(t):
            L += ["```", excerpts[t][-6000:], "```", ""]
    L += ["## Rules", "",
          "- Find why each test fails and fix the cause. If the test is right, fix the code; if the test "
          "depends on something its setup never provides, fix the setup.",
          "- Never skip, delete, weaken or loosen an assertion to make a test pass. A change to any test "
          "file will be shown to a person before it can merge.",
          "- Change as little as possible, and nothing unrelated. Do not add or upgrade dependencies.",
          "- Follow the repository's CLAUDE.md and contributing rules if it has them.",
          "- You cannot run the full suite here (its database and services are not in this container). "
          "PatchLab runs it after you finish, before and after your change, and rolls it back to check "
          "the failure returns.",
          "- When done, stop. Do not commit; the change is taken from the working tree.",
          ""]
    L += ["## Environment the checks run with", ""]
    L += [f"- `{k}={v}`" for k, v in pkg.env.items()] or ["- (none beyond the image defaults)"]
    L += [""]
    if pkg.sidecars:
        L += ["Services: " + ", ".join(f"`{s.name}` ({s.image})" for s in pkg.sidecars), ""]
    return "\n".join(L)


def run_agent(estate: Estate, pkg: Package, sha: str, brief: str, out: Path) -> dict:
    """Run the agent on a fresh checkout; returns what it changed."""
    agent = estate.repair
    missing = [n for n in agent.env if not os.environ.get(n)]
    if missing:
        raise RuntimeError(f"[repair] needs {', '.join(missing)} in the runner's environment")
    checkout = gitops.checkout(estate.repos_dir / f"{pkg.repo.name}.git", sha, estate.workdir / "tmp")
    result: dict = {"notes": []}
    try:
        (out).mkdir(parents=True, exist_ok=True)
        (out / "brief.md").write_text(brief, encoding="utf-8")
        with bridge.toolbox(estate, pkg, bridge.new_id("repair"), checkout, image=agent.image,
                            setup=agent.setup, extra_env={n: None for n in agent.env}) as tb:
            tb.box.copy_in(out / "brief.md", BRIEF_PATH)
            root = bridge.repo_root(pkg)
            started = dt.datetime.now()
            res = tb.run(f"cd {shlex.quote(root)} && {agent.command}", timeout=agent.timeout, workdir="/")
            result["agent_exit"] = res.exit_code
            result["agent_timed_out"] = res.timed_out
            result["agent_seconds"] = round((dt.datetime.now() - started).total_seconds())
            (out / "agent.log").write_text(res.output[-200_000:], encoding="utf-8")
            if not res.ok:
                result["notes"].append("the agent exited with an error; its output is in agent.log")
            # Anything the agent committed is folded back into the working tree diff.
            tb.run(f"git -C {root} reset --soft {sha} 2>/dev/null; git -C {root} add -A && "
                   f"git -C {root} diff --cached --binary {sha} > /tmp/change.patch && "
                   f"git -C {root} diff --cached --name-only {sha} > /tmp/changed.txt", timeout=120, workdir="/")
            tb.copy_out("/tmp/change.patch", out / "change.patch")
            tb.copy_out("/tmp/changed.txt", out / "changed.txt")
    finally:
        gitops.remove_checkout(checkout)
    changed = [x for x in (out / "changed.txt").read_text().split() if x] if (out / "changed.txt").is_file() else []
    result["changed_files"] = changed
    result["test_files_changed"] = [c for c in changed if TEST_PATH.search(c)]
    result["dependency_files_changed"] = [c for c in changed if DEP_MANIFEST.search(c)]
    result["diffstat"] = gitops.diff_stat(out / "change.patch") if changed else []
    return result


def fixed_targets(report: dict | None, targets: list[str]) -> tuple[list[str], list[str]]:
    """Which targeted failures pass after the change, and which do not."""
    t = triage._target(report) if report else None
    fixed = set()
    for c in (t or {}).get("checks", []):
        fixed |= {f"{c['name']}: {case}" for case in c.get("case_fixes", [])}
        if c.get("transition") == "fixed":
            fixed.add(c["name"])
    return sorted(x for x in targets if x in fixed), sorted(x for x in targets if x not in fixed)
