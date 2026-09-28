"""The estate lifecycle: sync -> scan -> propose -> test -> triage -> publish, and health runs."""

from __future__ import annotations

import datetime as dt
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from .. import report as engine_report
from .. import runner
from ..config import Patch
from . import advisories, bridge, fixers, gitops, manifest, npm, repair, sast, state, triage
from .manifest import Estate, Package


def log(msg: str) -> None:
    print(f"{dt.datetime.now():%H:%M:%S} [estate] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- sync

def mirror_path(estate: Estate, repo_name: str) -> Path:
    return estate.repos_dir / f"{repo_name}.git"


def sync(estate: Estate, only: list[str] | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """Fetch every repo and private-dependency mirror.

    Returns (repo -> head commit, name -> error). One unreachable repo never
    stops the others; a failed mirror fails every repo, because packages that
    need it would install stale code."""
    heads, errors = {}, {}
    # Only the private-dependency mirrors the synced repos' packages use.
    wanted = {m for r in estate.repos if not only or r.name in only for p in r.packages for m in p.mirrors}
    for name, spec in estate.mirrors.items():
        if name not in wanted:
            continue
        log(f"mirror {name} <- {spec.url}")
        try:
            gitops.sync_mirror(spec.url, estate.mirrors_dir / f"{name}.git")
        except gitops.GitError as e:
            errors[f"mirror {name}"] = str(e)
    for repo in estate.repos:
        if only and repo.name not in only:
            continue
        log(f"repo {repo.name} <- {repo.url} ({repo.branch})")
        m = mirror_path(estate, repo.name)
        try:
            gitops.sync_mirror(repo.url, m)
            heads[repo.name] = gitops.head(m, repo.branch)
        except gitops.GitError as e:
            errors[repo.name] = str(e)
    return heads, errors


def resolve(estate: Estate, pkg: Package, commit: str | None) -> str:
    m = mirror_path(estate, pkg.repo.name)
    if not (m / "HEAD").is_file():
        raise RuntimeError(f"{pkg.repo.name} is not synced yet: run `estate sync` first")
    if commit:
        return gitops.git("rev-parse", "--verify", f"{commit}^{{commit}}", cwd=m).strip()
    return gitops.head(m, pkg.repo.branch)


# ---------------------------------------------------------------- scan

def scan(estate: Estate, pkg: Package, commit: str | None = None) -> dict:
    sha = resolve(estate, pkg, commit)
    out = {"package": pkg.id, "commit": sha, "ecosystem": pkg.ecosystem,
           "scanned": dt.datetime.now().astimezone().isoformat(timespec="seconds")}
    if pkg.unsupported or pkg.ecosystem not in manifest.SCANNERS:
        out["error"] = f"no scanner for {pkg.ecosystem} yet; advisories not checked"
        return _save_scan(estate, pkg, out)
    checkout = gitops.checkout(mirror_path(estate, pkg.repo.name), sha, estate.workdir / "tmp")
    try:
        with bridge.toolbox(estate, pkg, bridge.new_id("scan"), checkout) as tb:
            if pkg.ecosystem == "npm":
                result = npm.audit(tb)
            else:
                result = advisories.scan(tb, pkg.ecosystem, pkg.install)
        if pkg.ecosystem == "npm":
            direct = npm.direct_dependencies(checkout / pkg.path / "package.json")
            plans, blocked = npm.plan(result, set(direct), estate.ignore)
        else:
            plans, blocked = upgrade_plans(result, estate.ignore)
            out["production_known"] = False
        out.update(scan=result.to_dict(), plans=[p.to_dict() for p in plans],
                   not_fixable=[b.to_dict() for b in blocked], error=result.error)
    finally:
        gitops.remove_checkout(checkout)
    log(f"{pkg.id}: {len(out.get('scan', {}).get('vulnerable', []))} vulnerable package(s), "
        f"{len(out.get('plans', []))} proposal(s) possible")
    return _save_scan(estate, pkg, out)


def upgrade_plans(result: npm.Scan, ignore: dict[str, str]) -> tuple[list[npm.Plan], list[npm.NotFixable]]:
    """One "upgrade" plan per vulnerable dependency (Python, Go, Cargo)."""
    plans, blocked = [], []
    for v in result.vulnerable:
        if v.name in ignore:
            blocked.append(npm.NotFixable(v.name, f"ignored in estate.toml: {ignore[v.name]}",
                                          v.severity, v.advisories))
        elif v.fix == "none" or not v.fix_version:
            blocked.append(npm.NotFixable(v.name, "no fixed version published for every advisory",
                                          v.severity, v.advisories))
        elif all(a.severity == "info" for a in v.advisories):
            blocked.append(npm.NotFixable(v.name, "informational only (unmaintained, unsound or yanked); "
                                          "nothing to upgrade to", v.severity, v.advisories))
        else:
            plans.append(npm.Plan("upgrade", v.name, [v.name], v.advisories, v.severity,
                                  production=False, suggested_version=v.fix_version))
    return plans, blocked


def _save_scan(estate: Estate, pkg: Package, data: dict) -> dict:
    state.write_json(estate.state_dir / pkg.slug / "scan.json", data)
    return data


# ---------------------------------------------------------------- propose

def _plan_from(d: dict) -> npm.Plan:
    return npm.Plan(kind=d["kind"], dependency=d.get("dependency"), covers=d["covers"],
                    advisories=[npm.Advisory(**a) for a in d["advisories"]], severity=d["severity"],
                    production=d["production"], suggested_version=d.get("suggested_version"))


def propose(estate: Estate, pkg: Package, plan: npm.Plan, sha: str, out: Path) -> dict:
    """Build the change in a tool container and capture it as a diff. Nothing is tested here."""
    checkout = gitops.checkout(mirror_path(estate, pkg.repo.name), sha, estate.workdir / "tmp")
    lock_rel = f"{pkg.path}/package-lock.json" if pkg.path != "." else "package-lock.json"
    result: dict = {"package": pkg.id, "commit": sha, "plan": plan.to_dict(), "notes": []}
    try:
        before_lock = json.loads((checkout / lock_rel).read_text(encoding="utf-8"))
        root = bridge.repo_root(pkg)
        with bridge.toolbox(estate, pkg, bridge.new_id("propose"), checkout) as tb:
            before = npm.audit(tb)
            result["audit_before"] = before.to_dict()
            after, chosen = None, None
            if plan.kind == "major":
                current = npm.installed_version(before_lock, plan.dependency) or "0.0.0"
                own = [a.range for v in before.vulnerable if v.name == plan.dependency
                       for a in v.advisories if a.range]
                candidates = npm.candidate_versions(tb, plan.dependency, current, own) if own else []
                if plan.suggested_version and plan.suggested_version not in candidates:
                    candidates.append(plan.suggested_version)
                result["candidates"] = candidates
                for version in candidates[:4]:
                    tb.run(f"git -C {root} checkout -- .", timeout=60)
                    res = tb.run(f"npm install --package-lock-only {npm.QUIET} "
                                 f"'{plan.dependency}@{version}'", timeout=900)
                    if not res.ok:
                        result["notes"].append(f"{plan.dependency}@{version} did not resolve: "
                                               + res.output.strip().splitlines()[-1][:300])
                        continue
                    trial = npm.audit(tb)
                    # Clean means every package the plan covers, not just the one bumped:
                    # a new react-router-dom can still pull in a vulnerable react-router.
                    targeted = {a.id for a in plan.advisories}
                    still = sorted({a.id for v in trial.vulnerable if v.name in plan.covers
                                    for a in v.advisories if a.id in targeted})
                    if still:
                        result["notes"].append(f"{plan.dependency}@{version} leaves advisories: "
                                               + ", ".join(still))
                        continue
                    after, chosen = trial, version
                    break
                if chosen and npm.ships_types(tb, plan.dependency, chosen):
                    direct = npm.direct_dependencies(checkout / pkg.path / "package.json")
                    if f"@types/{plan.dependency}" in direct:
                        result["notes"].append(
                            f"{plan.dependency} {chosen} ships its own type definitions, so "
                            f"@types/{plan.dependency} is no longer used. It is left in place to keep "
                            "this change minimal; remove it separately.")
            else:
                res = tb.run(f"npm audit fix --package-lock-only {npm.QUIET}", timeout=900)
                if res.ok:
                    after, chosen = npm.audit(tb), "in-range"
                elif not tb.run(f"git -C {root} diff --quiet -- {shlex.quote(lock_rel)}", timeout=60).ok:
                    # npm exits non-zero when some advisories need a breaking
                    # change, after fixing the rest. Keep what it fixed; what it
                    # left is recorded as deferred and makes the verdict REVIEW.
                    after, chosen = npm.audit(tb), "in-range"
                    result["partial"] = True
                    result["notes"].append("npm audit fix fixed what it could within the declared "
                                           "ranges; the rest needs a breaking change and a person.")
                else:
                    result["notes"].append("npm audit fix failed: " + res.output.strip()[-300:])
            if after is None:
                result["status"] = "no-candidate"
                return _save_proposal(out, result)
            result["version"] = chosen
            result["audit_after"] = after.to_dict()
            pj_rel = f"{pkg.path}/package.json" if pkg.path != "." else "package.json"
            out.mkdir(parents=True, exist_ok=True)
            tb.copy_out(f"{root}/{pj_rel}", out / "package.npm.json")
            original = (checkout / pj_rel).read_text(encoding="utf-8")
            rewritten = (out / "package.npm.json").read_text(encoding="utf-8")
            try:
                minimal = npm.minimal_manifest_edit(original, rewritten)
            except ValueError as e:
                result["status"] = "no-candidate"
                result["notes"].append(f"package.json change could not be kept minimal: {e}")
                return _save_proposal(out, result)
            if minimal != rewritten:
                (out / "package.npm.json").write_text(minimal, encoding="utf-8")
                tb.box.copy_in(out / "package.npm.json", f"{root}/{pj_rel}")
            (out / "package.npm.json").unlink()
            tb.run(f"git -C {root} diff --binary > /tmp/change.patch", timeout=60)
            tb.run(f"git -C {root} diff --name-only > /tmp/changed.txt", timeout=60)
            out.mkdir(parents=True, exist_ok=True)
            tb.copy_out("/tmp/change.patch", out / "change.patch")
            tb.copy_out("/tmp/changed.txt", out / "changed.txt")
            tb.copy_out(f"{root}/{lock_rel}", out / "package-lock.after.json")
    finally:
        gitops.remove_checkout(checkout)

    changed = [x for x in (out / "changed.txt").read_text().split() if x]
    allowed = {lock_rel, f"{pkg.path}/package.json" if pkg.path != "." else "package.json"}
    result["changed_files"] = changed
    result["unexpected_files"] = [c for c in changed if c not in allowed]
    if not changed:
        result["status"] = "no-change"
        return _save_proposal(out, result)
    after_lock = json.loads((out / "package-lock.after.json").read_text(encoding="utf-8"))
    (out / "package-lock.after.json").unlink()
    allowed_git = tuple(f"git+ssh://git@github.com/{s.url.split('github.com/', 1)[-1]}"
                        for s in estate.mirrors.values())
    result["lock_diff"] = npm.lock_diff(before_lock, after_lock, allowed_git).to_dict()
    b_ids, a_ids = before.advisory_ids(), after.advisory_ids()
    targeted = {a.id for a in plan.advisories}
    result["fixed_advisories"] = sorted(targeted - a_ids)
    remaining = sorted(targeted & a_ids)
    if result.get("partial"):
        result["deferred_advisories"], remaining = remaining, []
    result["remaining_advisories"] = remaining
    result["introduced_advisories"] = sorted(a_ids - b_ids)
    result["diffstat"] = gitops.diff_stat(out / "change.patch")
    result["status"] = "proposed"
    return _save_proposal(out, result)


def _save_proposal(out: Path, result: dict) -> dict:
    state.write_json(out / "proposal.json", result)
    return result


# ---------------------------------------------------------------- test

@dataclass
class TestOutcome:
    report: dict | None
    report_dir: Path | None


def test_change(estate: Estate, pkg: Package, sha: str, patch_file: Path | None, label: str,
                out: Path, run_id: str) -> TestOutcome:
    """One engine run on a fresh checkout: baseline, apply, reinstall, verify,
    roll back, reinstall, verify. ``patch_file`` None = baseline only."""
    checkout = gitops.checkout(mirror_path(estate, pkg.repo.name), sha, estate.workdir / "tmp")
    try:
        cfg = bridge.config_for(estate, pkg, checkout, sha)
        patch = (Patch(kind="source", description=label, files=[patch_file], target=bridge.repo_root(pkg))
                 if patch_file else None)
        opts = runner.Options(out_dir=out, verify_rollback=patch is not None, quiet=False,
                              run_id=run_id, no_patch=patch is None)
        rep = runner.run(cfg, patch, opts)
        engine_report.write_all(rep)
        return TestOutcome(rep.to_dict(), rep.out_dir)
    finally:
        gitops.remove_checkout(checkout)


def propose_and_test(estate: Estate, pkg: Package, plan_key: str | None = None,
                     commit: str | None = None, confirm_failures: bool = True) -> list[dict]:
    """For each fixable advisory group (or just ``plan_key``): build, test, triage."""
    if pkg.unsupported:
        log(f"{pkg.id}: not verified ({pkg.unsupported}); nothing proposed")
        return []
    sha = resolve(estate, pkg, commit)
    scanned = state.read_json(estate.state_dir / pkg.slug / "scan.json")
    if not scanned or scanned.get("commit") != sha:
        scanned = scan(estate, pkg, sha)
    plans = [_plan_from(p) for p in scanned.get("plans", [])]
    if plan_key:
        plans = [p for p in plans if p.key == plan_key or p.dependency == plan_key]
        if not plans:
            raise RuntimeError(f"{pkg.id}: nothing to propose for '{plan_key}' at {sha[:10]} "
                               f"(fixable: {', '.join(_plan_from(p).key for p in scanned.get('plans', [])) or 'none'})")
    results = []
    queue, seen = list(plans), {p.key for p in plans}
    while queue:
        plan = queue.pop(0)
        run_id = bridge.new_id("proposal")
        out = estate.state_dir / pkg.slug / "proposals" / plan.key / run_id
        log(f"{pkg.id}: proposing {plan.title} at {sha[:10]}")
        if pkg.ecosystem == "npm":
            prop = propose(estate, pkg, plan, sha, out)
        else:
            prop = fixers.propose(estate, pkg, plan, sha, out, _save_proposal)
        if prop["status"] != "proposed":
            log(f"{pkg.id}: {plan.key}: {prop['status']}")
            decision = triage.Decision(triage.BLOCKED if prop["status"] == "no-candidate" else triage.READY,
                                       "No safe version could be resolved." if prop["status"] == "no-candidate"
                                       else "Nothing to change: already fixed.", [], notes=prop.get("notes", []))
            state.write_json(out / "decision.json", decision.to_dict())
            results.append({"proposal": prop, "decision": decision.to_dict(), "dir": str(out)})
            continue
        label = (f"{plan.dependency} -> {prop['version']}" if plan.kind in ("major", "upgrade")
                 else f"in-range fixes ({', '.join(plan.covers)})")
        log(f"{pkg.id}: testing {label}")
        first = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs", run_id + "-1")
        confirm = None
        if confirm_failures and first.report and triage.regressions(first.report):
            log(f"{pkg.id}: regressions seen; running once more to separate real failures from flaky ones")
            confirm = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs",
                                  run_id + "-2").report
        decision = triage.decide(first.report, prop, pkg.unsupported, confirm)
        state.write_json(out / "decision.json", decision.to_dict())
        (out / "pr.md").write_text(pr_body(pkg, prop, decision, first), encoding="utf-8")
        if estate.repair and only_regressions_block(decision):
            log(f"{pkg.id}: {plan.key} fixes its advisories but breaks tests; asking the repair agent "
                "to adapt the code")
            adapted = repair_upgrade(estate, pkg, sha, plan, prop, out, first)
            if adapted:
                results.append(adapted)
        log(f"{pkg.id}: {plan.key}: {decision.verdict}. {decision.summary}")
        results.append({"proposal": prop, "decision": decision.to_dict(), "dir": str(out),
                        "report": str(first.report_dir) if first.report_dir else None})
        for extra in follow_up_plans(estate, pkg, sha, prop):
            if extra.key not in seen:
                seen.add(extra.key)
                log(f"{pkg.id}: {extra.title} fixes what {plan.key} left; proposing it too")
                queue.append(extra)
    return results


def only_regressions_block(decision: triage.Decision) -> bool:
    """BLOCKED by real regressions and nothing else: the case code changes can fix."""
    blockers = [g for g in decision.gate if not g.ok and g.kind == "blocker"]
    return (decision.verdict == triage.BLOCKED and bool(blockers)
            and all(g.name == "no regressions" for g in blockers))


def repair_upgrade(estate: Estate, pkg: Package, sha: str, plan: npm.Plan, prop: dict, out: Path,
                   first: "TestOutcome") -> dict | None:
    """An upgrade that fixes advisories but breaks tests: the agent adapts the code
    to it, and upgrade plus adaptation go through the gate together."""
    broken = triage.regressions(first.report)
    targets = [b for b in broken if not b.endswith("passed before, fails after")]
    targets += [b.split(":", 1)[0] for b in broken if b.endswith("passed before, fails after")]
    rdir = out / "adapted"
    excerpts = repair.excerpts_from(first.report_dir, targets, "after") if first.report_dir else {}
    brief = repair.write_upgrade_brief(pkg, sha, prop, targets, excerpts)
    try:
        agent = repair.run_agent(estate, pkg, sha, brief, rdir, base_patch=out / "change.patch")
    except RuntimeError as e:
        log(f"{pkg.id}: repair agent could not run: {e}")
        return None
    if not agent["agent_changed_files"]:
        log(f"{pkg.id}: the repair agent changed nothing")
        return None
    adapted = {**prop, **agent, "repaired_by_agent": True, "broken_by_upgrade": targets,
               "notes": prop.get("notes", []) + agent.get("notes", [])}
    adapted["diffstat"] = gitops.diff_stat(rdir / "change.patch")
    adapted["unexpected_files"] = []      # code changes are the point; the agent-only checks judge them
    state.write_json(rdir / "proposal.json", adapted)
    run_id = bridge.new_id("proposal")
    label = f"{plan.dependency} -> {prop.get('version')} with code adapted"
    outcome = test_change(estate, pkg, sha, rdir / "change.patch", label, rdir / "runs", run_id + "-1")
    confirm = None
    if outcome.report and triage.regressions(outcome.report):
        confirm = test_change(estate, pkg, sha, rdir / "change.patch", label, rdir / "runs", run_id + "-2").report
    decision = triage.decide(outcome.report, adapted, pkg.unsupported, confirm)
    state.write_json(rdir / "decision.json", decision.to_dict())
    (rdir / "pr.md").write_text(pr_body(pkg, adapted, decision, outcome), encoding="utf-8")
    log(f"{pkg.id}: {plan.key} with adapted code: {decision.verdict}. {decision.summary}")
    return {"proposal": adapted, "decision": decision.to_dict(), "dir": str(rdir),
            "report": str(outcome.report_dir) if outcome.report_dir else None}


def follow_up_plans(estate: Estate, pkg: Package, sha: str, prop: dict) -> list[npm.Plan]:
    """Major upgrades for what a partial in-range fix left behind.

    npm's audit of the committed lockfile can call a fix in-range that only a
    major upgrade reaches; once the in-range fixes are applied, the re-audit
    names the major. Those become proposals of their own, tested separately."""
    deferred = set(prop.get("deferred_advisories", []))
    if pkg.ecosystem != "npm" or not deferred or not prop.get("audit_after"):
        return []
    after = npm.scan_from_dict(prop["audit_after"])
    after.vulnerable = [v for v in after.vulnerable if {a.id for a in v.advisories} & deferred]
    pj_rel = f"{pkg.path}/package.json" if pkg.path != "." else "package.json"
    manifest_json = gitops.git("show", f"{sha}:{pj_rel}", cwd=mirror_path(estate, pkg.repo.name))
    data = json.loads(manifest_json)
    direct = {n for sec in ("dependencies", "devDependencies", "optionalDependencies")
              for n in data.get(sec, {})}
    plans, _ = npm.plan(after, direct, estate.ignore)
    return [p for p in plans if p.kind == "major"]


# ---------------------------------------------------------------- repair

def repair_and_test(estate: Estate, pkg: Package, only: list[str] | None = None,
                    commit: str | None = None, confirm_failures: bool = True) -> dict:
    """Hand the package's failing tests to the [repair] agent, then test and triage its change."""
    if estate.repair is None:
        raise RuntimeError("no [repair] agent in estate.toml")
    if pkg.unsupported:
        raise RuntimeError(f"{pkg.id} is not verified here ({pkg.unsupported})")
    sha = resolve(estate, pkg, commit)
    failing, h = repair.latest_failures(estate, pkg, sha)
    if h is None or h.get("commit") != sha:
        log(f"{pkg.id}: no health run at {sha[:10]} yet; running one")
        h = health(estate, pkg, sha)
        failing = list(h.get("failing", []))
    targets = [t for t in failing if not only or any(o in t for o in only)]
    if not targets:
        raise RuntimeError(f"{pkg.id}: nothing failing at {sha[:10]}" + (" matches that" if only else ""))
    run_id = bridge.new_id("repair")
    key = "failing-tests" if not only else re.sub(r"[^A-Za-z0-9_.-]+", "-", "-".join(only))[:60]
    out = estate.state_dir / pkg.slug / "repairs" / key / run_id
    brief = repair.write_brief(pkg, sha, targets, repair.failure_excerpts(h, targets))
    log(f"{pkg.id}: asking the repair agent to fix {len(targets)} failing test(s)")
    prop = {"kind": "repair", "package": pkg.id, "commit": sha, "targets": targets,
            "plan": {"kind": "repair", "title": f"fix {len(targets)} failing test(s)", "key": key}}
    prop.update(repair.run_agent(estate, pkg, sha, brief, out))
    if not prop["changed_files"]:
        prop["status"] = "no-change"
        decision = triage.Decision(triage.BLOCKED, "The agent made no change.", [], ["repair"],
                                   notes=prop["notes"])
        state.write_json(out / "proposal.json", prop)
        state.write_json(out / "decision.json", decision.to_dict())
        return {"proposal": prop, "decision": decision.to_dict(), "dir": str(out)}
    prop["status"] = "proposed"
    state.write_json(out / "proposal.json", prop)
    label = f"repair: {len(targets)} failing test(s)"
    first = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs", run_id + "-1")
    confirm = None
    if confirm_failures and first.report and triage.regressions(first.report):
        confirm = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs", run_id + "-2").report
    decision = triage.decide(first.report, prop, pkg.unsupported, confirm)
    state.write_json(out / "decision.json", decision.to_dict())
    (out / "pr.md").write_text(repair_pr_body(pkg, prop, decision), encoding="utf-8")
    log(f"{pkg.id}: repair: {decision.verdict}. {decision.summary}")
    return {"proposal": prop, "decision": decision.to_dict(), "dir": str(out),
            "report": str(first.report_dir) if first.report_dir else None}


def repaired_already(estate: Estate, pkg: Package, h: dict) -> bool:
    """A repair was already tried for this commit and these failures (whatever it
    concluded), so the nightly cycle doesn't pay for the same attempt twice."""
    base = estate.state_dir / pkg.slug / "repairs"
    if not base.is_dir():
        return False
    for prop in base.glob("*/*/proposal.json"):
        p = state.read_json(prop) or {}
        if p.get("commit") == h.get("commit") and set(p.get("targets", [])) == set(h.get("failing", [])):
            return True
    return False


def repair_pr_body(pkg: Package, prop: dict, decision: triage.Decision) -> str:
    L = [f"# Fix {len(prop['targets'])} failing test(s) in {pkg.id}", "",
         f"**PatchLab Internal verdict: {decision.verdict}.** {decision.summary}", "",
         "Written by a coding agent from the brief below, then tested by PatchLab Internal: the "
         "package's checks ran before and after the change, and again after rolling it back.", "",
         "## Tests that were failing", ""] + [f"- `{t}`" for t in prop["targets"]]
    L += ["", "## What changed", ""] + [f"- `{x}`" for x in prop.get("diffstat", [])]
    L += ["", "## Gate", "", "| Check | Result | Detail |", "|---|---|---|"]
    for g in decision.gate:
        L.append(f"| {g.name} | {'✅' if g.ok else ('⚠️' if g.kind == 'review' else '❌')} | {g.detail} |")
    if decision.notes:
        L += ["", "## Notes", ""] + [f"- {n}" for n in decision.notes]
    if pkg.not_covered:
        L += ["", "## What this does not prove", ""] + [f"- {x}" for x in pkg.not_covered]
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- code scanning

def code_scan(estate: Estate, pkg: Package, commit: str | None = None) -> dict:
    sha = resolve(estate, pkg, commit)
    log(f"{pkg.id}: code scan at {sha[:10]}")
    data = sast.save(estate, pkg, sha, sast.scan(estate, pkg, sha))
    log(f"{pkg.id}: code scan: {data['counts']['high']} high, {data['counts']['medium']} medium; "
        f"{len(data['plans'])} to fix" + ("" if data["complete"] else f" (incomplete: {data['tools']})"))
    return data


def code_fix_and_test(estate: Estate, pkg: Package, key: str | None = None, commit: str | None = None,
                      confirm_failures: bool = True) -> list[dict]:
    """For each blocking finding group (or just ``key``): the repair agent fixes it,
    then test, re-scan and triage."""
    if estate.repair is None:
        raise RuntimeError("no [repair] agent in estate.toml")
    sha = resolve(estate, pkg, commit)
    scanned = state.read_json(estate.state_dir / pkg.slug / "sast.json")
    if not scanned or scanned.get("commit") != sha:
        scanned = code_scan(estate, pkg, sha)
    todo = [p for p in scanned["plans"] if not key or p["key"] == key]
    if key and not todo:
        raise RuntimeError(f"{pkg.id}: no finding group '{key}' at {sha[:10]}")
    before = sast.result_from(scanned)
    results = []
    for plan in todo:
        run_id = bridge.new_id("code")
        out = estate.state_dir / pkg.slug / "code-fixes" / plan["key"] / run_id
        log(f"{pkg.id}: asking the repair agent to fix {plan['title']}")
        prop = {"kind": "code", "package": pkg.id, "commit": sha, "targets": [], "code_plan": plan,
                "plan": {"kind": "code", "key": plan["key"], "title": f"fix {plan['title']}"}}
        try:
            prop.update(repair.run_agent(estate, pkg, sha, sast.write_brief(pkg, sha, plan), out))
        except RuntimeError as e:
            log(f"{pkg.id}: repair agent could not run: {e}")
            break
        if plan["tool"] == "gitleaks":
            prop["notes"].append("Removing a credential from the code does not revoke it, and it stays in git "
                                 "history: whoever owns it must rotate it.")
        if not prop["changed_files"]:
            fp = prop.get("agent_verdict", "").strip()
            decision = triage.Decision(
                triage.REVIEW if fp.startswith("FALSE_POSITIVE") else triage.BLOCKED,
                ("The agent judged this a false positive and changed nothing; a person decides: " + fp[15:].strip()
                 if fp.startswith("FALSE_POSITIVE") else "The agent made no change."),
                [], ["security", "code", "false-positive" if fp else "agent-written"], notes=prop["notes"])
            state.write_json(out / "proposal.json", {**prop, "status": "no-change"})
            state.write_json(out / "decision.json", decision.to_dict())
            results.append({"proposal": prop, "decision": decision.to_dict(), "dir": str(out)})
            continue
        prop["status"] = "proposed"
        prop["suppressions_added"] = sast.suppressions_added((out / "change.patch").read_text(errors="replace"))
        after = sast.scan(estate, pkg, sha, out / "change.patch")
        prop["rescan"] = after.to_dict()
        prop["rescan_complete"] = after.complete and before.complete
        after_fps = {f.fingerprint for f in after.findings}
        before_fps = {f.fingerprint for f in before.findings}
        prop["remaining_findings"] = [fp for fp in plan["fingerprints"] if fp in after_fps]
        prop["introduced_findings"] = [f"{f.rule} {f.file}:{f.line}" for f in after.findings
                                       if f.fingerprint not in before_fps and f.severity in ("high", "medium")]
        state.write_json(out / "proposal.json", prop)
        label = f"code fix: {plan['rule']} in {plan['file']}"
        first = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs", run_id + "-1")
        confirm = None
        if confirm_failures and first.report and triage.regressions(first.report):
            confirm = test_change(estate, pkg, sha, out / "change.patch", label, out / "runs", run_id + "-2").report
        decision = triage.decide(first.report, prop, pkg.unsupported, confirm)
        state.write_json(out / "decision.json", decision.to_dict())
        (out / "pr.md").write_text(code_pr_body(pkg, prop, decision), encoding="utf-8")
        log(f"{pkg.id}: {plan['key']}: {decision.verdict}. {decision.summary}")
        results.append({"proposal": prop, "decision": decision.to_dict(), "dir": str(out),
                        "report": str(first.report_dir) if first.report_dir else None})
    return results


def code_fixed_already(estate: Estate, pkg: Package, sha: str, key: str) -> bool:
    for p in (estate.state_dir / pkg.slug / "code-fixes" / key).glob("*/proposal.json"):
        if (state.read_json(p) or {}).get("commit") == sha:
            return True
    return False


def code_pr_body(pkg: Package, prop: dict, decision: triage.Decision) -> str:
    plan = prop["code_plan"]
    f0 = plan["findings"][0]
    L = [f"# Fix {plan['rule']} in {plan['file']}", "",
         f"**PatchLab Internal verdict: {decision.verdict}.** {decision.summary}", "",
         f"Before: {plan['tool']} flags {len(plan['findings'])} location(s) in `{plan['file']}`"
         + (f" ({f0['cwe']})" if f0["cwe"] else "") + f": {f0['message']}", "",
         "After: the re-scan no longer reports them" if not prop.get("remaining_findings")
         else "After: the re-scan still reports some of them.", "",
         "Written by a coding agent, then tested by PatchLab Internal: the package's checks ran before and "
         "after the change and again after rolling it back, and the code was scanned again.", "",
         "## Locations", ""] + [f"- line {f['line']}: `{f['code'].strip()[:120]}`" for f in plan["findings"]]
    L += ["", "## What changed", ""] + [f"- `{x}`" for x in prop.get("diffstat", [])]
    L += ["", "## Gate", "", "| Check | Result | Detail |", "|---|---|---|"]
    for g in decision.gate:
        L.append(f"| {g.name} | {'✅' if g.ok else ('⚠️' if g.kind == 'review' else '❌')} | {g.detail} |")
    if decision.notes:
        L += ["", "## Notes", ""] + [f"- {n}" for n in decision.notes]
    if pkg.not_covered:
        L += ["", "## What this does not prove", ""] + [f"- {x}" for x in pkg.not_covered]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- health

def health(estate: Estate, pkg: Package, commit: str | None = None, recheck: bool = True) -> dict:
    """Run the package's checks on the current code and compare with the last health run."""
    hdir = estate.state_dir / pkg.slug / "health"
    run_id = bridge.new_id("health")
    if pkg.unsupported:
        summary = {"package": pkg.id, "status": "not-verified", "reason": pkg.unsupported,
                   "when": dt.datetime.now().astimezone().isoformat(timespec="seconds")}
        state.write_json(hdir / run_id / "summary.json", summary)
        return summary
    sha = resolve(estate, pkg, commit)
    _, prev = state.latest(hdir, "summary.json")
    log(f"{pkg.id}: health run at {sha[:10]}")
    outcome = test_change(estate, pkg, sha, None, "health", hdir / run_id / "runs", run_id)
    summary = summarise_health(pkg, sha, outcome.report, prev)
    if recheck and summary["newly_failing"]:
        log(f"{pkg.id}: {len(summary['newly_failing'])} new failure(s); re-running once to rule out flakiness")
        again = test_change(estate, pkg, sha, None, "health recheck", hdir / run_id / "runs", run_id + "-r")
        still = set(_failing(again.report))
        summary["flaky"] = sorted(t for t in summary["newly_failing"] if t not in still)
        summary["newly_failing"] = sorted(t for t in summary["newly_failing"] if t in still)
    if prev and prev.get("commit") and summary["newly_failing"]:
        summary["commits_since_last_pass"] = gitops.commits_between(
            mirror_path(estate, pkg.repo.name), prev["commit"], sha)
    summary["report"] = str(outcome.report_dir) if outcome.report_dir else None
    summary["status"] = ("error" if summary.get("error") else "broken" if summary["newly_failing"]
                         else "failing" if summary["failing"] else "healthy")
    state.write_json(hdir / run_id / "summary.json", summary)
    log(f"{pkg.id}: health {summary['status']}: {len(summary['failing'])} failing, "
        f"{len(summary['newly_failing'])} new, {len(summary.get('flaky', []))} flaky")
    return summary


def _failing(report: dict | None) -> list[str]:
    t = triage._target(report) if report else None
    out = []
    for c in (t or {}).get("checks", []):
        before = c.get("before") or {}
        cases = [k for k, v in before.get("cases", {}).items() if v == "fail"]
        if cases:
            out += [f"{c['name']}: {k}" for k in cases]
        elif before and not before.get("passed"):
            out.append(c["name"])
    return sorted(out)


def summarise_health(pkg: Package, sha: str, report: dict | None, prev: dict | None) -> dict:
    t = triage._target(report) if report else None
    errors = [f["message"] for f in (t or {}).get("findings", []) if f["severity"] == "error"]
    failing = _failing(report)
    passing_cases = 0
    for c in (t or {}).get("checks", []):
        passing_cases += sum(1 for v in (c.get("before") or {}).get("cases", {}).values() if v == "pass")
    prev_failing = set((prev or {}).get("failing", []))
    return {
        "package": pkg.id, "commit": sha,
        "when": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "error": "; ".join(errors) if errors or t is None else None,
        "failing": failing,
        "newly_failing": sorted(set(failing) - prev_failing) if prev else [],
        "fixed_since_last": sorted(prev_failing - set(failing)) if prev else [],
        "passing_tests": passing_cases,
        "previous_commit": (prev or {}).get("commit"),
    }


# ---------------------------------------------------------------- PR body

def pr_body(pkg: Package, prop: dict, decision: triage.Decision, outcome: TestOutcome) -> str:
    plan = prop["plan"]
    title = (f"Upgrade {plan['dependency']} to {prop.get('version')}" if plan["kind"] in ("major", "upgrade")
             else f"Apply in-range security fixes ({', '.join(plan['covers'])})")
    L = [f"# {title} in {pkg.id}", "",
         f"**PatchLab Internal verdict: {decision.verdict}.** {decision.summary}", ""]
    if decision.verdict == triage.REVIEW:
        L += ["> [!WARNING]", "> Needs a person to look before merging: "
              + "; ".join(f"{g.name}: {', '.join(g.details[:5])}" for g in decision.gate if not g.ok), ""]
    L += ["## Why", ""]
    for a in plan["advisories"]:
        link = f"[{a['id']}]({a['url']})" if a.get("url") else a["id"]
        L.append(f"- **{a['severity']}** {a['title']} ({link}, affects `{a.get('range') or '?'}`)")
    L += ["", "## What changed", ""] + [f"- `{x}`" for x in prop.get("diffstat", [])]
    ld = prop.get("lock_diff", {})
    if ld.get("upgraded") or ld.get("added") or ld.get("removed"):
        L += ["", "<details><summary>Lockfile changes</summary>", "", "| Package | Before | After |", "|---|---|---|"]
        L += [f"| {u['name']} | {u['from']} | {u['to']} |" for u in ld.get("upgraded", [])]
        L += [f"| {u['name']} | — | {u['version']} |" for u in ld.get("added", [])]
        L += [f"| {u['name']} | {u['version']} | — |" for u in ld.get("removed", [])]
        L += ["", "</details>"]
    L += ["", "## Gate", "", "| Check | Result | Detail |", "|---|---|---|"]
    for g in decision.gate:
        L.append(f"| {g.name} | {'✅' if g.ok else ('⚠️' if g.kind == 'review' else '❌')} | {g.detail} |")
    if decision.notes:
        L += ["", "## Notes", ""] + [f"- {n}" for n in decision.notes]
    if pkg.not_covered:
        L += ["", "## What this does not prove", ""] + [f"- {x}" for x in pkg.not_covered]
    L += ["", "## How this was tested", "",
          f"On a fresh checkout of `{prop['commit'][:12]}` in a disposable container "
          f"(`{pkg.image}`), with {', '.join(s.name for s in pkg.sidecars) or 'no'} sidecars and no "
          "credentials: dependencies installed, every check run, the change applied and reinstalled, "
          "every check run again, then the change reverted, reinstalled and checked a third time.",
          "", "The full report is attached to this PR's run in PatchLab Internal.", ""]
    if outcome.report_dir:
        L.append(f"_Report: `{outcome.report_dir}/report.html`_")
    return "\n".join(L) + "\n"
