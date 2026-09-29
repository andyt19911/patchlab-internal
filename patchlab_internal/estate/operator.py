"""The operator agent's tools (DESIGN.md §4.9): what it reads, and the few things it may do.

The agent works from ``status`` alone: a JSON account of the last cycle and of
everything in state/ that still needs something. What it may change goes
through the commands here, each bounded:

- ``retry`` re-runs one step that failed in the last cycle, once per target,
  step and commit, and only for a failure that looks passing (network,
  timeouts, registries). Anything else is PatchLab's to fix, not to retry.
- ``brief`` writes a reviewer brief next to a REVIEW decision. It never changes
  the decision; the gate alone decides.
- ``discover`` lists packages and Dockerfiles in the managed repos that
  estate.toml doesn't cover.
- ``guard`` checks the agent's own change to patchlab-internal before it
  becomes a pull request: it may not touch the gate, publishing, the agents'
  settings or the workflows (PROTECTED).

Nothing here writes to a managed repository.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.request
from pathlib import Path, PurePosixPath

from . import gitops, state
from .manifest import Estate

CYCLES = "cycles"
REVIEW_BRIEF = "review.md"

# Errors worth one more try: the network, a registry or a timeout, not PatchLab.
TRANSIENT = re.compile(
    r"timed? ?out|TimeoutExpired|Connection (reset|refused|aborted)|Temporary failure in name resolution|"
    r"Could not resolve host|RemoteDisconnected|TLS handshake|unexpected EOF|HTTP (429|5\d\d)|"
    r"\b(429|50[0234])\b|rate limit|toomanyrequests|ECONNRESET|ETIMEDOUT|EAI_AGAIN|"
    r"early EOF|RPC failed|no space left on device", re.I)

RETRY_STEPS = ("sync", "health", "propose", "actions", "images")

# The agent's change to patchlab-internal may not touch what judges or limits it.
PROTECTED = (
    re.compile(r"^\.github/"),
    re.compile(r"^patchlab_internal/estate/(triage|publish|operator|gitops|repair)\.py$"),
    re.compile(r"^tests/test_estate_(triage|publish|operator)\.py$"),
    re.compile(r"^(pyproject\.toml|setup\.cfg|setup\.py)$"),
    re.compile(r"(^|/)\.claude/"),
    re.compile(r"(^|/)CLAUDE\.md$"),
)

# Release feeds for PatchLab's pinned scanners (current pins are read from the code).
TOOL_FEEDS = {
    "trivy": "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
    "opengrep": "https://api.github.com/repos/opengrep/opengrep/releases/latest",
    "gitleaks": "https://api.github.com/repos/gitleaks/gitleaks/releases/latest",
    "gosec": "https://api.github.com/repos/securego/gosec/releases/latest",
    "bandit": "https://pypi.org/pypi/bandit/json",
}

PACKAGE_FILES = {"package.json": "npm", "pyproject.toml": "python", "requirements.txt": "python",
                 "go.mod": "go", "Cargo.toml": "cargo", "Package.swift": "swift", "build.gradle": "gradle",
                 "build.gradle.kts": "gradle"}
SKIP_DIRS = re.compile(r"(^|/)(node_modules|vendor|third_party|\.git|dist|build|examples?|fixtures?|"
                       r"testdata|__tests__|tests?|docs?|samples?|[^/]*-next|[^/]*-sample)(/|$)")
DOCKERFILE = re.compile(r"(^|/)(Dockerfile(\.[\w.-]+)?|[\w.-]+\.Dockerfile)$")


# ---------------------------------------------------------------- the cycle record

def record_cycle(estate: Estate, started: dt.datetime, heads: dict[str, str], failures: list[dict],
                 no_propose: bool = False, steps: list[dict] | None = None) -> Path:
    stamp = started.strftime("%Y%m%d-%H%M%S")
    data = {"started": started.isoformat(timespec="seconds"),
            "finished": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "repos": [r.name for r in estate.repos], "heads": heads, "no_propose": no_propose,
            "failures": [{**f, "transient": bool(TRANSIENT.search(f["error"]))} for f in failures],
            "retries": [], "steps": steps or []}
    return state.write_json(estate.state_dir / CYCLES / f"{stamp}.json", data)


def last_cycle(estate: Estate) -> tuple[Path | None, dict | None]:
    d = estate.state_dir / CYCLES
    files = sorted(d.glob("*.json")) if d.is_dir() else []
    return (files[-1], state.read_json(files[-1])) if files else (None, None)


# ---------------------------------------------------------------- status

def _decisions(estate: Estate) -> list[dict]:
    from . import digest
    out = []
    for r in digest.collect(estate):
        for d in r["decisions"]:
            out.append((r["package"].id, d["key"], Path(d["run"]), d["decision"]))
    for it in digest.collect_images(estate):
        for d in it["decisions"]:
            out.append((it["id"], d["key"], Path(d["run"]), d["decision"]))
    for repo in estate.repos:
        run, d = state.latest(estate.state_dir / "workflows" / repo.name, "decision.json")
        if d:
            out.append((repo.name, "pin-actions", run, d))
    rows = []
    for where, key, run, d in out:
        rows.append({"where": where, "key": key, "id": run.resolve().relative_to(estate.state_dir.resolve()).as_posix(),
                     "verdict": d.get("verdict"), "summary": d.get("summary", ""), "labels": d.get("labels", []),
                     "failed_gate": [f"{g['name']}: {g['detail']}" for g in d.get("gate", []) if not g.get("ok")],
                     "has_brief": (run / REVIEW_BRIEF).is_file()})
    return rows


def status(estate: Estate) -> dict:
    """Everything the operator agent acts on, as data."""
    from . import digest
    path, cycle = last_cycle(estate)
    needs: list[dict] = []
    if cycle:
        retried = {(r["target"], r["step"]) for r in cycle.get("retries", [])}
        for f in cycle["failures"]:
            done = (f["target"], f["step"]) in retried
            needs.append({"kind": "failed-step", "target": f["target"], "step": f["step"], "error": f["error"],
                          "next": "already retried once: fix PatchLab or report it" if done
                          else ("retry" if f["transient"] and f["step"] in RETRY_STEPS else "fix PatchLab")})
    for r in digest.collect(estate):
        pkg, h, code = r["package"], r["health"] or {}, r["code"] or {}
        if h.get("status") in ("broken", "error"):
            needs.append({"kind": "health", "target": pkg.id, "status": h["status"], "error": h.get("error"),
                          "failing": h.get("failing", [])[:20]})
        if code and not code.get("complete"):
            needs.append({"kind": "code-scan-incomplete", "target": pkg.id,
                          "tools": {k: v for k, v in code.get("tools", {}).items() if v != "ok"}})
        blocking = [f for f in code.get("findings", []) if f.get("blocking")]
        if blocking and not estate.repair:
            needs.append({"kind": "code-findings-waiting", "target": pkg.id,
                          "why": "no [repair] agent is configured, so these wait for one",
                          "findings": [{k: f.get(k) for k in ("tool", "rule", "file", "line", "message")}
                                       for f in blocking]})
        for nf in r["scan"].get("not_fixable", []):
            needs.append({"kind": "not-fixable", "target": pkg.id, **nf})
    for it in digest.collect_images(estate):
        if (it["scan"] or {}).get("error"):
            needs.append({"kind": "image-scan", "target": it["id"], "error": it["scan"]["error"]})
    decisions = _decisions(estate)
    for d in decisions:
        if d["verdict"] == "REVIEW" and not d["has_brief"]:
            needs.append({"kind": "review-brief", "target": d["where"], "decision": d["id"],
                          "failed_gate": d["failed_gate"], "labels": d["labels"]})
        elif d["verdict"] in ("BLOCKED", "INCONCLUSIVE"):
            needs.append({"kind": "decision-" + d["verdict"].lower(), "target": d["where"], "decision": d["id"],
                          "failed_gate": d["failed_gate"]})
    return {"cycle": {"file": str(path) if path else None, **(cycle or {})}, "repair_configured": bool(estate.repair),
            "publish": estate.publish, "decisions": decisions, "needs": needs,
            "counts": {k: sum(1 for n in needs if n["kind"] == k) for k in sorted({n["kind"] for n in needs})}}


# ---------------------------------------------------------------- retry

def _check_retry(estate: Estate, target: str, step: str) -> tuple[Path, dict]:
    path, cycle = last_cycle(estate)
    if not cycle:
        raise RuntimeError("no cycle has run yet")
    match = [f for f in cycle["failures"] if f["target"] == target and f["step"] == step]
    if not match:
        raise RuntimeError(f"{target} {step} did not fail in the last cycle")
    if any(r["target"] == target and r["step"] == step for r in cycle.get("retries", [])):
        raise RuntimeError(f"{target} {step} was already retried once; a second failure is real")
    if step not in RETRY_STEPS or not match[0]["transient"]:
        raise RuntimeError(f"{target} {step} failed for a reason a retry won't fix: {match[0]['error'][:300]}")
    return path, cycle


def request_retry(estate: Estate, target: str, step: str) -> dict:
    """Queue a retry for the runner to carry out after the agent (the agent holds no repo credentials)."""
    path, cycle = _check_retry(estate, target, step)
    req = {"target": target, "step": step}
    if req not in cycle.setdefault("requested", []):
        cycle["requested"].append(req)
        state.write_json(path, cycle)
    return req


def run_requests(estate: Estate) -> list[dict]:
    _, cycle = last_cycle(estate)
    return [retry(estate, r["target"], r["step"]) for r in (cycle or {}).get("requested", [])
            if not any(x["target"] == r["target"] and x["step"] == r["step"] for x in cycle.get("retries", []))]


def retry(estate: Estate, target: str, step: str) -> dict:
    """Re-run one step that failed in the last cycle, if it failed for a passing reason."""
    from . import cli, pipeline
    path, cycle = _check_retry(estate, target, step)
    outcome: dict = {"target": target, "step": step, "when": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    try:
        with state.exclusive(estate.state_dir):
            if step == "sync":
                heads, errors = pipeline.sync(estate, [target])
                if errors:
                    raise RuntimeError("; ".join(errors.values()))
                outcome["detail"] = f"{target} at {heads[target][:10]}"
            elif step in ("actions", "images"):
                repo = estate.repo(target)
                sha = cycle["heads"].get(target) or cli.gitops_head(estate, repo)
                (cli.run_actions if step == "actions" else cli.run_images)(estate, repo, not cycle.get("no_propose"),
                                                                           sha)
            else:
                pkg = estate.find(target)
                sha = cycle["heads"].get(pkg.repo.name)
                if step == "health":
                    h = pipeline.health(estate, pkg, sha)
                    outcome["detail"] = h.get("status")
                else:
                    pipeline.scan(estate, pkg, sha)
                    pipeline.propose_and_test(estate, pkg)
        outcome["ok"] = True
    except Exception as e:
        outcome.update(ok=False, error=f"{type(e).__name__}: {e}"[-2000:])
    cycle.setdefault("retries", []).append(outcome)
    state.write_json(path, cycle)
    return outcome


# ---------------------------------------------------------------- reviewer briefs

def brief(estate: Estate, decision_id: str, text: str) -> Path:
    """Write the reviewer brief for a REVIEW decision (shown with it); the decision itself never changes."""
    root = estate.state_dir.resolve()
    run = (root / decision_id).resolve()
    if root not in run.parents:
        raise RuntimeError("the decision must be inside the state folder")
    d = state.read_json(run / "decision.json")
    if not d:
        raise RuntimeError(f"no decision at {decision_id}")
    if d.get("verdict") != "REVIEW":
        raise RuntimeError(f"only REVIEW decisions get a brief ({decision_id} is {d.get('verdict')})")
    text = text.strip()
    if not text or len(text) > 8000:
        raise RuntimeError("a brief is 1 to 8000 characters")
    out = run / REVIEW_BRIEF
    out.write_text(text + "\n", encoding="utf-8")
    return out


# ---------------------------------------------------------------- the agent's copy

def import_results(estate: Estate, copy_workdir: Path) -> dict:
    """Take the agent's briefs and retry requests from its copy of the state, and nothing else.

    The agent works on a copy so that nothing it writes there (a decision
    edited to READY, a planted file) reaches the real state; each brief and
    request is re-checked here against the real state."""
    copy_state = Path(copy_workdir) / "state"
    out: dict = {"briefs": [], "requests": [], "refused": []}
    for f in sorted(copy_state.rglob(REVIEW_BRIEF)):
        rel = f.parent.relative_to(copy_state).as_posix()
        try:
            brief(estate, rel, f.read_text(encoding="utf-8", errors="replace"))
            out["briefs"].append(rel)
        except RuntimeError as e:
            out["refused"].append(f"brief {rel}: {e}")
    real_path, _ = last_cycle(estate)
    copy_cycle = state.read_json(copy_state / CYCLES / real_path.name) if real_path else None
    for r in (copy_cycle or {}).get("requested", []):
        try:
            out["requests"].append(request_retry(estate, str(r["target"]), str(r["step"])))
        except (RuntimeError, KeyError, TypeError) as e:
            out["refused"].append(f"retry {r}: {e}")
    return out


# ---------------------------------------------------------------- discover

def discover(estate: Estate) -> list[dict]:
    """Package directories and Dockerfiles in the synced repos that estate.toml doesn't list."""
    found = []
    for repo in estate.repos:
        mirror = estate.repos_dir / f"{repo.name}.git"
        if not mirror.is_dir():
            found.append({"repo": repo.name, "kind": "not-synced"})
            continue
        sha = gitops.head(mirror, repo.branch)
        files = gitops.git("ls-tree", "-r", "--name-only", sha, cwd=mirror).splitlines()
        listed = {p.path.strip("/") or "." for p in repo.packages}
        images = {i.dockerfile for i in repo.images}

        def covered(path: str, ecosystems: set[str] | None = None) -> bool:
            if any(path == k or path.startswith(k + "/") for k in repo.not_managed):
                return True
            # A workspace member inside a listed package of the same ecosystem is that package's.
            return ecosystems is not None and any(
                p.ecosystem in ecosystems and (p.path == "." or path.startswith(p.path.strip("/") + "/"))
                for p in repo.packages)
        dirs: dict[str, set[str]] = {}
        for f in files:
            pure = PurePosixPath(f)
            if pure.name in PACKAGE_FILES and not SKIP_DIRS.search(str(pure.parent) + "/"):
                dirs.setdefault(str(pure.parent), set()).add(PACKAGE_FILES[pure.name])
            if DOCKERFILE.search(f) and f not in images and not SKIP_DIRS.search(f) and not covered(f):
                found.append({"repo": repo.name, "kind": "dockerfile", "path": f, "commit": sha})
        for d, eco in sorted(dirs.items()):
            if d not in listed and not covered(d, eco):
                found.append({"repo": repo.name, "kind": "package", "path": d, "ecosystems": sorted(eco),
                              "commit": sha})
    return found


# ---------------------------------------------------------------- tools

def pinned_tools() -> dict[str, str]:
    from . import images, sast
    return {"trivy": images.TRIVY_IMAGE.rsplit(":", 1)[-1], "opengrep": sast.OPENGREP_VERSION,
            "gitleaks": sast.GITLEAKS_VERSION, "gosec": sast.GOSEC.rsplit("@v", 1)[-1],
            "bandit": sast.BANDIT.split("==", 1)[-1]}


def tool_releases(fetch=None) -> list[dict]:
    """Each pinned scanner's version against its latest release (None when the feed can't be read)."""
    def default_fetch(url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": "patchlab-internal", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    fetch = fetch or default_fetch
    out = []
    for name, pinned in pinned_tools().items():
        try:
            data = fetch(TOOL_FEEDS[name])
            latest = (data.get("info", {}).get("version") if name == "bandit" else data.get("tag_name", "")).lstrip("v")
        except Exception:
            latest = None
        out.append({"tool": name, "pinned": pinned, "latest": latest or None,
                    "behind": bool(latest) and _vkey(latest) > _vkey(pinned)})
    return out


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)[:3])


# ---------------------------------------------------------------- guard

def guard(changed: list[str], old_manifest: str | None = None, new_manifest: str | None = None) -> list[str]:
    """Why the agent's change to patchlab-internal may not become a PR (empty: it may).

    estate.toml may gain packages and images in the repos it already lists. What
    it fetches (repos, mirrors), where it writes, publishing, the [repair] agent,
    code-scanning rules and a package's network access may not change."""
    import tomllib
    problems = [f"{f}: the operator may not change this file" for f in changed
                if any(p.search(f) for p in PROTECTED)]
    if old_manifest is None or new_manifest is None or old_manifest == new_manifest:
        return problems
    try:
        old, new = tomllib.loads(old_manifest), tomllib.loads(new_manifest)
    except tomllib.TOMLDecodeError as e:
        return problems + [f"estate.toml: not valid TOML ({e})"]
    for key in ("estate", "repair", "mirror", "sast"):
        if old.get(key) != new.get(key):
            problems.append(f"estate.toml: the operator may not change [{key}]")

    def repos(d: dict) -> dict:
        return {r.get("name"): r for r in d.get("repo", [])}
    before, after = repos(old), repos(new)
    if {n: (r.get("url"), r.get("branch")) for n, r in before.items()} != \
            {n: (r.get("url"), r.get("branch")) for n, r in after.items()}:
        problems.append("estate.toml: the operator may not add, remove or re-point a repo")
    for name, r in after.items():
        old_pkgs = {p.get("path"): p for p in before.get(name, {}).get("package", [])}
        for pkg in r.get("package", []):
            prev = old_pkgs.get(pkg.get("path"))
            net = pkg.get("check_network", "isolated")
            if net != (prev or {}).get("check_network", "isolated"):
                problems.append(f"estate.toml: {name}/{pkg.get('path')}: the operator may not change check_network")
            if prev is not None and prev != pkg:
                problems.append(f"estate.toml: {name}/{pkg.get('path')}: the operator may add packages, "
                                "not change existing ones")
        for path in set(old_pkgs) - {p.get("path") for p in r.get("package", [])}:
            problems.append(f"estate.toml: {name}/{path}: the operator may not remove a package")
    return problems
