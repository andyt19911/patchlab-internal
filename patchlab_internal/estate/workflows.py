"""CI supply chain: GitHub Actions workflows.

Scan (every workflow in .github/workflows):
- ``unpinned-action``: ``uses: owner/repo@v4`` follows a tag its owner can move,
  so a compromised action runs in CI with the repo's token and secrets. Pinning
  to the commit the tag points to now changes nothing today and stops that.
- ``script-injection``: ``${{ github.event... }}`` text an outsider controls
  (an issue title, a branch name) expanded straight into a ``run:`` script.
- ``pr-target-checkout``: ``pull_request_target`` (which has secrets) checking out
  the pull request's own code.
- ``no-permissions``: no ``permissions:`` block, so the token gets the repo's
  default, often write access.

Fix. Pinning is done here, deterministically: each tag or branch is resolved
with ``git ls-remote`` against the action's repository, and the line becomes
``uses: owner/repo@<sha> # v4``. The gate checks every pin resolves to what the
tag names now and that nothing but ``uses:`` lines changed. The other findings
are code changes; they go to the repair agent through the code-scanning path.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

USES = re.compile(r"^(?P<lead>\s*(?:-\s+)?uses:\s*)(?P<q>['\"]?)(?P<ref>[^'\"\s#]+)(?P=q)(?P<rest>\s*(?:#.*)?)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
# Event fields an outsider writes (GitHub's own list of untrusted input).
UNTRUSTED = re.compile(r"\$\{\{\s*github\.(?:event\.(?:issue\.title|issue\.body|pull_request\.title|"
                       r"pull_request\.body|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|"
                       r"commits\.[^}]*\.message|head_commit\.message|head_commit\.author\.(?:email|name)|"
                       r"pull_request\.head\.ref|pull_request\.head\.label|pull_request\.head\.repo\.default_branch)"
                       r"|head_ref)\s*\}\}")


def parse_uses(ref: str) -> tuple[str, str, str] | None:
    """(action repo "owner/name", path within it, version ref), or None for local and docker actions."""
    if ref.startswith(("./", "docker://")) or "@" not in ref:
        return None
    name, version = ref.rsplit("@", 1)
    parts = name.split("/")
    if len(parts) < 2:
        return None
    return "/".join(parts[:2]), "/".join(parts[2:]), version


def scan_text(path: str, text: str) -> list[dict]:
    out = []
    lines = text.splitlines()
    has_perms = any(re.match(r"^permissions:", line) for line in lines)
    prt = any(re.search(r"\bpull_request_target\b", line) for line in lines)
    in_run = None
    for i, line in enumerate(lines, 1):
        m = USES.match(line)
        if m:
            u = parse_uses(m["ref"])
            if u and not SHA.match(u[2]):
                out.append({"rule": "unpinned-action", "file": path, "line": i, "severity": "medium",
                            "message": f"{u[0]} is used by the tag or branch '{u[2]}', which its owner can move; "
                                       "pin it to a commit.", "code": line.strip()})
            if prt and u and u[0] == "actions/checkout":
                window = "\n".join(lines[i:i + 6])
                if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", window):
                    out.append({"rule": "pr-target-checkout", "file": path, "line": i, "severity": "high",
                                "message": "pull_request_target runs with secrets and checks out the pull "
                                           "request's own code, so anyone who opens a PR can run code with them.",
                                "code": line.strip()})
        indent = len(line) - len(line.lstrip())
        if re.match(r"^\s*(?:-\s+)?run:\s*", line):
            in_run = indent
            body = line
        elif in_run is not None and (not line.strip() or indent > in_run):
            body = line
        else:
            in_run, body = None, ""
        if body and UNTRUSTED.search(body):
            out.append({"rule": "script-injection", "file": path, "line": i, "severity": "high",
                        "message": "Text an outsider controls is expanded into a shell script. Pass it through "
                                   "an environment variable instead.", "code": line.strip()})
    if not has_perms:
        out.append({"rule": "no-permissions", "file": path, "line": 1, "severity": "low",
                    "message": "No top-level permissions block: the workflow token gets the repository's default "
                               "permissions.", "code": ""})
    return out


def scan_checkout(checkout: Path) -> list[dict]:
    out = []
    for wf in sorted((checkout / ".github" / "workflows").glob("*.y*ml")):
        out += scan_text(wf.relative_to(checkout).as_posix(), wf.read_text(encoding="utf-8"))
    return out


def ls_remote(repo: str, version: str) -> str | None:
    """The commit ``version`` (a tag or branch) of github.com/``repo`` names now."""
    url = f"https://github.com/{repo}"
    res = subprocess.run(["git", "ls-remote", url, f"refs/tags/{version}", f"refs/tags/{version}^{{}}",
                          f"refs/heads/{version}"], capture_output=True, text=True, timeout=60,
                         env={"GIT_TERMINAL_PROMPT": "0", **_env()})
    if res.returncode != 0:
        return None
    refs = dict(reversed(line.split("\t")) for line in res.stdout.splitlines() if "\t" in line)
    # An annotated tag's own object is not a commit; its peeled ^{} entry is.
    return (refs.get(f"refs/tags/{version}^{{}}") or refs.get(f"refs/tags/{version}")
            or refs.get(f"refs/heads/{version}"))


def _env() -> dict:
    import os
    return {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "HTTPS_PROXY", "https_proxy",
                                                         "NO_PROXY", "no_proxy", "GIT_SSL_CAINFO",
                                                         "SSL_CERT_FILE")}


def pin_text(text: str, resolve) -> tuple[str, list[dict]]:
    """Pin every unpinned ``uses:`` line. ``resolve(repo, version)`` returns a sha or None."""
    out, pins = [], []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        m = USES.match(body)
        u = parse_uses(m["ref"]) if m else None
        if u and not SHA.match(u[2]):
            sha = resolve(u[0], u[2])
            pins.append({"action": u[0], "version": u[2], "sha": sha})
            if sha:
                name = m["ref"].rsplit("@", 1)[0]
                comment = m["rest"].strip()
                tail = f" # {u[2]}" + (f" {comment.lstrip('#').strip()}" if comment else "")
                body = f"{m['lead']}{m['q']}{name}@{sha}{m['q']}{tail}"
        out.append(body + line[len(line.rstrip("\r\n")):])
    return "".join(out), pins


# ---------------------------------------------------------------- proposal

def propose(estate, repo, sha: str) -> dict | None:
    """Pin every action in the repo's workflows; decide. None when there is nothing to pin."""
    from . import bridge, gitops, state, triage
    checkout = gitops.checkout(estate.repos_dir / f"{repo.name}.git", sha, estate.workdir / "tmp")
    cache: dict = {}

    def resolve(action, version):
        if (action, version) not in cache:
            cache[(action, version)] = ls_remote(action, version)
        return cache[(action, version)]
    try:
        pins, files = [], []
        for wf in sorted((checkout / ".github" / "workflows").glob("*.y*ml")):
            text, p = pin_text(wf.read_text(encoding="utf-8"), resolve)
            if p:
                pins += [{**x, "file": wf.relative_to(checkout).as_posix()} for x in p]
                wf.write_text(text, encoding="utf-8")
                files.append(wf.relative_to(checkout).as_posix())
        if not pins:
            return None
        out = estate.state_dir / "workflows" / repo.name / bridge.new_id("pin")
        out.mkdir(parents=True, exist_ok=True)
        gitops.git("diff", "--output", str(out / "change.patch"), cwd=checkout)
        diff = gitops.git("diff", "-U0", cwd=checkout)
        # Every changed line must still be a uses: line naming the same action.
        stray = [line for line in diff.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))
                 and not USES.match(line[1:])]
        after = scan_checkout(checkout)
    finally:
        gitops.remove_checkout(checkout)
    unresolved = [f"{p['action']}@{p['version']} ({p['file']})" for p in pins if not p["sha"]]
    still = [f"{f['file']}:{f['line']}" for f in after if f["rule"] == "unpinned-action"]
    G = triage.GateItem
    gate = [G("every action resolved", not unresolved, f"{len(pins) - len(unresolved)} of {len(pins)} uses: lines "
              "pinned to the commit their tag names now", unresolved),
            G("nothing left unpinned", not still, "a re-scan finds no unpinned action" if not still
              else "still unpinned", still),
            G("only uses: lines changed", not stray, ", ".join(files), stray[:10])]
    failed = [g for g in gate if not g.ok]
    verdict = triage.BLOCKED if failed else triage.READY
    summary = ("Tested and safe to review: each action is pinned to the commit its tag points to today, so CI "
               "runs exactly what it runs now." if not failed else
               "Not proposed: " + "; ".join(f"{g.name} ({g.detail})" for g in failed) + ".")
    decision = triage.Decision(verdict, summary, gate, ["security", "ci"],
                               ["Dependabot or `estate actions --propose` moves the pins when the actions "
                                "release; the comment keeps the version readable."])
    prop = {"kind": "actions", "repo": repo.name, "commit": sha, "pins": pins, "changed_files": files,
            "plan": {"kind": "actions", "key": "pin-actions", "title": f"pin {len(pins)} GitHub Actions uses"}}
    state.write_json(out / "proposal.json", prop)
    state.write_json(out / "decision.json", decision.to_dict())
    body = [f"## Pin GitHub Actions to commits in {repo.name}", "", f"**{decision.verdict}.** {decision.summary}",
            "", "Before: workflows use actions by tag (`@v4`). Whoever controls the action's repository can move "
            "the tag, and CI would run the new code with this repository's token and secrets.", "",
            "After: each `uses:` names the commit the tag points to today, with the tag kept as a comment.", "",
            "| Action | Tag | Commit |", "|---|---|---|"]
    seen = set()
    for p in pins:
        if (p["action"], p["version"]) not in seen:
            seen.add((p["action"], p["version"]))
            body.append(f"| {p['action']} | {p['version']} | `{(p['sha'] or 'unresolved')[:12]}` |")
    (out / "pr.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    return {"proposal": prop, "decision": decision.to_dict(), "dir": str(out)}


def latest_scan(estate, repo, sha: str) -> dict:
    from . import gitops, state
    checkout = gitops.checkout(estate.repos_dir / f"{repo.name}.git", sha, estate.workdir / "tmp")
    try:
        findings = scan_checkout(checkout)
    finally:
        gitops.remove_checkout(checkout)
    data = {"repo": repo.name, "commit": sha, "findings": findings}
    state.write_json(estate.state_dir / "workflows" / repo.name / "scan.json", data)
    return data
