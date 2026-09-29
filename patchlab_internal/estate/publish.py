"""Publish: turn READY and REVIEW decisions into draft pull requests (M4).

Off unless both hold: ``[estate] publish = "draft-pr"`` in estate.toml, and a
token for the repo's owner on the runner (gitops.token_for). ``estate publish``
without ``--apply`` only prints and records what it would do.

What it does, per publishable decision:

- Only decisions tested on the branch's current head are published. When the
  branch has moved, the next cycle re-tests first; nothing stale is proposed.
- The change goes on its own branch, ``patchlab/<package>/<key>``, as one
  commit on the tested commit, authored by PatchLab Internal.
- A draft PR is opened against the repo's branch, with the decision's pr.md as
  its body; REVIEW ones say so in the title. When the PR exists and the patch
  changed, the branch is replaced and the body updated.
- It only ever writes to branches under ``patchlab/``, and only when the
  branch's commits are all PatchLab's: a branch someone else pushed to is left
  alone and reported.
- It never merges, approves, or marks a PR ready. At most ``max_prs`` new PRs a
  run (default 5), so a bad day can't flood a repo.

The token reaches git through GIT_CONFIG_* environment variables (an HTTP
header), never a command line or a URL, and never a sandbox.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import gitops, state
from .manifest import Estate, Repo

TOKEN_ENV = gitops.TOKEN_ENV
BRANCH_PREFIX = "patchlab/"
AUTHOR = ("PatchLab Internal", "patchlab-internal@users.noreply.github.com")
PUBLISHABLE = ("READY", "REVIEW")


@dataclass
class Item:
    repo: Repo
    key: str               # stable per change: <package-slug>/<plan key>
    commit: str            # the commit it was tested on
    title: str
    verdict: str
    patch: Path
    body: Path | None
    labels: list[str]

    @property
    def branch(self) -> str:
        return BRANCH_PREFIX + re.sub(r"[^A-Za-z0-9_./-]+", "-", self.key).strip("-./")[:120]

    @property
    def patch_hash(self) -> str:
        return hashlib.sha256(self.patch.read_bytes()).hexdigest()[:16]


def owner_repo(repo: Repo) -> str:
    m = re.match(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", repo.url)
    if not m:
        raise ValueError(f"{repo.name}: only github.com repositories can get pull requests ({repo.url})")
    return m.group(1)


# ---------------------------------------------------------------- what to publish

def _latest_runs(base: Path) -> list[Path]:
    """The newest run directory of each proposal key under ``base``/<key>/<run>."""
    out = []
    if base.is_dir():
        for key in sorted(p for p in base.iterdir() if p.is_dir()):
            run, _ = state.latest(key, "decision.json")
            if run is not None:
                # An upgrade the repair agent adapted supersedes the blocked one.
                out.append(run / "adapted" if (run / "adapted" / "decision.json").is_file() else run)
    return out


def _item(repo: Repo, key: str, run: Path) -> Item | None:
    d = state.read_json(run / "decision.json") or {}
    p = state.read_json(run / "proposal.json") or {}
    patch = run / "change.patch"
    if d.get("verdict") not in PUBLISHABLE or not patch.is_file() or not patch.stat().st_size:
        return None
    title = (p.get("plan") or {}).get("title") or key
    return Item(repo, key, p.get("commit", ""), title, d["verdict"], patch,
                run / "pr.md" if (run / "pr.md").is_file() else None, list(d.get("labels", [])))


def candidates(estate: Estate) -> list[Item]:
    from . import images
    items = []
    for repo in estate.repos:
        for pkg in repo.packages:
            pdir = estate.state_dir / pkg.slug
            for kind in ("proposals", "repairs", "code-fixes"):
                for run in _latest_runs(pdir / kind):
                    key = run.parent.name if run.name != "adapted" else run.parent.parent.name
                    it = _item(repo, f"{pkg.slug}/{key}", run)
                    if it:
                        items.append(it)
        for image in repo.images:
            idir = images.image_dir(estate, repo, image)
            for run in _latest_runs(idir / "proposals"):
                it = _item(repo, f"{idir.name}/{run.parent.name}", run)
                if it:
                    items.append(it)
        run, _ = state.latest(estate.state_dir / "workflows" / repo.name, "decision.json")
        if run is not None:
            it = _item(repo, f"{repo.name}/pin-actions", run)
            if it:
                items.append(it)
    return items


def plan(estate: Estate, heads: dict[str, str]) -> list[dict]:
    """What a publish would do, without doing it."""
    published = state.read_json(estate.state_dir / "published.json", {})
    out = []
    for it in candidates(estate):
        head = heads.get(it.repo.name)
        prev = published.get(it.branch, {})
        if head and it.commit != head:
            action, why = "skip", f"tested on {it.commit[:10]}; {it.repo.branch} is now at {head[:10]}"
        elif prev.get("patch") == it.patch_hash:
            action, why = "skip", f"already published as {prev.get('url', 'a PR')}"
        else:
            action, why = ("update" if prev else "open"), it.verdict
        out.append({"repo": it.repo.name, "branch": it.branch, "title": it.title, "verdict": it.verdict,
                    "action": action, "why": why, "item": it})
    return out


# ---------------------------------------------------------------- doing it

class GitHub:
    def __init__(self, token: str, api: str = "https://api.github.com"):
        self.token, self.api = token, api

    def call(self, method: str, path: str, body: dict | None = None):
        req = urllib.request.Request(self.api + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28",
                                              "User-Agent": "patchlab-internal"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                text = r.read().decode()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub {method} {path}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}")


def _run_git(args: list[str], cwd: Path, env: dict) -> str:
    import subprocess
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=600,
                         env={**os.environ, **env})
    if res.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {res.stderr.strip()[-300:]}")
    return res.stdout


def branch_is_ours(gh: GitHub, slug: str, branch: str, base: str) -> bool | None:
    """None when the branch doesn't exist; else whether every commit on it past the
    base was authored by PatchLab."""
    try:
        cmp = gh.call("GET", f"/repos/{slug}/compare/{base}...{urllib.request.quote(branch, safe='')}")
    except RuntimeError as e:
        if "HTTP 404" in str(e):
            return None
        raise
    return all((c.get("commit", {}).get("author") or {}).get("email") == AUTHOR[1]
               for c in cmp.get("commits", []))


def publish_one(estate: Estate, gh: GitHub, it: Item) -> dict:
    slug = owner_repo(it.repo)
    ours = branch_is_ours(gh, slug, it.branch, it.repo.branch)
    if ours is False:
        return {"status": "skipped", "why": f"{it.branch} has commits PatchLab didn't make; left alone"}
    checkout = gitops.checkout(estate.repos_dir / f"{it.repo.name}.git", it.commit, estate.workdir / "tmp")
    try:
        env = gitops.auth_env(it.repo.url)
        _run_git(["apply", "--index", str(it.patch)], checkout, env)
        _run_git(["-c", f"user.name={AUTHOR[0]}", "-c", f"user.email={AUTHOR[1]}", "commit", "-q",
                  "-m", it.title, "-m", f"Tested by PatchLab Internal on {it.commit[:12]}: {it.verdict}."],
                 checkout, env)
        # Force is safe here: the branch is PatchLab's own (checked above).
        _run_git(["push", "--force", f"https://github.com/{slug}.git", f"HEAD:refs/heads/{it.branch}"],
                 checkout, env)
    finally:
        gitops.remove_checkout(checkout)
    title = ("[needs review] " if it.verdict == "REVIEW" else "") + it.title
    body = (it.body.read_text(encoding="utf-8") if it.body else it.title)[:60000]
    body += "\n\n---\n_Opened by PatchLab Internal. It never merges; a person does._\n"
    owner = slug.split("/")[0]
    existing = gh.call("GET", f"/repos/{slug}/pulls?state=open&head={owner}:{urllib.request.quote(it.branch)}")
    if existing:
        pr = gh.call("PATCH", f"/repos/{slug}/pulls/{existing[0]['number']}", {"title": title, "body": body})
    else:
        pr = gh.call("POST", f"/repos/{slug}/pulls", {"title": title, "body": body, "head": it.branch,
                                                      "base": it.repo.branch, "draft": True})
    labels = sorted(set(it.labels) | {"patchlab"})
    try:
        gh.call("POST", f"/repos/{slug}/issues/{pr['number']}/labels", {"labels": labels})
    except RuntimeError:
        pass   # labels are a convenience; the title and body carry the verdict
    return {"status": "updated" if existing else "opened", "url": pr["html_url"], "number": pr["number"]}


def run(estate: Estate, heads: dict[str, str], apply: bool, max_prs: int = 5) -> list[dict]:
    steps = plan(estate, heads)
    if not apply:
        return steps
    if estate.publish != "draft-pr":
        raise RuntimeError('publishing is off: set [estate] publish = "draft-pr" in estate.toml')
    missing = sorted({r.name for r in estate.repos if not gitops.token_for(r.url)})
    if missing:
        raise RuntimeError(f"publishing needs {TOKEN_ENV} (or {TOKEN_ENV}_<OWNER>) in the runner's "
                           f"environment; none covers {', '.join(missing)}")
    published = state.read_json(estate.state_dir / "published.json", {})
    opened = 0
    for s in steps:
        if s["action"] == "skip":
            continue
        if s["action"] == "open" and opened >= max_prs:
            s.update(action="skip", why=f"limit of {max_prs} new PRs a run reached")
            continue
        it = s.pop("item")
        try:
            res = publish_one(estate, GitHub(gitops.token_for(it.repo.url)), it)
        except (RuntimeError, ValueError, gitops.GitError) as e:
            res = {"status": "failed", "why": str(e)}
        s["result"] = res
        if res["status"] in ("opened", "updated"):
            opened += res["status"] == "opened"
            published[it.branch] = {"url": res["url"], "patch": it.patch_hash, "commit": it.commit}
            state.write_json(estate.state_dir / "published.json", published)
    return steps
