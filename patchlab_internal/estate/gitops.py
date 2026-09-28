"""Host-side git: keep bare mirrors of each repo and private dependency, and check out exact commits.

These commands run on the runner host with the host's own git credentials.
Nothing here runs inside a sandbox, and no credential is ever copied into one:
sandboxes only receive the fetched bare repositories.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class GitError(Exception):
    pass


def git(*args: str, cwd: Path | None = None, timeout: int = 600, auth_url: str | None = None) -> str:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=timeout,
                              env={**_env(), **auth_env(auth_url)})
    except FileNotFoundError:
        raise GitError("git not found on PATH") from None
    except subprocess.TimeoutExpired:
        raise GitError(f"git {args[0]} timed out") from None
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])} failed: "
                       f"{proc.stderr.decode(errors='replace').strip()[-500:]}")
    return proc.stdout.decode(errors="replace")


def _env() -> dict:
    import os
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"   # fail, never hang waiting for a password
    return env


TOKEN_ENV = "PATCHLAB_INTERNAL_GITHUB_TOKEN"


def token_for(url: str | None) -> str | None:
    """The runner's GitHub token for ``url``'s owner: PATCHLAB_INTERNAL_GITHUB_TOKEN_<OWNER>
    (a fine-grained token covers one owner), else PATCHLAB_INTERNAL_GITHUB_TOKEN. None
    means the host's own git credentials are used."""
    import os
    import re
    m = re.match(r"https://github\.com/([^/]+)/", url or "")
    if not m:
        return None
    owner = re.sub(r"[^A-Z0-9]", "_", m.group(1).upper())
    return os.environ.get(f"{TOKEN_ENV}_{owner}") or os.environ.get(TOKEN_ENV) or None


def auth_env(url: str | None) -> dict:
    """The token for ``url`` as an HTTP header, through git's environment config:
    never on a command line, in a URL or in a repository's config."""
    import base64
    token = token_for(url)
    if not token:
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}


def sync_mirror(url: str, dest: Path) -> None:
    """Create or refresh a bare mirror of ``url`` at ``dest``."""
    if (dest / "HEAD").is_file():
        git("remote", "set-url", "origin", url, cwd=dest)
        git("fetch", "--prune", "--tags", "origin", "+refs/heads/*:refs/heads/*", cwd=dest, timeout=1800,
            auth_url=url)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".partial")
    shutil.rmtree(tmp, ignore_errors=True)
    git("clone", "--quiet", "--mirror", url, str(tmp), timeout=1800, auth_url=url)
    tmp.rename(dest)


def head(mirror: Path, branch: str) -> str:
    return git("rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}", cwd=mirror).strip()


def commits_between(mirror: Path, old: str, new: str, limit: int = 30) -> list[str]:
    """One line per commit in old..new, newest first (empty if old is unknown)."""
    try:
        out = git("log", "--format=%h %an: %s", f"-{limit}", f"{old}..{new}", cwd=mirror)
    except GitError:
        return []
    return [line for line in out.splitlines() if line.strip()]


def checkout(mirror: Path, sha: str, parent: Path) -> Path:
    """A fresh working tree of ``sha`` in a new directory under ``parent``.

    A clone rather than a worktree, so the tree carries a self-contained .git
    (some test suites read git metadata) that still works once copied into a sandbox."""
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="checkout-", dir=parent))
    git("clone", "--quiet", "--no-checkout", str(mirror), str(work / "src"))
    git("-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", sha, cwd=work / "src")
    return work / "src"


def remove_checkout(path: Path) -> None:
    shutil.rmtree(path.parent, ignore_errors=True)


def diff_stat(patch: Path) -> list[str]:
    """Files a unified diff touches, as "path (+added -removed)"."""
    out: dict[str, list[int]] = {}
    current = None
    for line in patch.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+++ "):
            current = line[4:].removeprefix("b/")
            out.setdefault(current, [0, 0])
        elif line.startswith("--- ") or current is None:
            continue
        elif line.startswith("+"):
            out[current][0] += 1
        elif line.startswith("-"):
            out[current][1] += 1
    return [f"{f} (+{a} -{r})" for f, (a, r) in out.items()]
