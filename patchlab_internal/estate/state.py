"""The estate's state: plain JSON files under <workdir>/state, one directory per package.

  state/<package>/scan.json                   latest advisories
  state/<package>/health/<run>/...            baseline-only runs (engine report + summary.json)
  state/<package>/proposals/<key>/<run>/...   proposals: change.patch, proposal.json,
                                              decision.json, pr.md, the engine report
  state/digest/<date>.md                      daily digest

The dashboard and the digest read only these files.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path


def write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)   # readers never see a half-written file
    return path


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def package_dir(state: Path, slug: str) -> Path:
    return state / slug


def latest(dirpath: Path, name: str) -> tuple[Path, dict] | tuple[None, None]:
    """The newest run directory under ``dirpath`` holding ``name`` (run ids sort by time)."""
    if not dirpath.is_dir():
        return None, None
    for run in sorted((p for p in dirpath.iterdir() if p.is_dir()), reverse=True):
        data = read_json(run / name)
        if data is not None:
            return run, data
    return None, None


def history(dirpath: Path, name: str, limit: int = 30) -> list[dict]:
    if not dirpath.is_dir():
        return []
    out = []
    for run in sorted((p for p in dirpath.iterdir() if p.is_dir()), reverse=True)[:limit]:
        data = read_json(run / name)
        if data is not None:
            out.append(data)
    return out


@contextmanager
def exclusive(state: Path):
    """One estate command at a time: two schedulers on one host must not race
    on the same checkouts, sandboxes and state."""
    import fcntl   # the estate layer runs on Linux hosts; imported here so the module loads anywhere
    state.mkdir(parents=True, exist_ok=True)
    with open(state / ".lock", "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"another estate command is running (lock: {state / '.lock'})") from None
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
