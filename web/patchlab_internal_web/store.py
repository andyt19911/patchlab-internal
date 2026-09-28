"""Read-only access to run reports and configs on disk."""

from __future__ import annotations

import json
import re
from pathlib import Path

from patchlab_internal import config

RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "reports"}
MAX_CONFIGS = 500


class NotFound(Exception):
    pass


def inside(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root``; refuse anything that escapes it."""
    root = root.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise NotFound(rel)
    return target


def run_dir(reports: Path, run_id: str) -> Path:
    if not RUN_ID.match(run_id):
        raise NotFound(run_id)
    d = inside(reports, run_id)
    if not d.is_dir():
        raise NotFound(run_id)
    return d


_cache: dict[Path, tuple[float, dict]] = {}


def _report(path: Path) -> dict | None:
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return None
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    _cache[path] = (mtime, data)
    return data


def summarise(run_id: str, data: dict | None) -> dict:
    if not data:
        return {"run_id": run_id, "has_report": False}
    targets = data.get("targets", [])
    counts: dict[str, int] = {}
    for t in targets:
        for f in t.get("findings", []):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "run_id": run_id, "has_report": True, "name": data.get("name"), "verdict": data.get("verdict"),
        "patch": (data.get("patch") or {}).get("label"), "platform": data.get("platform", "linux"),
        "provider": data.get("provider", "docker"), "started": data.get("started"),
        "duration": data.get("duration"), "cancelled": data.get("cancelled", False),
        "cleanup": data.get("cleanup"), "finding_counts": counts,
        "targets": [{"image": t.get("image"), "verdict": t.get("verdict"), "os": t.get("os")} for t in targets],
    }


def list_runs(reports: Path) -> list[dict]:
    if not reports.is_dir():
        return []
    runs = []
    for d in reports.iterdir():
        if d.is_dir() and RUN_ID.match(d.name):
            s = summarise(d.name, _report(d / "report.json"))
            s["has_console"] = (d / "console.log").exists()
            runs.append(s)
    return sorted(runs, key=lambda r: r["run_id"], reverse=True)


def load_run(reports: Path, run_id: str) -> dict:
    d = run_dir(reports, run_id)
    data = _report(d / "report.json")
    out = summarise(run_id, data)
    out["report"] = data
    out["files"] = sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file())[:2000]
    return out


def read_console(reports: Path, run_id: str, offset: int, limit: int = 256_000) -> tuple[str, int]:
    f = run_dir(reports, run_id) / "console.log"
    if not f.exists():
        return "", 0
    with open(f, "rb") as fh:
        fh.seek(max(0, offset))
        chunk = fh.read(limit)
    return chunk.decode("utf-8", "replace"), max(0, offset) + len(chunk)


def describe_config(root: Path, path: Path) -> dict | None:
    rel = path.relative_to(root).as_posix()
    try:
        cfg = config.load(path)
    except config.ConfigError as e:
        if "missing required key 'sandbox'" in str(e):
            return None   # an include-only file (shared checks), not a runnable config
        return {"path": rel, "valid": False, "error": str(e)}
    except (OSError, UnicodeDecodeError) as e:
        return {"path": rel, "valid": False, "error": str(e)}
    sb = cfg.sandbox
    return {
        "path": rel, "valid": True, "name": cfg.name, "platform": sb.platform, "provider": sb.provider,
        "images": sb.images, "checks": [c.name for c in cfg.checks],
        "patch": cfg.patch.label if cfg.patch else None,
        "patch_kind": cfg.patch.kind if cfg.patch else None,
        "patch_kinds": list(config.PLATFORMS[sb.platform][1]),
    }


def list_configs(root: Path) -> list[dict]:
    if not root.is_dir():
        return []
    found = []
    for path in sorted(root.rglob("*.toml")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.name == "pyproject.toml":
            continue
        info = describe_config(root, path)
        if info:
            found.append(info)
        if len(found) >= MAX_CONFIGS:
            break
    return found
