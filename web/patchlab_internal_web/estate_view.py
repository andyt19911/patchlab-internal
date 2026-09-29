"""Read-only view of the estate control plane's results (``patchlab-internal estate``).

Everything comes from the estate's ``state/`` folder, the same files the digest
is built from; nothing here runs a scan, writes state or reaches a managed repo.
Decisions are addressed by their run folder relative to ``state/`` and resolved
with ``store.inside``, so a request can't read outside it.
"""

from __future__ import annotations

import os
from pathlib import Path

from patchlab_internal.estate import analyst, digest, manifest, state

from . import store

MANIFEST_ENV = "PATCHLAB_INTERNAL_ESTATE_MANIFEST"
MAX_TEXT = 512_000          # a patch or PR body larger than this is cut, and says so


def find_manifest(explicit: str | None, configs: Path) -> Path | None:
    """--estate, then $PATCHLAB_INTERNAL_ESTATE_MANIFEST, then estate.toml in the configs folder."""
    for p in (explicit, os.environ.get(MANIFEST_ENV)):
        if p:
            return Path(p).expanduser().resolve()
    candidate = configs / "estate.toml"
    return candidate if candidate.is_file() else None


def _text(path: Path) -> str | None:
    if not path.is_file():
        return None
    data = path.read_bytes()
    text = data[:MAX_TEXT].decode("utf-8", errors="replace")
    return text + (f"\n… cut at {MAX_TEXT} bytes of {len(data)}" if len(data) > MAX_TEXT else "")


def _rel(est: manifest.Estate, run: Path | str) -> str:
    return Path(run).resolve().relative_to(est.state_dir.resolve()).as_posix()


def _decision(est: manifest.Estate, where: str, kind: str, key: str, run: Path, d: dict) -> dict:
    prop = state.read_json(run / "proposal.json") or {}
    return {"id": _rel(est, run), "where": where, "kind": kind, "key": key,
            "title": (prop.get("plan") or {}).get("title") or key,
            "verdict": d.get("verdict"), "summary": d.get("summary", ""),
            "labels": d.get("labels", []), "commit": prop.get("commit", ""),
            "has_patch": (run / "change.patch").is_file(), "has_pr": (run / "pr.md").is_file(),
            "gate_failed": sum(1 for g in d.get("gate", []) if not g.get("ok"))}


def overview(est: manifest.Estate) -> dict:
    packages, decisions = [], []
    for r in digest.collect(est):
        pkg, h, scan, code = r["package"], r["health"] or {}, r["scan"] or {}, r["code"] or {}
        vul = scan.get("scan", {}).get("vulnerable", [])
        packages.append({
            "id": pkg.id, "repo": pkg.repo.name, "ecosystem": pkg.ecosystem, "unsupported": pkg.unsupported or "",
            "health": h.get("status") or ("not-verified" if pkg.unsupported else None),
            "passing_tests": h.get("passing_tests"), "failing": len(h.get("failing") or []),
            "newly_failing": h.get("newly_failing") or [], "health_error": h.get("error"),
            "health_when": h.get("when"), "commit": h.get("commit") or scan.get("commit", ""),
            "scanned": bool(scan), "scan_error": scan.get("error"),
            "advisories": len(vul), "advisories_production": sum(1 for v in vul if v.get("production")),
            "not_fixable": [{"name": n["name"], "severity": n.get("severity"), "reason": n.get("reason")}
                            for n in scan.get("not_fixable", [])],
            "code_scanned": bool(code), "code_complete": bool(code.get("complete")),
            "code_counts": code.get("counts", {}),
            "code_tools": code.get("tools", {}),
            "code_blocking": [{k: f.get(k) for k in ("tool", "rule", "file", "line", "severity", "message", "code")}
                              for f in code.get("findings", []) if f.get("blocking")],
        })
        for d in r["decisions"]:
            kind = "code fix" if d["key"].startswith("code fix") else "repair" if d["key"].startswith("repair") \
                else "dependency"
            decisions.append(_decision(est, pkg.id, kind, d["key"], Path(d["run"]), d["decision"]))

    images = []
    for it in digest.collect_images(est):
        scan = it["scan"] or {}
        bases = [{"image": b["image"], "support": b["support"].get("status"), "eol": b["support"].get("eol"),
                  "fixable": len(b["scan"].get("fixable", [])), "fixable_high": b["scan"].get("fixable_high", 0),
                  "scan_error": b["scan"].get("error")} for b in scan.get("bases", [])]
        images.append({"id": it["id"], "scanned": bool(scan), "error": scan.get("error"), "bases": bases})
        for d in it["decisions"]:
            decisions.append(_decision(est, it["id"], "runtime move", d["key"], Path(d["run"]), d["decision"]))

    workflows = []
    for repo in est.repos:
        base = est.state_dir / "workflows" / repo.name
        scan = state.read_json(base / "scan.json")
        if not scan:
            continue
        counts: dict[str, int] = {}
        for f in scan.get("findings", []):
            counts[f["rule"]] = counts.get(f["rule"], 0) + 1
        workflows.append({"repo": repo.name, "counts": counts})
        run, d = state.latest(base, "decision.json")
        if d:
            decisions.append(_decision(est, repo.name, "CI workflows", "pin-actions", run, d))

    ddir = est.state_dir / "digest"
    digests = sorted((p.stem for p in ddir.glob("*.md")), reverse=True) if ddir.is_dir() else []
    order = {"READY": 0, "REVIEW": 1, "BLOCKED": 2, "INCONCLUSIVE": 3}
    decisions.sort(key=lambda d: (order.get(d["verdict"], 9), d["where"], d["key"]))
    published = state.read_json(est.state_dir / "published.json", {}) or {}
    report = analyst.latest_report(est)
    return {"manifest": str(est.path), "state_dir": str(est.state_dir), "publish": est.publish,
            "repos": [r.name for r in est.repos], "packages": packages, "images": images,
            "workflows": workflows, "decisions": decisions, "digests": digests,
            "published": [{"branch": b, "url": v.get("url")} for b, v in sorted(published.items())],
            "analysis": {"date": report[0], "text": report[1][:MAX_TEXT]} if report else None}


def decision(est: manifest.Estate, rel: str) -> dict:
    run = store.inside(est.state_dir, rel)
    d = state.read_json(run / "decision.json") if run.is_dir() else None
    if not d:
        raise store.NotFound(rel)
    prop = state.read_json(run / "proposal.json") or {}
    return {"id": _rel(est, run), "decision": d, "title": (prop.get("plan") or {}).get("title") or run.parent.name,
            "commit": prop.get("commit", ""), "pr": _text(run / "pr.md"), "patch": _text(run / "change.patch")}


def digest_text(est: manifest.Estate, day: str) -> str:
    if not store.RUN_ID.match(day):
        raise store.NotFound(day)
    text = _text(store.inside(est.state_dir / "digest", f"{day}.md"))
    if text is None:
        raise store.NotFound(day)
    return text
