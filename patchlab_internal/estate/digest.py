"""The estate digest: one Markdown page with the state of every package, built only from state/."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from . import state
from .manifest import Estate

ICON = {"READY": "✅", "REVIEW": "👀", "BLOCKED": "❌", "INCONCLUSIVE": "❔",
        "healthy": "✅", "failing": "⚠️", "broken": "❌", "error": "⛔", "not-verified": "➖"}


def collect(estate: Estate) -> list[dict]:
    rows = []
    for pkg in estate.packages():
        pdir = estate.state_dir / pkg.slug
        _, h = state.latest(pdir / "health", "summary.json")
        scan = state.read_json(pdir / "scan.json") or {}
        decisions = []
        for kind, prefix in (("proposals", ""), ("repairs", "repair of ")):
            props = pdir / kind
            if not props.is_dir():
                continue
            for key in sorted(p.name for p in props.iterdir() if p.is_dir()):
                run, d = state.latest(props / key, "decision.json")
                if d:
                    prop = state.read_json(run / "proposal.json") or {}
                    decisions.append({"key": prefix + key, "run": str(run), "decision": d, "proposal": prop})
        rows.append({"package": pkg, "health": h, "scan": scan, "decisions": decisions})
    return rows


def render(estate: Estate, rows: list[dict] | None = None) -> str:
    rows = rows if rows is not None else collect(estate)
    today = dt.date.today().isoformat()
    L = [f"# Estate digest, {today}", ""]
    needs = []
    for r in rows:
        h = r["health"] or {}
        if h.get("status") in ("broken", "error"):
            needs.append(f"{r['package'].id}: health {h['status']}")
        for d in r["decisions"]:
            if d["decision"]["verdict"] in ("READY", "REVIEW"):
                needs.append(f"{r['package'].id}: review the {d['key']} change ({d['decision']['verdict']})")
        manual = r["scan"].get("not_fixable", [])
        if manual:
            needs.append(f"{r['package'].id}: {len(manual)} vulnerable package(s) with no automatic fix "
                         f"({', '.join(m['name'] for m in manual[:5])})")
    L += ["## Needs a person", ""] + ([f"- {n}" for n in needs] or ["- Nothing today."]) + [""]

    L += ["## Packages", "", "| Package | Health | Advisories (in production code; ? = not known) | Proposals |", "|---|---|---|---|"]
    for r in rows:
        pkg, h, scan = r["package"], r["health"] or {}, r["scan"]
        if pkg.unsupported:
            health = f"{ICON['not-verified']} not verified: {pkg.unsupported}"
        elif h:
            health = f"{ICON.get(h['status'], '')} {h['status']}"
            if h.get("failing"):
                health += f" ({len(h['failing'])} failing)"
        else:
            health = "not run yet"
        vul = scan.get("scan", {}).get("vulnerable", [])
        if scan.get("error") and not vul:
            adv = f"not scanned ({scan['error']})"
        elif scan:
            prod = [v for v in vul if v.get("production")]
            if not vul:
                adv = "none"
            elif scan.get("production_known") is False:
                adv = f"{len(vul)} (?)"
            else:
                adv = f"{len(vul)} ({len(prod)})"
            adv += f" at `{scan.get('commit', '')[:8]}`"
        else:
            adv = "not scanned yet"
        props = ", ".join(f"{ICON.get(d['decision']['verdict'], '')} {d['key']}" for d in r["decisions"]) or "—"
        L.append(f"| {pkg.id} | {health} | {adv} | {props} |")

    for r in rows:
        h = r["health"] or {}
        details = []
        if h.get("newly_failing"):
            details += ["**Newly failing:**"] + [f"- `{t}`" for t in h["newly_failing"][:20]]
            if h.get("commits_since_last_pass"):
                details += ["", "Commits since the last run:"] + [f"- {c}" for c in h["commits_since_last_pass"][:15]]
        if h.get("flaky"):
            details += ["**Flaky (failed once, passed on re-run):**"] + [f"- `{t}`" for t in h["flaky"][:20]]
        if h.get("failing") and not h.get("newly_failing"):
            details += [f"**Failing on `{h['commit'][:8]}`** (not new):"] + [f"- `{t}`" for t in h["failing"][:20]]
        if h.get("error"):
            details += [f"**Health run could not complete:** {h['error']}"]
        for d in r["decisions"]:
            dec = d["decision"]
            details += [f"**{d['key']}: {dec['verdict']}.** {dec['summary']}"]
            for g in dec.get("gate", []):
                if not g["ok"]:
                    details += [f"- {g['name']}: {g['detail']}"] + [f"  - `{x}`" for x in g["details"][:10]]
        for nf in r["scan"].get("not_fixable", []):
            details += [f"- `{nf['name']}` ({nf['severity']}): {nf['reason']}"]
        if details:
            # A blank line before each bold heading keeps the Markdown lists apart.
            spaced = []
            for line in details:
                if line.startswith("**") and spaced:
                    spaced.append("")
                spaced.append(line)
            L += ["", f"## {r['package'].id}", ""] + spaced
    L.append("")
    return "\n".join(L)


def write(estate: Estate) -> Path:
    path = estate.state_dir / "digest" / f"{dt.date.today().isoformat()}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(estate), encoding="utf-8")
    return path
