"""Render run reports as JSON (machines), Markdown (tickets/PRs) and HTML (people)."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .runner import RunReport, TargetResult

ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "ERROR": "⛔"}
SEV_ICON = {"info": "ℹ️", "warn": "⚠️", "fail": "❌", "error": "⛔"}
SEV_ORDER = {"error": 0, "fail": 1, "warn": 2, "info": 3}
TRANSITION = {
    "ok": "unchanged (pass)", "regressed": "REGRESSED", "fixed": "fixed by patch",
    "still-failing": "already failing", "missing": "not run",
}
MAX_DETAILS = 40
HTML_INLINE = 10


def write_all(report: RunReport) -> dict[str, Path]:
    out = report.out_dir
    paths = {"json": out / "report.json", "markdown": out / "report.md", "html": out / "report.html"}
    paths["json"].write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    paths["markdown"].write_text(markdown(report), encoding="utf-8")
    paths["html"].write_text(render_html(report), encoding="utf-8")
    return paths


def _fmt_status(cr) -> str:
    if cr is None:
        return "—"
    s = "pass" if cr.passed else ("timeout" if cr.timed_out else f"fail ({cr.exit_code})")
    return f"{s}, {cr.duration:.1f}s"


def _check_counts(t: TargetResult, phase: str) -> str:
    ph = getattr(t, phase)
    if not ph:
        return "—"
    return f"{sum(c.passed for c in ph.checks.values())}/{len(ph.checks)}"


def _pkg_summary(t: TargetResult) -> str:
    p = t.packages
    parts = [f"{len(p.upgraded)} upgraded" if p.upgraded else "",
             f"{len(p.added)} added" if p.added else "",
             f"{len(p.removed)} removed" if p.removed else ""]
    return ", ".join(x for x in parts if x) or "none"


def patch_label(r: RunReport) -> str:
    return r.patch.label if r.patch else "Baseline only (no patch applied)"


def _sorted_findings(t: TargetResult):
    return sorted(t.findings, key=lambda f: SEV_ORDER[f.severity])


# ---------------------------------------------------------------- markdown

def markdown(r: RunReport) -> str:
    d = r.to_dict()
    L = [f"# Patch test report: {r.config.name}", "",
         f"**Verdict: {ICON[r.verdict]} {r.verdict}**", "",
         f"- **Patch:** {patch_label(r)}",
         f"- **Run:** `{r.run_id}` — started {d['started']}, took {d['duration']}s",
         f"- **Targets:** {len(r.targets)} · **Cleanup:** {r.cleanup}"]
    L += [f"- **{k.replace('_', ' ').capitalize()}:** `{v}`" for k, v in r.config.metadata.items()]
    L.append("")
    if r.cancelled:
        L += ["> Run was cancelled before completion; results are partial.", ""]
    L += ["| Target | OS | Verdict | Checks passing (before → after) | Packages changed | Time |",
          "|---|---|---|---|---|---|"]
    for t in r.targets:
        L.append(f"| `{t.image}` | {t.os or '—'} | {ICON[t.verdict]} {t.verdict} | "
                 f"{_check_counts(t, 'baseline')} → {_check_counts(t, 'patched')} | "
                 f"{_pkg_summary(t)} | {t.duration:.0f}s |")
    for t in r.targets:
        L += ["", f"## {ICON[t.verdict]} `{t.image}` — {t.verdict}", ""]
        if t.kept_container:
            L += [f"> Container kept for debugging: `docker exec -it {t.kept_container} sh`", ""]
        L += ["### Findings", ""]
        if not t.findings:
            L.append("- No differences detected between baseline and patched system.")
        for f in _sorted_findings(t):
            L.append(f"- {SEV_ICON[f.severity]} **{f.severity.upper()}** [{f.area}] {f.message}")
            for det in f.details[:MAX_DETAILS]:
                L.append(f"  - `{det}`")
            if len(f.details) > MAX_DETAILS:
                L.append(f"  - … {len(f.details) - MAX_DETAILS} more (see report.json)")
        if t.updates:
            L += ["", f"### Updates applied ({len(t.updates)})", "",
                  "| KB | Update | Classification | Result |", "|---|---|---|---|"]
            for u in t.updates:
                L.append(f"| {u.get('kb') or '—'} | {u.get('title', '')} | {u.get('classification') or '—'} | "
                         f"{u.get('result') or '—'} |")
        if t.reboots:
            L += ["", f"Reboots: {len(t.reboots)} (" +
                  ", ".join(f"{s:.0f}s" for s in t.reboots) + " until the guest was back)"]
        if t.deltas:
            L += ["", "### Checks", "", "| Check | Category | Baseline | Patched | Change |",
                  "|---|---|---|---|---|"]
            for dl in t.deltas:
                crit = "" if dl.critical else " (non-critical)"
                L.append(f"| {dl.name}{crit} | {dl.category} | {_fmt_status(dl.before)} | "
                         f"{_fmt_status(dl.after)} | {TRANSITION[dl.transition]} |")
        p = t.packages
        if p.upgraded or p.added or p.removed:
            L += ["", f"### Package changes ({_pkg_summary(t)})", "", "<details><summary>Show</summary>", "",
                  "| Package | Before | After |", "|---|---|---|"]
            L += [f"| {n} | {o} | {v} |" for n, o, v in p.upgraded]
            L += [f"| {n} | — | {v} |" for n, v in p.added]
            L += [f"| {n} | {v} | — |" for n, v in p.removed]
            L += ["", "</details>"]
        L += ["", "### Pipeline", "", "| Stage | Status | Time | Detail |", "|---|---|---|---|"]
        for s in t.stages:
            L.append(f"| {s.name} | {s.status} | {s.duration:.1f}s | {s.detail} |")
    L += ["", f"_Logs for every command are in `{r.out_dir}`._", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#6b6b66;--border:#e3e2dd;
--pass:#1a7f37;--pass-bg:#e6f4ea;--warn:#9a6700;--warn-bg:#fff4d6;--fail:#c62828;--fail-bg:#fde8e8;
--error:#6e2bb5;--error-bg:#f1e8fb;--info:#2f5fb3;--info-bg:#e8effb;--code:#f0efeb}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#171716;--panel:#211f1e;
--text:#ecebe6;--muted:#a3a29c;--border:#373532;--pass:#5cc97a;--pass-bg:#16301f;--warn:#e3b341;
--warn-bg:#352a0f;--fail:#f47171;--fail-bg:#3a1b1b;--error:#c29bf5;--error-bg:#2c1d42;--info:#86a9f0;
--info-bg:#1b2640;--code:#2b2927}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.2rem;margin:0}h3{font-size:1rem;margin:20px 0 8px}
.muted{color:var(--muted)}code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.88em;
overflow-wrap:anywhere}
.hero>*,.target-head>*{min-width:0}h1,h2{overflow-wrap:anywhere}td code{overflow-wrap:normal;white-space:nowrap}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;margin-top:16px}
.hero{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:600;font-size:.85rem}
.big{font-size:1.1rem;padding:8px 18px}
.PASS,.info-ok{color:var(--pass);background:var(--pass-bg)}.WARN{color:var(--warn);background:var(--warn-bg)}
.FAIL{color:var(--fail);background:var(--fail-bg)}.ERROR{color:var(--error);background:var(--error-bg)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px 24px;margin-top:12px}
.meta div span{display:block;font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
.finding{border-left:4px solid var(--border);padding:8px 12px;margin:8px 0;border-radius:0 6px 6px 0;background:var(--bg)}
.finding.fail{border-color:var(--fail)}.finding.warn{border-color:var(--warn)}.finding.info{border-color:var(--info)}
.finding.error{border-color:var(--error)}
.sev{font-weight:700;font-size:.75rem;letter-spacing:.05em;margin-right:6px}
.sev.fail{color:var(--fail)}.sev.warn{color:var(--warn)}.sev.info{color:var(--info)}.sev.error{color:var(--error)}
.finding ul{margin:6px 0 0;padding-left:18px;font-size:.85rem}
.t-regressed{color:var(--fail);font-weight:600}.t-fixed{color:var(--pass);font-weight:600}
.t-still-failing{color:var(--warn)}
details summary{cursor:pointer;color:var(--muted);margin:6px 0}
.target-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
footer{margin-top:24px;font-size:.85rem}
"""


def _e(s) -> str:
    return html.escape(str(s))


def render_html(r: RunReport) -> str:
    d = r.to_dict()
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Patch Test Report</title><style>{CSS}</style></head><body><main>"]
    out.append("<div class='panel'><div class='hero'>"
               f"<span class='badge big {r.verdict}'>{ICON[r.verdict]} {r.verdict}</span>"
               f"<div><h1>{_e(r.config.name)}</h1><div class='muted'>{_e(patch_label(r))}</div></div></div>"
               "<div class='meta'>"
               f"<div><span>Run</span><code>{_e(r.run_id)}</code></div>"
               f"<div><span>Started</span>{_e(d['started'])}</div>"
               f"<div><span>Duration</span>{_e(d['duration'])}s</div>"
               f"<div><span>Cleanup</span>{_e(r.cleanup)}</div>" +
               "".join(f"<div><span>{_e(k.replace('_', ' '))}</span><code>{_e(v)}</code></div>"
                       for k, v in r.config.metadata.items()) + "</div>")
    if r.cancelled:
        out.append("<p class='finding error'>Run was cancelled; results are partial.</p>")
    out.append("<h3>Targets</h3><div class='scroll'><table><tr><th>Target</th><th>OS</th><th>Verdict</th>"
               "<th>Checks before → after</th><th>Packages changed</th><th>Time</th></tr>")
    for t in r.targets:
        out.append(f"<tr><td><a href='#{_e(t.slug)}'><code>{_e(t.image)}</code></a></td><td>{_e(t.os or '—')}</td>"
                   f"<td><span class='badge {t.verdict}'>{t.verdict}</span></td>"
                   f"<td>{_check_counts(t, 'baseline')} → {_check_counts(t, 'patched')}</td>"
                   f"<td>{_e(_pkg_summary(t))}</td><td>{t.duration:.0f}s</td></tr>")
    out.append("</table></div></div>")

    for t in r.targets:
        out.append(f"<section class='panel' id='{_e(t.slug)}'><div class='target-head'>"
                   f"<h2><code>{_e(t.image)}</code></h2><span class='badge {t.verdict}'>"
                   f"{ICON[t.verdict]} {t.verdict}</span></div>")
        if t.kept_container:
            out.append(f"<p class='muted'>Kept for debugging: <code>docker exec -it "
                       f"{_e(t.kept_container)} sh</code></p>")
        out.append("<h3>Findings</h3>")
        if not t.findings:
            out.append("<p class='muted'>No differences detected between the baseline and patched system.</p>")
        for f in _sorted_findings(t):
            out.append(f"<div class='finding {f.severity}'><span class='sev {f.severity}'>"
                       f"{f.severity.upper()}</span><span class='muted'>[{_e(f.area)}]</span> {_e(f.message)}")
            if f.details:
                li = [f"<li><code>{_e(x)}</code></li>" for x in f.details[:MAX_DETAILS]]
                if len(f.details) > MAX_DETAILS:
                    li.append(f"<li class='muted'>… {len(f.details) - MAX_DETAILS} more in report.json</li>")
                out.append(f"<ul>{''.join(li[:HTML_INLINE])}</ul>")
                if len(li) > HTML_INLINE:
                    out.append(f"<details><summary>{len(f.details) - HTML_INLINE} more</summary>"
                               f"<ul>{''.join(li[HTML_INLINE:])}</ul></details>")
            out.append("</div>")

        if t.updates:
            out.append(f"<h3>Updates applied ({len(t.updates)})</h3><div class='scroll'><table>"
                       "<tr><th>KB</th><th>Update</th><th>Classification</th><th>Result</th></tr>")
            for u in t.updates:
                res = u.get("result") or "—"
                cls = "t-fixed" if str(res).startswith(("Succeeded", "installed", "already")) else "t-regressed"
                out.append(f"<tr><td><code>{_e(u.get('kb') or '—')}</code></td><td>{_e(u.get('title', ''))}</td>"
                           f"<td>{_e(u.get('classification') or '—')}</td><td class='{cls}'>{_e(res)}</td></tr>")
            out.append("</table></div>")
        if t.reboots:
            out.append(f"<p class='muted'>Reboots: {len(t.reboots)} (" +
                       ", ".join(f"{s:.0f}s" for s in t.reboots) + " until the guest was back)</p>")
        if t.deltas:
            out.append("<h3>Checks</h3><div class='scroll'><table><tr><th>Check</th><th>Category</th>"
                       "<th>Baseline</th><th>Patched</th><th>Change</th><th>Logs</th></tr>")
            for dl in t.deltas:
                logs = " ".join(f"<a href='{_e(c.log_file)}'>{ph}</a>" for ph, c in
                                (("before", dl.before), ("after", dl.after)) if c and c.log_file)
                crit = "" if dl.critical else " <span class='muted'>(non-critical)</span>"
                out.append(f"<tr><td>{_e(dl.name)}{crit}</td><td>{_e(dl.category)}</td>"
                           f"<td>{_e(_fmt_status(dl.before))}</td><td>{_e(_fmt_status(dl.after))}</td>"
                           f"<td class='t-{dl.transition}'>{_e(TRANSITION[dl.transition])}</td>"
                           f"<td>{logs}</td></tr>")
            out.append("</table></div>")

        p = t.packages
        if p.upgraded or p.added or p.removed:
            out.append(f"<h3>Package changes</h3><details><summary>{_e(_pkg_summary(t))}</summary>"
                       "<div class='scroll'><table><tr><th>Package</th><th>Before</th><th>After</th></tr>")
            rows = ([(n, o, v) for n, o, v in p.upgraded] + [(n, "—", v) for n, v in p.added] +
                    [(n, v, "—") for n, v in p.removed])
            out += [f"<tr><td>{_e(n)}</td><td><code>{_e(o)}</code></td><td><code>{_e(v)}</code></td></tr>"
                    for n, o, v in rows]
            out.append("</table></div></details>")

        out.append("<h3>Pipeline</h3><div class='scroll'><table><tr><th>Stage</th><th>Status</th>"
                   "<th>Time</th><th>Detail</th></tr>")
        for s in t.stages:
            cls = {"ok": "PASS", "failed": "FAIL", "skipped": "WARN"}.get(s.status, "")
            out.append(f"<tr><td>{_e(s.name)}</td><td><span class='badge {cls}'>{_e(s.status)}</span></td>"
                       f"<td>{s.duration:.1f}s</td><td>{_e(s.detail)}</td></tr>")
        out.append("</table></div></section>")

    out.append(f"<footer class='muted'>Generated by {_e(d['tool'])}. Full data in "
               "<a href='report.json'>report.json</a>; command logs are alongside this file.</footer>"
               "</main></body></html>")
    return "".join(out)
