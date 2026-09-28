"""Advisory scanners for the ecosystems PatchLab Internal reports on but does not yet fix: Python, Go and Cargo.

Each one runs the ecosystem's own audit tool inside a tool container
(bridge.ToolBox), never on the host, and returns the same ``npm.Scan`` shape
so the digest and state files treat every ecosystem alike. They only report:
proposals stay npm-only until each ecosystem has its own planner.

The tools are pinned so a scan is repeatable. Bump them deliberately.
"""

from __future__ import annotations

import json
import re
import shlex

from .npm import Advisory, Scan, Vulnerable

PIP_AUDIT = "pip-audit==2.10.1"
GOVULNCHECK = "golang.org/x/vuln/cmd/govulncheck@v1.8.0"
CARGO_AUDIT = "cargo-audit@0.22.0"

# None of these tools reports a severity for every advisory, and guessing one
# would be worse than saying so.
UNKNOWN = "unknown"


def scan(tb, ecosystem: str, install: list[str]) -> Scan:
    if ecosystem == "python":
        return python(tb, install)
    if ecosystem == "go":
        return go(tb)
    if ecosystem == "cargo":
        return cargo(tb)
    return Scan([], {}, f"no scanner for {ecosystem} yet; advisories not checked")


def _counts(vulnerable: list[Vulnerable]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in vulnerable:
        out[v.severity] = out.get(v.severity, 0) + 1
    out["total"] = len(vulnerable)
    return out


def _version_key(v: str) -> tuple:
    """Numeric release parts first, so 3.10 sorts after 3.9."""
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+-]", v.lstrip("v")))


# ---------------------------------------------------------------- python

def python(tb, install: list[str]) -> Scan:
    """Install the package as its checks do, freeze the result, and audit exactly
    that set, transitive dependencies included.

    pip-audit lives in its own virtualenv, so neither it nor its dependencies
    end up in the audited list."""
    for cmd in install:
        res = tb.run(cmd, timeout=1800)
        if not res.ok:
            return Scan([], {}, f"install failed before the audit: {res.output.strip()[-300:]}")
    # Without --all: pip, setuptools and wheel belong to the base image, not the
    # package, and are the image maintainer's to update.
    freeze = tb.run("python -m pip freeze --exclude-editable > /tmp/audit-freeze.txt", timeout=120)
    if not freeze.ok:
        return Scan([], {}, f"pip freeze failed: {freeze.output.strip()[-300:]}")
    setup = tb.run(f"python -m venv /tmp/pip-audit && /tmp/pip-audit/bin/pip install -q "
                   f"--disable-pip-version-check {shlex.quote(PIP_AUDIT)}", timeout=600)
    if not setup.ok:
        return Scan([], {}, f"could not install {PIP_AUDIT}: {setup.output.strip()[-300:]}")
    # --no-deps --disable-pip: every version is already pinned by the freeze,
    # so nothing is resolved or installed again.
    res = tb.run("/tmp/pip-audit/bin/pip-audit -r /tmp/audit-freeze.txt --no-deps --disable-pip "
                 "--progress-spinner off -f json 2>/dev/null", timeout=600)
    return parse_pip_audit(res.stdout)


def parse_pip_audit(text: str) -> Scan:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return Scan([], {}, f"pip-audit did not return JSON: {e}")
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        return Scan([], {}, "pip-audit output has no dependency list")
    out = []
    for d in deps:
        # pip-audit can list one advisory twice (once per affected range).
        vulns = list({v["id"]: v for v in d.get("vulns") or []}.values())
        if not vulns:
            continue
        fixes = sorted({f for v in vulns for f in v.get("fix_versions") or []}, key=_version_key)
        out.append(Vulnerable(
            name=d["name"], severity=UNKNOWN, direct=False,
            advisories=[Advisory(id=v["id"], title=(v.get("description") or "")[:200], severity=UNKNOWN,
                                 url=f"https://osv.dev/vulnerability/{v['id']}",
                                 range=f"{d['name']}=={d.get('version', '?')}") for v in vulns],
            fix="in-range" if fixes else "none", fix_name=d["name"],
            fix_version=fixes[-1] if fixes else None))
    counts = _counts(out)
    counts["audited"] = len(deps)
    return Scan(out, counts)


# ---------------------------------------------------------------- go

def go(tb) -> Scan:
    """govulncheck at symbol level: only advisories whose vulnerable code the
    module actually calls count, as in the repos' own CI."""
    res = tb.run(f"go run {GOVULNCHECK} -format json ./... 2>/tmp/govulncheck.err", timeout=1200)
    scan = parse_govulncheck(res.stdout)
    if scan.error is None and not res.stdout.strip():
        err = tb.run("tail -c 300 /tmp/govulncheck.err", timeout=30).stdout.strip()
        return Scan([], {}, f"govulncheck produced no output: {err}")
    return scan


def parse_govulncheck(text: str) -> Scan:
    """Parse govulncheck's JSON stream (a sequence of objects, not one document)."""
    dec, i, objs = json.JSONDecoder(), 0, []
    text = text.strip()
    try:
        while i < len(text):
            obj, i = dec.raw_decode(text, i)
            objs.append(obj)
            while i < len(text) and text[i].isspace():
                i += 1
    except json.JSONDecodeError as e:
        return Scan([], {}, f"govulncheck did not return JSON: {e}")
    osv = {o["osv"]["id"]: o["osv"] for o in objs if "osv" in o}
    modules: dict[str, Vulnerable] = {}
    for o in objs:
        f = o.get("finding")
        if not f or not f.get("trace"):
            continue
        # A trace whose first frame names a function is a call the code makes;
        # anything else is only an imported package or a required module.
        if not f["trace"][0].get("function"):
            continue
        frame = f["trace"][0]
        mod = frame.get("module", "?")
        v = modules.setdefault(mod, Vulnerable(name=mod, severity=UNKNOWN, direct=False,
                                               fix="none", fix_name=mod))
        if any(a.id == f["osv"] for a in v.advisories):
            continue
        entry = osv.get(f["osv"], {})
        v.advisories.append(Advisory(id=f["osv"], title=entry.get("summary", ""), severity=UNKNOWN,
                                     url=f"https://pkg.go.dev/vuln/{f['osv']}",
                                     range=f"{mod}@{frame.get('version', '?')}"))
        if f.get("fixed_version"):
            v.fix = "in-range"
            fixed = set(filter(None, (v.fix_version or "").split(", "))) | {f["fixed_version"]}
            v.fix_version = ", ".join(sorted(fixed))
    out = sorted(modules.values(), key=lambda v: v.name)
    return Scan(out, _counts(out))


# ---------------------------------------------------------------- cargo

def cargo(tb) -> Scan:
    """cargo-audit against Cargo.lock. It fetches the RustSec advisory database
    itself; it never builds or runs the crates it audits."""
    have = tb.run("cargo audit --version", timeout=60)
    if not have.ok:
        inst = tb.run(f"cargo install --locked --quiet {shlex.quote(CARGO_AUDIT)}", timeout=1800)
        if not inst.ok:
            return Scan([], {}, f"could not install {CARGO_AUDIT}: {inst.output.strip()[-300:]}")
    res = tb.run("cargo audit --json 2>/dev/null", timeout=600)
    return parse_cargo_audit(res.stdout)


def parse_cargo_audit(text: str) -> Scan:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return Scan([], {}, f"cargo audit did not return JSON: {e}")
    items = list((data.get("vulnerabilities") or {}).get("list") or [])
    # Warnings are unmaintained, unsound or yanked crates: reported, at severity "info".
    for kind, warns in (data.get("warnings") or {}).items():
        for w in warns or []:
            if w.get("advisory"):
                items.append({**w, "_informational": kind})
    crates: dict[str, Vulnerable] = {}
    for it in items:
        adv, pkg = it.get("advisory") or {}, it.get("package") or {}
        name = pkg.get("name", "?")
        sev = "info" if it.get("_informational") else UNKNOWN
        v = crates.setdefault(name, Vulnerable(name=name, severity=sev, direct=False, fix="none",
                                               fix_name=name))
        if sev != "info":
            v.severity = UNKNOWN
        title = adv.get("title", "")
        if it.get("_informational"):
            title = f"({it['_informational']}) {title}"
        v.advisories.append(Advisory(id=adv.get("id", "?"), title=title, severity=sev,
                                     url=adv.get("url") or f"https://rustsec.org/advisories/{adv.get('id', '')}",
                                     range=f"{name}@{pkg.get('version', '?')}"))
        patched = (it.get("versions") or {}).get("patched") or []
        if patched:
            v.fix, v.fix_version = "in-range", ", ".join(patched)
    out = sorted(crates.values(), key=lambda v: v.name)
    counts = _counts(out)
    if isinstance((data.get("lockfile") or {}).get("dependency-count"), int):
        counts["audited"] = data["lockfile"]["dependency-count"]
    return Scan(out, counts)
