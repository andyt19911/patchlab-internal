"""npm: read advisories, work out the smallest fix, build it as a diff, and check what the lockfile change brings in.

Every npm command runs inside a tool container (bridge.ToolBox), never on the
host, and with ``--ignore-scripts`` / ``--package-lock-only`` so that producing
a proposal never executes a dependency's code. Code runs only in the test
sandbox, which is where it is meant to run.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = ("info", "low", "moderate", "high", "critical")
REGISTRY = "https://registry.npmjs.org/"
QUIET = "--no-audit --no-fund --ignore-scripts --loglevel=error"


@dataclass
class Advisory:
    id: str
    title: str
    severity: str
    url: str = ""
    range: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Vulnerable:
    """One vulnerable package in the lockfile and what npm says would fix it."""

    name: str
    severity: str
    direct: bool
    advisories: list[Advisory] = field(default_factory=list)
    via: list[str] = field(default_factory=list)     # other vulnerable packages it depends on
    fix: str = "none"                                 # none | in-range | major
    fix_name: str | None = None
    fix_version: str | None = None
    production: bool = False

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["advisories"] = [a.to_dict() for a in self.advisories]
        return d


@dataclass
class Scan:
    vulnerable: list[Vulnerable]
    counts: dict[str, int]
    error: str | None = None

    def by_name(self) -> dict[str, Vulnerable]:
        return {v.name: v for v in self.vulnerable}

    def advisory_ids(self) -> set[str]:
        return {a.id for v in self.vulnerable for a in v.advisories}

    def to_dict(self) -> dict:
        return {"vulnerable": [v.to_dict() for v in self.vulnerable], "counts": self.counts,
                "error": self.error}


def scan_from_dict(d: dict) -> Scan:
    vul = [Vulnerable(**{**v, "advisories": [Advisory(**a) for a in v["advisories"]]})
           for v in d.get("vulnerable", [])]
    return Scan(vul, d.get("counts", {}), d.get("error"))


def parse_audit(text: str, production: set[str] | None = None) -> Scan:
    """Parse ``npm audit --json`` (npm 7+). ``production`` names the packages that
    also appear in an ``--omit=dev`` audit."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return Scan([], {}, f"npm audit did not return JSON: {e}")
    if "vulnerabilities" not in data:
        err = data.get("error", {})
        return Scan([], {}, f"npm audit failed: {err.get('summary') or err or 'no vulnerabilities key'}")
    out = []
    for name, v in sorted(data["vulnerabilities"].items()):
        vul = Vulnerable(name=name, severity=v.get("severity", "info"), direct=bool(v.get("isDirect")),
                         production=name in (production or set()))
        for via in v.get("via", []):
            if isinstance(via, str):
                vul.via.append(via)
            else:
                vul.advisories.append(Advisory(
                    id=str(via.get("source", via.get("url", "?"))), title=via.get("title", ""),
                    severity=via.get("severity", vul.severity), url=via.get("url", ""),
                    range=via.get("range", "")))
        fix = v.get("fixAvailable")
        if fix is True:
            vul.fix = "in-range"
        elif isinstance(fix, dict):
            vul.fix = "major" if fix.get("isSemVerMajor") else "in-range"
            vul.fix_name, vul.fix_version = fix.get("name"), fix.get("version")
        out.append(vul)
    counts = {k: int(n) for k, n in data.get("metadata", {}).get("vulnerabilities", {}).items()}
    return Scan(out, counts)


def production_names(text: str) -> set[str]:
    try:
        return set(json.loads(text).get("vulnerabilities", {}))
    except json.JSONDecodeError:
        return set()


def audit(tb) -> Scan:
    """Audit the lockfile as committed. --package-lock-only: nothing is installed or run."""
    full = tb.run("npm audit --package-lock-only --json 2>/dev/null", timeout=300)
    prod = tb.run("npm audit --package-lock-only --omit=dev --json 2>/dev/null", timeout=300)
    return parse_audit(full.stdout, production_names(prod.stdout))


# ---------------------------------------------------------------- planning

@dataclass
class Plan:
    """One change to propose: either a major bump of one direct dependency, or
    every in-range fix at once (npm audit fix without --force)."""

    kind: str                  # major | in-range | upgrade (one dependency, non-npm ecosystems)
    dependency: str | None     # the direct dependency bumped (major only)
    covers: list[str]          # vulnerable package names this should fix
    advisories: list[Advisory]
    severity: str
    production: bool
    suggested_version: str | None = None

    @property
    def key(self) -> str:
        return self.dependency if self.kind in ("major", "upgrade") else "in-range-fixes"

    @property
    def title(self) -> str:
        if self.kind == "major":
            return f"{self.dependency} (major upgrade)"
        if self.kind == "upgrade":
            return f"{self.dependency} upgrade"
        return f"in-range fixes for {', '.join(self.covers)}"

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["advisories"] = [a.to_dict() for a in self.advisories]
        d["key"], d["title"] = self.key, self.title
        return d


@dataclass
class NotFixable:
    name: str
    reason: str
    severity: str
    advisories: list[Advisory]

    def to_dict(self) -> dict:
        return {"name": self.name, "reason": self.reason, "severity": self.severity,
                "advisories": [a.to_dict() for a in self.advisories]}


def worst_severity(items) -> str:
    return max((i for i in items), key=SEVERITY_ORDER.index, default="info")


def _advisories_of(scan: Scan, names: list[str]) -> list[Advisory]:
    by = scan.by_name()
    seen, out = set(), []
    for n in names:
        for a in by[n].advisories if n in by else []:
            if a.id not in seen:
                seen.add(a.id)
                out.append(a)
    return out


def plan(scan: Scan, direct_deps: set[str], ignore: dict[str, str] | None = None
         ) -> tuple[list[Plan], list[NotFixable]]:
    ignore = ignore or {}
    majors: dict[str, list[Vulnerable]] = {}
    in_range: list[Vulnerable] = []
    blocked: list[NotFixable] = []
    for v in scan.vulnerable:
        if v.name in ignore:
            blocked.append(NotFixable(v.name, f"ignored in estate.toml: {ignore[v.name]}", v.severity,
                                      v.advisories))
        elif v.fix == "major" and v.fix_name:
            if v.fix_name in ignore:
                blocked.append(NotFixable(v.name, f"its fix ({v.fix_name}) is ignored in estate.toml: "
                                          f"{ignore[v.fix_name]}", v.severity, v.advisories))
            elif v.fix_name not in direct_deps:
                blocked.append(NotFixable(v.name, f"fixed by a major upgrade of {v.fix_name}, which is "
                                          "not a direct dependency; needs a person", v.severity, v.advisories))
            else:
                majors.setdefault(v.fix_name, []).append(v)
        elif v.fix == "in-range":
            in_range.append(v)
        else:
            blocked.append(NotFixable(v.name, "no fixed version published", v.severity, v.advisories))

    plans = []
    for dep, vs in sorted(majors.items()):
        names = [v.name for v in vs]
        plans.append(Plan("major", dep, names, _advisories_of(scan, names),
                          worst_severity(v.severity for v in vs), any(v.production for v in vs),
                          suggested_version=vs[0].fix_version))
    if in_range:
        names = [v.name for v in in_range]
        plans.append(Plan("in-range", None, names, _advisories_of(scan, names),
                          worst_severity(v.severity for v in in_range), any(v.production for v in in_range)))
    # Production first, then severity.
    plans.sort(key=lambda p: (not p.production, -SEVERITY_ORDER.index(p.severity)))
    return plans, blocked


def direct_dependencies(package_json: Path) -> dict[str, str]:
    """name -> "dependencies" | "devDependencies" | "optionalDependencies"."""
    data = json.loads(package_json.read_text(encoding="utf-8"))
    out = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name in data.get(section, {}):
            out[name] = section
    return out


# ---------------------------------------------------------------- choosing a version

# Runs in the tool container with npm's own semver, so ranges are read exactly as npm reads them.
_CHOOSE_JS = r"""
const path = require('path');
const semver = require(path.join(process.env.NPM_ROOT, 'npm/node_modules/semver'));
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const vulnerable = (v) => input.ranges.some((r) => { try { return semver.satisfies(v, r); } catch { return false; } });
const stable = input.versions.filter((v) => semver.valid(v) && !semver.prerelease(v) && semver.gt(v, input.current));
const safe = stable.filter((v) => !vulnerable(v));
const majors = [...new Set(safe.map((v) => semver.major(v)))].sort((a, b) => a - b);
const out = majors.map((m) => semver.maxSatisfying(safe.filter((v) => semver.major(v) === m), '*'));
console.log(JSON.stringify(out));
"""


def candidate_versions(tb, dependency: str, current: str, ranges: list[str]) -> list[str]:
    """Safe versions to try, smallest major jump first: the newest release in
    each major line that no known advisory range covers."""
    res = tb.run(f"npm view {shlex.quote(dependency)} versions --json", timeout=120)
    if not res.ok:
        return []
    try:
        versions = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(versions, str):
        versions = [versions]
    payload = json.dumps({"versions": versions, "ranges": ranges, "current": current})
    script = base64.b64encode(_CHOOSE_JS.encode()).decode()
    data = base64.b64encode(payload.encode()).decode()
    res = tb.run(f"echo {data} | base64 -d | NPM_ROOT=$(npm root -g) node -e "
                 f"\"$(echo {script} | base64 -d)\"", timeout=60)
    try:
        return [v for v in json.loads(res.stdout.strip().splitlines()[-1]) if v]
    except (json.JSONDecodeError, IndexError):
        return []


def minimal_manifest_edit(original: str, rewritten: str) -> str:
    """Carry over only the dependency-spec changes npm made to package.json.

    npm re-serialises the whole file when it saves (it turns a "\\u2014"
    escape into the literal character, for one), which would put unrelated
    lines into the proposal. The diff that is tested and proposed must be the
    change and nothing else, so each changed spec is edited into the original text."""
    old, new = json.loads(original), json.loads(rewritten)
    text = original
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        before, after = old.get(section, {}), new.get(section, {})
        for name, spec in after.items():
            if before.get(name) == spec:
                continue
            if name not in before:
                raise ValueError(f"npm added {name} to {section}; refusing to guess where it goes")
            pattern = re.compile(r'("' + re.escape(json.dumps(name)[1:-1]) + r'"\s*:\s*)"'
                                 + re.escape(json.dumps(before[name])[1:-1]) + '"')
            text, n = pattern.subn(lambda m: m.group(1) + json.dumps(spec), text, count=1)
            if n != 1:
                raise ValueError(f"could not find {name} in {section} of package.json")
        removed = set(before) - set(after)
        if removed:
            raise ValueError(f"npm removed {', '.join(sorted(removed))} from {section}")
    if json.loads(text) != {**old, **{k: new[k] for k in new if k.endswith("ependencies")}}:
        raise ValueError("package.json edit did not reproduce npm's dependency changes")
    return text


def installed_version(lock: dict, name: str) -> str | None:
    return lock.get("packages", {}).get(f"node_modules/{name}", {}).get("version")


# ---------------------------------------------------------------- lockfile changes

@dataclass
class LockDiff:
    upgraded: list[tuple[str, str, str]] = field(default_factory=list)
    added: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    # Supply-chain signals: each makes a change need a person, even if tests pass.
    new_install_scripts: list[str] = field(default_factory=list)
    unusual_sources: list[str] = field(default_factory=list)
    missing_integrity: list[str] = field(default_factory=list)

    @property
    def new_names(self) -> list[str]:
        """Packages that were not in the tree at all before (not just a new copy)."""
        before = {n for n, _, _ in self.upgraded} | {n for n, _ in self.removed}
        return sorted({n for n, _ in self.added} - before)

    def to_dict(self) -> dict:
        return {"upgraded": [{"name": n, "from": a, "to": b} for n, a, b in self.upgraded],
                "added": [{"name": n, "version": v} for n, v in self.added],
                "removed": [{"name": n, "version": v} for n, v in self.removed],
                "new_packages": self.new_names, "new_install_scripts": self.new_install_scripts,
                "unusual_sources": self.unusual_sources, "missing_integrity": self.missing_integrity}


def _pkg_name(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def lock_diff(before: dict, after: dict, allowed_git: tuple[str, ...] = ()) -> LockDiff:
    """Compare two package-lock.json (v2/v3) trees."""
    b = {k: v for k, v in before.get("packages", {}).items() if k.startswith("node_modules/") or "/node_modules/" in k}
    a = {k: v for k, v in after.get("packages", {}).items() if k.startswith("node_modules/") or "/node_modules/" in k}
    d = LockDiff()
    names_before: dict[str, set[str]] = {}
    for k, v in b.items():
        names_before.setdefault(_pkg_name(k), set()).add(v.get("version", "?"))
    for k, v in sorted(a.items()):
        name, ver = _pkg_name(k), v.get("version", "?")
        old = b.get(k)
        if old is None:
            d.added.append((name, ver))
        elif old.get("version") != ver:
            d.upgraded.append((name, old.get("version", "?"), ver))
        if v.get("hasInstallScript") and not (old or {}).get("hasInstallScript"):
            d.new_install_scripts.append(f"{name}@{ver}")
        if old is None or old.get("resolved") != v.get("resolved"):
            resolved = v.get("resolved", "")
            if v.get("link") or not resolved:
                continue
            if resolved.startswith(REGISTRY):
                if not v.get("integrity"):
                    d.missing_integrity.append(f"{name}@{ver}")
            elif not any(resolved.startswith(g) for g in allowed_git):
                d.unusual_sources.append(f"{name}@{ver} from {resolved}")
    for k, v in sorted(b.items()):
        if k not in a:
            d.removed.append((_pkg_name(k), v.get("version", "?")))
    # A package moved within the tree (hoisting) is not a removal plus an addition.
    moved = {n for n, _ in d.added} & {n for n, _ in d.removed}
    for n in moved:
        olds = [v for m, v in d.removed if m == n]
        news = [v for m, v in d.added if m == n]
        if sorted(olds) == sorted(news):
            d.added = [x for x in d.added if x[0] != n]
            d.removed = [x for x in d.removed if x[0] != n]
    return d


def ships_types(tb, dependency: str, version: str) -> bool:
    res = tb.run(f"npm view {shlex.quote(f'{dependency}@{version}')} types typings --json", timeout=120)
    return res.ok and bool(res.stdout.strip()) and res.stdout.strip() not in ("{}", "")
