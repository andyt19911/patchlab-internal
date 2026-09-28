"""Build fixes for Python, Go and Cargo advisories, as diffs, for the same test and gate as npm.

Each fixer makes the smallest change its ecosystem allows:

- Python: the exact pin (``name==x``) in the package's requirement files is
  moved to the lowest version that fixes every advisory. A dependency that is
  not pinned anywhere gets a ``name>=x`` floor in the main requirements file.
- Go: ``go get module@version`` then ``go mod tidy``.
- Cargo: ``cargo update --package crate`` to the newest semver-compatible
  version (Cargo.lock only).

Tool commands run in a tool container (bridge.ToolBox), never on the host, and
the re-audit afterwards decides whether the advisories are really gone. What
changed in the dependency tree (added, removed, upgraded, unusual sources) is
recorded in the same ``lock_diff`` shape as npm so the gate treats it alike.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

from . import advisories, bridge, gitops, npm
from .manifest import Estate, Package

CRATES_IO = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")


def _norm(name: str) -> str:
    """PEP 503 normalised name: Foo_Bar.baz and foo-bar-baz are the same project."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- python

REQ_LINE = re.compile(r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?"
                      r"\s*==\s*(?P<ver>[^\s;#\\]+)(?P<rest>.*)$")


def requirement_files(pkg_dir: Path) -> list[Path]:
    files = sorted(p for p in pkg_dir.glob("*.txt") if "requirement" in p.name.lower())
    files += sorted(pkg_dir.glob("requirements/*.txt"))
    return files


def repin(text: str, name: str, version: str) -> tuple[str, int]:
    """Move every exact pin of ``name`` in a requirements file to ``version``.
    Returns the new text and how many lines changed; nothing else is touched."""
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        m = REQ_LINE.match(body)
        if m and _norm(m["name"]) == _norm(name) and m["ver"] != version:
            body = f"{m['lead']}{m['name']}{m['extras'] or ''}=={version}{m['rest']}"
            n += 1
        out.append(body + line[len(line.rstrip("\r\n")):])
    return "".join(out), n


def _python(tb, pkg: Package, checkout: Path, plan: npm.Plan, result: dict) -> bool:
    pkg_dir = checkout / pkg.path if pkg.path != "." else checkout
    target = plan.suggested_version
    edited = []
    for f in requirement_files(pkg_dir):
        new, n = repin(f.read_text(encoding="utf-8"), plan.dependency, target)
        if n:
            f.write_text(new, encoding="utf-8")
            edited.append(f)
    if not edited:
        main = pkg_dir / "requirements.txt"
        if not main.is_file():
            result["notes"].append(f"{plan.dependency} is not pinned in any requirements file, and there "
                                   "is no requirements.txt to add a floor to.")
            return False
        text = main.read_text(encoding="utf-8")
        text += ("" if text.endswith("\n") or not text else "\n")
        text += f"{plan.dependency}>={target}  # security floor: {', '.join(a.id for a in plan.advisories)}\n"
        main.write_text(text, encoding="utf-8")
        edited.append(main)
        result["notes"].append(f"{plan.dependency} is a transitive dependency pinned nowhere, so this adds "
                               f"a floor (>={target}) to requirements.txt rather than pinning it.")
    for f in edited:
        tb.box.copy_in(f, f"{bridge.repo_root(pkg)}/{f.relative_to(checkout).as_posix()}")
    result["allowed_files"] = [f.relative_to(checkout).as_posix() for f in edited]
    return True


def _python_tree(tb) -> dict[str, str]:
    """name -> version from the freeze the last audit made; VCS/URL installs keep their source."""
    out = {}
    for line in tb.run("cat /tmp/audit-freeze.txt", timeout=60).stdout.splitlines():
        if "==" in line:
            n, v = line.split("==", 1)
            out[_norm(n.strip())] = v.strip()
        elif " @ " in line:
            n, src = line.split(" @ ", 1)
            out[_norm(n.strip())] = "@ " + src.strip()
    return out


# ---------------------------------------------------------------- go

def _go(tb, pkg: Package, checkout: Path, plan: npm.Plan, result: dict) -> bool:
    mod = f"{plan.dependency}@{plan.suggested_version}"
    res = tb.run(f"GOFLAGS=-mod=mod go get {shlex.quote(mod)} && GOFLAGS=-mod=mod go mod tidy", timeout=1200)
    if not res.ok:
        result["notes"].append(f"go get {mod} failed: " + res.output.strip()[-300:])
        return False
    base = "" if pkg.path == "." else f"{pkg.path}/"
    result["allowed_files"] = [f"{base}go.mod", f"{base}go.sum"]
    return True


def _go_tree(tb) -> dict[str, str]:
    res = tb.run("GOFLAGS=-mod=mod go list -m all 2>/dev/null", timeout=600)
    out = {}
    for line in res.stdout.splitlines()[1:]:          # the first line is the main module
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = parts[1] if len(parts) == 2 else " ".join(parts[1:])
    return out


# ---------------------------------------------------------------- cargo

def _cargo(tb, pkg: Package, checkout: Path, plan: npm.Plan, result: dict) -> bool:
    res = tb.run(f"cargo update --package {shlex.quote(plan.dependency)}", timeout=1200)
    if not res.ok:
        result["notes"].append(f"cargo update --package {plan.dependency} failed: "
                               + res.output.strip()[-300:])
        return False
    # A workspace has one Cargo.lock at its root.
    lock = next((p for p in (checkout / pkg.path / "Cargo.lock", checkout / "Cargo.lock") if p.is_file()), None)
    result["allowed_files"] = [lock.relative_to(checkout).as_posix()] if lock else ["Cargo.lock"]
    return True


def _cargo_tree(tb, pkg: Package, checkout: Path) -> dict[str, str]:
    lock = next((p for p in (checkout / pkg.path / "Cargo.lock", checkout / "Cargo.lock") if p.is_file()), None)
    if lock is None:
        return {}
    rel = lock.relative_to(checkout).as_posix()
    res = tb.run(f"cat {bridge.repo_root(pkg)}/{rel}", timeout=60, workdir="/")
    try:
        data = tomllib.loads(res.stdout)
    except tomllib.TOMLDecodeError:
        return {}
    out = {}
    for p in data.get("package", []):
        src = p.get("source")
        key = f"{p['name']} {p['version']}"      # Cargo.lock can hold two versions of one crate
        out[key] = p["version"] if (src is None or src.startswith(CRATES_IO)) else f"@ {src}"
    return out


def tree_diff(before: dict[str, str], after: dict[str, str], keyed_by_version: bool = False) -> dict:
    """The lock_diff shape npm uses, from two name -> version maps. A version
    starting with "@ " is a non-registry source and is flagged."""
    if keyed_by_version:
        def name(k): return k.split(" ", 1)[0]
        b = {}
        for k, v in before.items():
            b.setdefault(name(k), set()).add(v)
        a = {}
        for k, v in after.items():
            a.setdefault(name(k), set()).add(v)
        before = {n: ", ".join(sorted(v)) for n, v in b.items()}
        after = {n: ", ".join(sorted(v)) for n, v in a.items()}
    upgraded = [{"name": n, "from": before[n], "to": after[n]} for n in sorted(after)
                if n in before and before[n] != after[n]]
    added = [{"name": n, "version": after[n]} for n in sorted(after) if n not in before]
    removed = [{"name": n, "version": before[n]} for n in sorted(before) if n not in after]
    unusual = [f"{n} {v[2:]}" for n, v in sorted(after.items())
               if v.startswith("@ ") and before.get(n) != v]
    return {"upgraded": upgraded, "added": added, "removed": removed,
            "new_packages": [a["name"] for a in added], "new_install_scripts": [],
            "unusual_sources": unusual, "missing_integrity": []}


FIXERS = {"python": _python, "go": _go, "cargo": _cargo}


def propose(estate: Estate, pkg: Package, plan: npm.Plan, sha: str, out: Path, save) -> dict:
    """Build the change for one "upgrade" plan and capture it as a diff. Nothing is tested here."""
    eco = pkg.ecosystem
    checkout = gitops.checkout(gitops_mirror(estate, pkg), sha, estate.workdir / "tmp")
    result: dict = {"package": pkg.id, "commit": sha, "plan": plan.to_dict(), "notes": []}
    try:
        with bridge.toolbox(estate, pkg, bridge.new_id("propose"), checkout) as tb:
            if eco == "go":
                tb.run("go mod download", timeout=1200)
            before = advisories.scan(tb, eco, pkg.install)
            result["audit_before"] = before.to_dict()
            if before.error:
                result["status"] = "no-candidate"
                result["notes"].append(f"the audit before the change failed: {before.error}")
                return save(out, result)
            tree_before = _tree(tb, pkg, checkout)
            if not FIXERS[eco](tb, pkg, checkout, plan, result):
                result["status"] = "no-candidate"
                return save(out, result)
            after = advisories.scan(tb, eco, pkg.install)
            if after.error:
                result["status"] = "no-candidate"
                result["notes"].append(f"the change did not install or audit cleanly: {after.error}")
                return save(out, result)
            tree_after = _tree(tb, pkg, checkout)
            result["version"] = plan.suggested_version if eco != "cargo" else _cargo_version(
                tree_after, plan.dependency) or "latest compatible"
            result["audit_after"] = after.to_dict()
            root = bridge.repo_root(pkg)
            tb.run(f"git -C {root} diff --binary > /tmp/change.patch", timeout=60, workdir="/")
            tb.run(f"git -C {root} diff --name-only > /tmp/changed.txt", timeout=60, workdir="/")
            out.mkdir(parents=True, exist_ok=True)
            tb.copy_out("/tmp/change.patch", out / "change.patch")
            tb.copy_out("/tmp/changed.txt", out / "changed.txt")
    finally:
        gitops.remove_checkout(checkout)

    changed = [x for x in (out / "changed.txt").read_text().split() if x]
    result["changed_files"] = changed
    result["unexpected_files"] = [c for c in changed if c not in result.get("allowed_files", [])]
    if not changed:
        result["status"] = "no-change"
        return save(out, result)
    result["lock_diff"] = tree_diff(tree_before, tree_after, keyed_by_version=(eco == "cargo"))
    # The upgraded dependency itself is the point of the change, not a new package.
    b_ids, a_ids = before.advisory_ids(), after.advisory_ids()
    targeted = {a.id for a in plan.advisories}
    result["fixed_advisories"] = sorted(targeted - a_ids)
    result["remaining_advisories"] = sorted(targeted & a_ids)
    result["introduced_advisories"] = sorted(a_ids - b_ids)
    if result["remaining_advisories"] and eco == "cargo":
        result["notes"].append("the newest semver-compatible version still has the advisory; the fix "
                               "needs a new major in Cargo.toml.")
    current = next((a.range.split("==", 1)[-1].split("@", 1)[-1] for a in plan.advisories if a.range), "")
    result["major"] = bool(current and eco != "cargo" and advisories.is_major(current, result["version"]))
    result["diffstat"] = gitops.diff_stat(out / "change.patch")
    result["status"] = "proposed"
    return save(out, result)


def _tree(tb, pkg: Package, checkout: Path) -> dict[str, str]:
    if pkg.ecosystem == "python":
        return _python_tree(tb)
    if pkg.ecosystem == "go":
        return _go_tree(tb)
    return _cargo_tree(tb, pkg, checkout)


def _cargo_version(tree: dict[str, str], crate: str) -> str | None:
    versions = [v for k, v in tree.items() if k.split(" ", 1)[0] == crate]
    return max(versions, key=advisories._version_key) if versions else None


def gitops_mirror(estate: Estate, pkg: Package) -> Path:
    return estate.repos_dir / f"{pkg.repo.name}.git"
