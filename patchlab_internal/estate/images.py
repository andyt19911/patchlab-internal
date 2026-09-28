"""Container images: scan each Dockerfile's base images, and move a runtime that is out of support.

Scan. Every ``FROM`` in a listed Dockerfile is pulled and scanned with Trivy
(OS packages and the language packages the base ships). Trivy runs in its own
container on a ``docker save`` of the image: it never gets the Docker socket.

Runtime support. Official runtime images (node, python, golang, alpine, ...)
name their release line in the tag. A line past its end of life gets no more
security fixes, so PatchLab proposes the lowest supported line with at least
12 months left. End-of-life dates come from endoflife.date when the runner
can reach it, else from the dated table below.

Proposal. The Dockerfile's FROM lines change, and the linked package's checks
run on the new line (its sandbox image moved the same way) and on the current
one; nothing that passes today may fail on the new line. The new base is
re-scanned: it may not bring more fixable high or critical vulnerabilities.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

TRIVY_IMAGE = os.environ.get("PATCHLAB_INTERNAL_TRIVY_IMAGE", "aquasec/trivy:0.74.0")
# A registry mirror for Trivy's database (e.g. mirror.gcr.io/aquasec/trivy-db) where ghcr.io is unreachable.
TRIVY_DB = os.environ.get("PATCHLAB_INTERNAL_TRIVY_DB_REPOSITORY")
# A pull-through mirror of Docker Hub (e.g. mirror.gcr.io) for runners that can't reach it directly.
HUB_MIRROR = os.environ.get("PATCHLAB_INTERNAL_DOCKERHUB_MIRROR")
BUILD_TIMEOUT = int(os.environ.get("PATCHLAB_INTERNAL_IMAGE_BUILD_TIMEOUT", "1200"))

# Published end-of-life dates, used when endoflife.date is unreachable. Dated,
# so a stale table is visible: refresh it from the projects' own schedules.
EOL_TABLE_DATE = "2026-09-28"
EOL_TABLE = {
    "node": {"18": "2025-04-30", "20": "2026-04-30", "22": "2027-04-30", "24": "2028-04-30"},
    "python": {"3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31",
               "3.13": "2029-10-31", "3.14": "2030-10-31"},
    "alpine": {"3.19": "2025-11-01", "3.20": "2026-04-01", "3.21": "2026-11-01", "3.22": "2027-05-01",
               "3.23": "2027-11-01"},
}
# Node's odd majors are never LTS; they are not proposed.
LTS_ONLY = {"node": lambda line: int(line) % 2 == 0}
ENDOFLIFE_PRODUCT = {"node": "nodejs", "python": "python", "alpine": "alpine-linux"}
MIN_RUNWAY_DAYS = 365

FROM_LINE = re.compile(r"^(?P<lead>\s*FROM\s+(?:--platform=\S+\s+)?)(?P<image>\S+)(?P<rest>.*)$", re.I)
TAG = re.compile(r"^(?P<line>\d+(?:\.\d+)?)(?P<patch>(?:\.\d+)*)(?P<variant>-.+)?$")


@dataclass
class Base:
    image: str            # as written, e.g. node:20-alpine
    repo: str             # node (library images) or org/name
    tag: str
    line: str | None      # release line in the tag: 20, 3.11
    variant: str          # -alpine, -slim, "" ...

    @property
    def runtime(self) -> str:
        return self.repo.rsplit("/", 1)[-1]


def parse_base(image: str) -> Base:
    ref = image.split("@", 1)[0]
    repo, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "latest")
    repo = repo.removeprefix("docker.io/").removeprefix("library/")
    m = TAG.match(tag)
    return Base(image=image, repo=repo, tag=tag, line=m["line"] if m else None,
                variant=(m["variant"] or "") if m else "")


def dockerfile_bases(text: str) -> list[str]:
    """Base images of every stage, skipping references to earlier stages and ARG-built names."""
    stages, out = set(), []
    for line in text.splitlines():
        m = FROM_LINE.match(line)
        if not m:
            continue
        image = m["image"]
        alias = re.search(r"\bAS\s+(\S+)", m["rest"], re.I)
        if image.lower() not in stages and "$" not in image and image.lower() != "scratch":
            out.append(image)
        if alias:
            stages.add(alias.group(1).lower())
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- support dates

def eol_dates(runtime: str) -> tuple[dict[str, str], str]:
    """line -> end-of-life date, and where it came from."""
    product = ENDOFLIFE_PRODUCT.get(runtime)
    if product:
        try:
            with urllib.request.urlopen(f"https://endoflife.date/api/{product}.json", timeout=15) as r:
                rows = json.load(r)
            dates = {str(row["cycle"]): str(row["eol"]) for row in rows if isinstance(row.get("eol"), str)}
            if dates:
                return dates, "endoflife.date"
        except (OSError, ValueError, KeyError):
            pass
    return EOL_TABLE.get(runtime, {}), f"PatchLab's table of {EOL_TABLE_DATE}"


def support(base: Base, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    dates, source = eol_dates(base.runtime)
    if not base.line or base.line not in dates:
        return {"status": "unknown", "source": source}
    eol = dt.date.fromisoformat(dates[base.line])
    out = {"line": base.line, "eol": dates[base.line], "source": source,
           "status": "eol" if eol <= today else "ok", "days_left": (eol - today).days}
    if out["status"] == "eol" or out["days_left"] < 90:
        target = next_line(base.runtime, base.line, dates, today)
        if target:
            out["target"] = target
    return out


def _line_key(line: str) -> tuple:
    return tuple(int(p) for p in line.split("."))


def next_line(runtime: str, current: str, dates: dict[str, str], today: dt.date) -> str | None:
    """The lowest newer line with at least MIN_RUNWAY_DAYS of support left."""
    lts = LTS_ONLY.get(runtime, lambda _l: True)
    for line in sorted(dates, key=_line_key):
        if _line_key(line) <= _line_key(current) or not lts(line):
            continue
        if (dt.date.fromisoformat(dates[line]) - today).days >= MIN_RUNWAY_DAYS:
            return line
    return None


def moved(image: str, runtime: str, old: str, new: str) -> str:
    """``image`` with its ``runtime`` release line moved from ``old`` to ``new`` (other images unchanged)."""
    b = parse_base(image)
    if b.runtime != runtime or b.line != old:
        return image
    tag = new + b.variant                     # a pinned patch version or digest is dropped with the line
    prefix = image.split("@", 1)[0].rsplit(":", 1)[0]
    return f"{prefix}:{tag}"


def rewrite_dockerfile(text: str, runtime: str, old: str, new: str) -> tuple[str, int]:
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        m = FROM_LINE.match(line.rstrip("\r\n"))
        if m:
            new_image = moved(m["image"], runtime, old, new)
            if new_image != m["image"]:
                line = f"{m['lead']}{new_image}{m['rest']}" + line[len(line.rstrip("\r\n")):]
                n += 1
        out.append(line)
    return "".join(out), n


# ---------------------------------------------------------------- trivy

def _docker(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def pull(image: str) -> str | None:
    """Pull ``image`` (through HUB_MIRROR for Docker Hub images when set). None, or the error."""
    res = _docker("pull", "-q", image)
    if res.returncode == 0:
        return None
    b = parse_base(image)
    hub = "/" not in b.repo or "." not in b.repo.split("/", 1)[0]
    if HUB_MIRROR and hub and "@" not in image:
        path = b.repo if "/" in b.repo else f"library/{b.repo}"
        via = f"{HUB_MIRROR.rstrip('/')}/{path}:{b.tag}"
        if _docker("pull", "-q", via).returncode == 0 and _docker("tag", via, image).returncode == 0:
            return None
    return f"pull failed: {res.stderr.strip()[-300:]}"


def scan_image(image: str, workdir: Path, ca_bundle: Path | None = None) -> dict:
    """Pull ``image`` and scan it with Trivy. Returns counts and the vulnerabilities with a fix."""
    work = workdir / "trivy"
    work.mkdir(parents=True, exist_ok=True)
    err = pull(image)
    if err:
        return {"image": image, "error": err}
    tar = work / "image.tar"
    save = _docker("save", image, "-o", str(tar))
    if save.returncode != 0:
        return {"image": image, "error": f"save failed: {save.stderr.strip()[-300:]}"}
    args = ["run", "--rm", "--security-opt", "no-new-privileges", "-v", f"{work}:/w"]
    if ca_bundle:
        args += ["-v", f"{ca_bundle}:/etc/ssl/certs/ca-certificates.crt:ro",
                 "-e", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]
    args += [TRIVY_IMAGE, "image", "--cache-dir", "/w/cache", "--scanners", "vuln", "--format", "json",
             "--quiet", "--skip-java-db-update", "--input", "/w/image.tar"]
    if TRIVY_DB:
        args += ["--db-repository", TRIVY_DB]
    try:
        res = _docker(*args, timeout=1800)
    finally:
        tar.unlink(missing_ok=True)
    if res.returncode != 0:
        return {"image": image, "error": f"trivy failed: {res.stderr.strip()[-300:]}"}
    return summarise_trivy(image, res.stdout)


def summarise_trivy(image: str, text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {"image": image, "error": f"trivy did not return JSON: {e}"}
    os_meta = (data.get("Metadata") or {}).get("OS") or {}
    counts: dict[str, int] = {}
    fixable = []
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN").lower()
            counts[sev] = counts.get(sev, 0) + 1
            if v.get("FixedVersion"):
                fixable.append({"id": v["VulnerabilityID"], "package": v.get("PkgName"),
                                "installed": v.get("InstalledVersion"), "fixed": v["FixedVersion"],
                                "severity": sev, "class": r.get("Class"), "target": r.get("Target")})
    return {"image": image, "error": None, "os": f"{os_meta.get('Family', '?')} {os_meta.get('Name', '')}".strip(),
            "os_eosl": bool(os_meta.get("EOSL")), "counts": counts, "fixable": fixable,
            "fixable_high": sum(1 for f in fixable if f["severity"] in ("high", "critical"))}


# ---------------------------------------------------------------- the change

# The CI key that pins the same runtime, per image name.
CI_KEY = {"node": "node-version", "python": "python-version", "golang": "go-version"}
VERSION_FILES = {"node": (".nvmrc", ".node-version"), "python": (".python-version",)}


def companion_edits(text: str, runtime: str, old: str, new: str) -> tuple[str, int]:
    """Move a single-valued ``node-version: 20`` (or python-version, go-version)
    in a CI workflow. A version matrix is left alone: it tests several lines on
    purpose, and the proposal notes it."""
    key = CI_KEY.get(runtime)
    if not key:
        return text, 0
    pat = re.compile(rf"^(?P<lead>\s*{key}:\s*)(?P<q>['\"]?)v?{re.escape(old)}(?P<x>(?:\.x)?)(?P=q)(?P<rest>\s*(?:#.*)?)$")
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        m = pat.match(body)
        if m:
            body = f"{m['lead']}{m['q']}{new}{m['x']}{m['q']}{m['rest']}"
            n += 1
        out.append(body + line[len(line.rstrip("\r\n")):])
    return "".join(out), n


JOB = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")


def edit_workflow(text: str, pkg_rel: str, runtime: str, old: str, new: str) -> tuple[str, int]:
    """Move the runtime pin only in the jobs that build or test this package (they
    name its directory), so a repo's other jobs keep the line they chose."""
    if pkg_rel in (".", ""):
        return text, 0
    mentions = re.compile(rf"(^|[\s'\"/=:]){re.escape(pkg_rel)}(/|['\"\s]|$)", re.M)
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == "jobs:") + 1
    except StopIteration:
        return text, 0
    bounds = [i for i in range(start, len(lines)) if JOB.match(lines[i].rstrip("\r\n"))] + [len(lines)]
    out, total = lines[:bounds[0]] if bounds[:-1] else lines, 0
    for a, b in zip(bounds, bounds[1:]):
        block = "".join(lines[a:b])
        if mentions.search(block):
            block, n = companion_edits(block, runtime, old, new)
            total += n
        out.append(block)
    return "".join(out), total


def apply_runtime_move(checkout: Path, image, runtime: str, old: str, new: str) -> list[str]:
    """Edit the Dockerfile, and the CI pins and version files in its package, in
    place. Returns the files changed (repo-relative)."""
    changed = []
    df = checkout / image.dockerfile
    text, n = rewrite_dockerfile(df.read_text(encoding="utf-8"), runtime, old, new)
    if n:
        df.write_text(text, encoding="utf-8")
        changed.append(image.dockerfile)
    pkg_rel = image.package or Path(image.dockerfile).parent.as_posix()
    for wf in sorted((checkout / ".github" / "workflows").glob("*.y*ml")):
        text, n = edit_workflow(wf.read_text(encoding="utf-8"), pkg_rel, runtime, old, new)
        if n:
            wf.write_text(text, encoding="utf-8")
            changed.append(wf.relative_to(checkout).as_posix())
    pkg_dir = checkout / pkg_rel
    for name in VERSION_FILES.get(runtime, ()):
        for f in {checkout / name, pkg_dir / name}:
            if f.is_file() and f.read_text().strip().lstrip("v") in (old, f"{old}.x"):
                f.write_text(new + "\n")
                changed.append(f.relative_to(checkout).as_posix())
    return changed


def build(checkout: Path, image, tag: str) -> tuple[bool, str]:
    """``docker build`` the Dockerfile in its context. The repo's own build
    steps run here, as its tests already do in the sandbox."""
    context = checkout / (image.context or Path(image.dockerfile).parent.as_posix())
    for ref in dockerfile_bases((checkout / image.dockerfile).read_text(encoding="utf-8")):
        pull(ref)
    try:
        res = _docker("build", "-q", "-t", tag, "-f", str(checkout / image.dockerfile), str(context),
                      timeout=BUILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"the build did not finish within {BUILD_TIMEOUT}s"
    finally:
        _docker("rmi", "-f", tag, timeout=300)
    return res.returncode == 0, (res.stderr or res.stdout).strip()[-800:]


def worst_fixable(scans: list[dict]) -> int | None:
    if any(s.get("error") for s in scans):
        return None
    return sum(s.get("fixable_high", 0) for s in scans)


# ---------------------------------------------------------------- scan, propose, decide

def image_dir(estate, repo, image) -> Path:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{repo.name}/{image.dockerfile}").strip("-")
    return estate.state_dir / "images" / slug


def scan_repo(estate, repo, sha: str, today: dt.date | None = None) -> list[dict]:
    """Scan every base image of every listed Dockerfile at ``sha``; one scan.json per Dockerfile."""
    from . import gitops, state
    mirror = estate.repos_dir / f"{repo.name}.git"
    results = []
    for image in repo.images:
        try:
            text = gitops.git("show", f"{sha}:{image.dockerfile}", cwd=mirror)
        except gitops.GitError as e:
            res = {"repo": repo.name, "dockerfile": image.dockerfile, "commit": sha,
                   "error": f"not found at {sha[:10]}: {e}"}
            state.write_json(image_dir(estate, repo, image) / "scan.json", res)
            results.append(res)
            continue
        bases = []
        for ref in dockerfile_bases(text):
            b = parse_base(ref)
            entry = {"image": ref, "runtime": b.runtime, "support": support(b, today)}
            entry["scan"] = scan_image(ref, estate.workdir, estate.ca_bundle)
            bases.append(entry)
        res = {"repo": repo.name, "dockerfile": image.dockerfile, "commit": sha, "package": image.package,
               "when": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "error": None,
               "bases": bases, "moves": moves_for(bases)}
        state.write_json(image_dir(estate, repo, image) / "scan.json", res)
        results.append(res)
    return results


def moves_for(bases: list[dict]) -> list[dict]:
    """One move per (runtime, line) past or near end of life that has a supported target."""
    out, seen = [], set()
    for b in bases:
        s = b.get("support") or {}
        if s.get("target") and (b["runtime"], s["line"]) not in seen:
            seen.add((b["runtime"], s["line"]))
            out.append({"runtime": b["runtime"], "from": s["line"], "to": s["target"], "eol": s["eol"],
                        "status": s["status"]})
    return out


def _sandbox_candidate(pkg, runtime: str, old: str, new: str) -> tuple[str | None, str]:
    """The sandbox image the package's checks should run on after the move, and why."""
    if not pkg.image:
        return None, "the package has no sandbox image"
    b = parse_base(pkg.image)
    if b.runtime != runtime:
        return None, f"the package's checks run on {pkg.image}, not on {runtime}"
    if b.line == new:
        return pkg.image, f"the package's checks already run on {pkg.image}"
    return f"{pkg.image.split('@', 1)[0].rsplit(':', 1)[0]}:{new}{b.variant}", "moved with the Dockerfile"


def propose_move(estate, repo, image, sha: str, move: dict, confirm_failures: bool = True) -> dict:
    """Build the runtime move for one Dockerfile, test it and decide."""
    import dataclasses

    from . import bridge, gitops, pipeline, state
    runtime, old, new = move["runtime"], move["from"], move["to"]
    key = f"{runtime}-{old}-to-{new}"
    run_id = bridge.new_id("image")
    out = image_dir(estate, repo, image) / "proposals" / key / run_id
    out.mkdir(parents=True, exist_ok=True)
    prop: dict = {"kind": "runtime", "repo": repo.name, "dockerfile": image.dockerfile, "commit": sha,
                  "move": move, "notes": [],
                  "plan": {"kind": "runtime", "key": key,
                           "title": f"{image.dockerfile}: {runtime} {old} -> {new}"}}
    pipeline.log(f"{repo.name}: {prop['plan']['title']}")
    checkout = gitops.checkout(estate.repos_dir / f"{repo.name}.git", sha, estate.workdir / "tmp")
    try:
        before_bases = [b for b in dockerfile_bases((checkout / image.dockerfile).read_text(encoding="utf-8"))]
        built_before = build(checkout, image, f"patchlab-build-{run_id}-a")
        changed = apply_runtime_move(checkout, image, runtime, old, new)
        prop["changed_files"] = changed
        gitops.git("diff", "--binary", "--output", str(out / "change.patch"), cwd=checkout)
        after_text = (checkout / image.dockerfile).read_text(encoding="utf-8")
        after_bases = dockerfile_bases(after_text)
        built_after = build(checkout, image, f"patchlab-build-{run_id}-b")
    finally:
        gitops.remove_checkout(checkout)
    prop["build"] = {"before": {"ok": built_before[0], "tail": built_before[1]},
                     "after": {"ok": built_after[0], "tail": built_after[1]}}
    new_refs = [r for r in after_bases if r not in before_bases]
    old_refs = [r for r in before_bases if r not in after_bases]
    prop["scans_before"] = [scan_image(r, estate.workdir, estate.ca_bundle) for r in old_refs]
    prop["scans_after"] = [scan_image(r, estate.workdir, estate.ca_bundle) for r in new_refs]
    prop["diffstat"] = gitops.diff_stat(out / "change.patch") if changed else []

    tests: dict = {"status": "not-linked"}
    if image.package is not None:
        pkg = next(p for p in repo.packages if p.path == image.package)
        cand, why = _sandbox_candidate(pkg, runtime, old, new)
        tests = {"status": "not-applicable", "why": why, "package": pkg.id}
        if cand and not pkg.unsupported:
            current = pipeline.test_change(estate, pkg, sha, None, "runtime baseline", out / "runs", run_id + "-cur")
            moved_pkg = dataclasses.replace(pkg, image=cand)
            after = pipeline.test_change(estate, moved_pkg, sha, None, f"on {cand}", out / "runs", run_id + "-new")
            cur_fail, new_fail = set(pipeline._failing(current.report)), set(pipeline._failing(after.report))
            broken = sorted(new_fail - cur_fail)
            if broken and confirm_failures:
                again = pipeline.test_change(estate, moved_pkg, sha, None, f"on {cand} (again)", out / "runs",
                                             run_id + "-new2")
                still = set(pipeline._failing(again.report))
                tests["flaky"] = sorted(t for t in broken if t not in still)
                broken = sorted(t for t in broken if t in still)
            tests.update(status="ran", sandbox_image=cand, why=why, broken=broken,
                         fixed=sorted(cur_fail - new_fail), still_failing=sorted(cur_fail & new_fail),
                         error=(summarise_error(current.report) or summarise_error(after.report)),
                         passing_after=pipeline.summarise_health(pkg, sha, after.report, None)["passing_tests"],
                         report=str(after.report_dir) if after.report_dir else None)
            if cand != pkg.image:
                prop["estate_image_update"] = {"package": pkg.id, "from": pkg.image, "to": cand}
    prop["tests"] = tests
    decision = decide(prop)
    state.write_json(out / "proposal.json", prop)
    state.write_json(out / "decision.json", decision.to_dict())
    (out / "pr.md").write_text(pr_body(prop, decision), encoding="utf-8")
    pipeline.log(f"{repo.name}: {key}: {decision.verdict}. {decision.summary}")
    return {"proposal": prop, "decision": decision.to_dict(), "dir": str(out)}


def summarise_error(report: dict | None) -> str | None:
    from . import triage
    t = triage._target(report) if report else None
    if t is None:
        return "the test run produced no report"
    errs = [f["message"] for f in t.get("findings", []) if f["severity"] == "error"]
    return "; ".join(errs) or None


def decide(prop: dict):
    """The gate for a runtime move. Fails closed like every other gate: what
    could not be checked is never a pass."""
    from . import triage
    G = triage.GateItem
    gate = []
    b = prop["build"]
    if b["after"]["ok"]:
        gate.append(G("image builds", True, "the Dockerfile builds on the new line"))
    elif b["before"]["ok"]:
        gate.append(G("image builds", False, "it builds today and not on the new line",
                      [b["after"]["tail"][-300:]]))
    else:
        gate.append(G("image builds", False, "the Dockerfile does not build on this runner today either, "
                      "so the build was not compared", [b["before"]["tail"][-300:]], kind="review"))
    t = prop["tests"]
    if t["status"] != "ran":
        gate.append(G("checks pass on the new runtime", False,
                      t.get("why") or "no package's checks are linked to this image", kind="review"))
    elif t.get("error"):
        gate.append(G("checks pass on the new runtime", False, t["error"], kind="inconclusive"))
    elif t["broken"]:
        gate.append(G("checks pass on the new runtime", False,
                      f"{len(t['broken'])} test(s) pass today and fail on {t['sandbox_image']}", t["broken"][:20]))
    elif t.get("flaky"):
        gate.append(G("checks pass on the new runtime", False, "failures did not reproduce (flaky)",
                      t["flaky"], kind="inconclusive"))
    else:
        gate.append(G("checks pass on the new runtime", True,
                      f"{t['passing_after']} passing on {t['sandbox_image']}; nothing that passes today fails"))
    before, after = worst_fixable(prop["scans_before"]), worst_fixable(prop["scans_after"])
    if before is None or after is None:
        errs = [s["error"] for s in prop["scans_before"] + prop["scans_after"] if s.get("error")]
        gate.append(G("no new fixable high or critical vulnerabilities", False, "a scan failed", errs,
                      kind="inconclusive"))
    else:
        gate.append(G("no new fixable high or critical vulnerabilities", after <= before,
                      f"{before} before, {after} after"))
    unexpected = [f for f in prop.get("changed_files", [])
                  if f != prop["dockerfile"] and not f.startswith(".github/workflows/")
                  and Path(f).name not in (".nvmrc", ".node-version", ".python-version")]
    gate.append(G("only the runtime pins changed", not unexpected and bool(prop.get("changed_files")),
                  ", ".join(prop.get("changed_files", [])) or "nothing changed", unexpected))
    failed = [g for g in gate if not g.ok]
    if any(g.kind == "inconclusive" for g in failed):
        verdict = triage.INCONCLUSIVE
    elif any(g.kind == "blocker" for g in failed):
        verdict = triage.BLOCKED
    elif failed:
        verdict = triage.REVIEW
    else:
        verdict = triage.READY
    m = prop["move"]
    summary = {
        triage.READY: f"Tested and safe to review: {m['runtime']} {m['to']} builds, passes the same checks "
                      "and brings no new fixable high or critical vulnerabilities.",
        triage.REVIEW: "The checks that ran pass, but a person needs to look first: "
                       + "; ".join(g.name for g in failed) + ".",
        triage.BLOCKED: "Not proposed: " + "; ".join(f"{g.name} ({g.detail})" for g in failed
                                                     if g.kind == "blocker") + ".",
        triage.INCONCLUSIVE: "Could not be decided: " + "; ".join(f"{g.name} ({g.detail})" for g in failed
                                                                  if g.kind == "inconclusive") + ".",
    }[verdict]
    notes = []
    if m["status"] == "eol":
        notes.append(f"{m['runtime']} {m['from']} reached end of life on {m['eol']} and gets no security fixes.")
    if prop.get("estate_image_update"):
        u = prop["estate_image_update"]
        notes.append(f"Once merged, PatchLab tests {u['package']} on {u['to']} (was {u['from']}).")
    return triage.Decision(verdict, summary, gate, ["security", "runtime", "breaking-risk"], notes)


def pr_body(prop: dict, decision) -> str:
    m = prop["move"]
    L = [f"## Move {prop['dockerfile']} from {m['runtime']} {m['from']} to {m['to']}", "",
         f"**{decision.verdict}.** {decision.summary}", "",
         f"Before: the image is built on {m['runtime']} {m['from']}"
         + (f", which reached end of life on {m['eol']} and gets no more security fixes." if m["status"] == "eol"
            else f", which reaches end of life on {m['eol']}."), "",
         f"After: it is built on {m['runtime']} {m['to']}, a supported line.", "", "### Checked", ""]
    for g in decision.gate:
        L.append(f"- {'✅' if g.ok else '❌'} {g.name}: {g.detail}")
        L += [f"  - `{x}`" for x in g.details[:10]]
    L += ["", "### Changed", ""] + [f"- `{f}`" for f in prop.get("changed_files", [])]
    L += [""] + [f"> {n}" for n in decision.notes]
    return "\n".join(L) + "\n"
