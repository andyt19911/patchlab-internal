"""`patchlab-internal estate ...` commands."""

from __future__ import annotations

import json
import sys

from ..config import ConfigError
from ..sandbox import docker_available
from . import digest, manifest, pipeline, state


def _estate(args) -> manifest.Estate:
    return manifest.load(args.manifest)


def _packages(estate: manifest.Estate, names: list[str]) -> list[manifest.Package]:
    return [estate.find(n) for n in names] if names else estate.packages()


def _need_docker() -> None:
    reason = docker_available()
    if reason:
        raise RuntimeError(f"Docker is not available: {reason}")


def cmd_validate(args) -> int:
    est = _estate(args)
    print(f"{est.path.name}: OK ({len(est.repos)} repos, {len(est.packages())} packages)")
    print(f"  workdir : {est.workdir}")
    print(f"  publish : {est.publish}")
    for name, m in est.mirrors.items():
        print(f"  mirror  : {name} <- {m.url}")
    for p in est.packages():
        what = (f"not verified: {p.unsupported}" if p.unsupported else
                f"{p.ecosystem} on {p.image}; {len(p.checks)} checks"
                + (f"; sidecars {', '.join(s.name for s in p.sidecars)}" if p.sidecars else "")
                + (f"; mirrors {', '.join(p.mirrors)}" if p.mirrors else ""))
        print(f"  {p.id:<32} {what}")
    return 0


def cmd_sync(args) -> int:
    est = _estate(args)
    with state.exclusive(est.state_dir):
        heads, errors = pipeline.sync(est, args.repo or None)
    for repo, sha in heads.items():
        print(f"{repo:<28} {sha}")
    for name, err in errors.items():
        print(f"{name:<28} FAILED: {err}", file=sys.stderr)
    return 1 if errors else 0


def cmd_scan(args) -> int:
    est = _estate(args)
    _need_docker()
    with state.exclusive(est.state_dir):
        for pkg in _packages(est, args.package):
            res = pipeline.scan(est, pkg, args.commit)
            if args.json:
                print(json.dumps(res, indent=2))
                continue
            vul = res.get("scan", {}).get("vulnerable", [])
            audited = res.get("scan", {}).get("counts", {}).get("audited")
            of = f" of {audited} audited" if audited is not None else ""
            print(f"{pkg.id} @ {res['commit'][:10]}: " + (res.get("error") or f"{len(vul)} vulnerable{of}"))
            for p in res.get("plans", []):
                print(f"  propose  {p['key']:<22} {p['severity']:<9} {'prod' if p['production'] else 'dev '}  "
                      f"{len(p['advisories'])} advisories")
            for b in res.get("not_fixable", []):
                print(f"  manual   {b['name']:<22} {b['severity']:<9} {b['reason']}")
    return 0


def cmd_propose(args) -> int:
    est = _estate(args)
    _need_docker()
    pkg = est.find(args.package)
    with state.exclusive(est.state_dir):
        results = pipeline.propose_and_test(est, pkg, args.dependency, args.commit,
                                            confirm_failures=not args.no_confirm)
    worst = 0
    for r in results:
        d = r["decision"]
        print(f"\n{d['verdict']}: {r['proposal']['plan']['title']}\n  {d['summary']}\n  {r['dir']}")
        for g in d.get("gate", []):
            print(f"    {'ok ' if g['ok'] else 'NO '} {g['name']}: {g['detail']}")
        worst = max(worst, {"READY": 0, "REVIEW": 0, "BLOCKED": 1, "INCONCLUSIVE": 2}[d["verdict"]])
    return worst


def cmd_health(args) -> int:
    est = _estate(args)
    _need_docker()
    bad = 0
    with state.exclusive(est.state_dir):
        for pkg in _packages(est, args.package):
            s = pipeline.health(est, pkg, args.commit, recheck=not args.no_recheck)
            print(f"{pkg.id:<32} {s['status']}" + (f"  ({len(s.get('failing', []))} failing)"
                                                    if s.get("failing") else ""))
            bad = max(bad, {"healthy": 0, "not-verified": 0, "failing": 0, "broken": 1, "error": 2}[s["status"]])
    return bad


def cmd_digest(args) -> int:
    est = _estate(args)
    path = digest.write(est)
    print(path.read_text(encoding="utf-8") if not args.quiet else path)
    return 0


def cmd_cycle(args) -> int:
    """The scheduled job: sync, health, scan, propose and test every fixable advisory, digest."""
    est = _estate(args)
    _need_docker()
    failures = 0
    with state.exclusive(est.state_dir):
        heads, errors = pipeline.sync(est)
        for name, err in errors.items():
            failures += 1
            pipeline.log(f"sync {name} failed: {err}")
        for pkg in est.packages():
            if pkg.repo.name not in heads:
                # Never test a stale checkout as if it were current.
                continue
            # One package failing to run never stops the others.
            for step in (["health"] if args.no_propose else ["health", "propose"]):
                try:
                    if step == "health":
                        pipeline.health(est, pkg)
                    elif pkg.ecosystem in manifest.SCANNERS and not pkg.unsupported:
                        pipeline.scan(est, pkg)
                        if pkg.ecosystem in manifest.PROPOSERS:
                            pipeline.propose_and_test(est, pkg)
                except Exception as e:   # recorded in the digest via the missing state, and here
                    failures += 1
                    pipeline.log(f"{pkg.id}: {step} failed: {type(e).__name__}: {e}")
    path = digest.write(est)
    print(path)
    return 2 if failures else 0


def register(sub) -> None:
    e = sub.add_parser("estate", help="keep the estate's repositories up to date and tested (estate.toml)")
    e.add_argument("--manifest", "-m", default="estate.toml", help="path to estate.toml")
    es = e.add_subparsers(dest="estate_command", required=True)

    v = es.add_parser("validate", help="check estate.toml without running anything")
    v.set_defaults(func=cmd_validate)

    s = es.add_parser("sync", help="fetch every repo and private-dependency mirror")
    s.add_argument("repo", nargs="*")
    s.set_defaults(func=cmd_sync)

    sc = es.add_parser("scan", help="audit dependencies and list the changes that would fix them")
    sc.add_argument("package", nargs="*", help="repo/path (default: all)")
    sc.add_argument("--commit", help="scan this commit instead of the branch head")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_scan)

    p = es.add_parser("propose", help="build, test and triage fixes for one package")
    p.add_argument("package", help="repo/path, e.g. subsovereign/backend")
    p.add_argument("dependency", nargs="?", help="only this dependency (or 'in-range-fixes')")
    p.add_argument("--commit")
    p.add_argument("--no-confirm", action="store_true",
                   help="don't re-run a failing test to separate real failures from flaky ones")
    p.set_defaults(func=cmd_propose)

    h = es.add_parser("health", help="run each package's checks on the current code (no change)")
    h.add_argument("package", nargs="*")
    h.add_argument("--commit")
    h.add_argument("--no-recheck", action="store_true", help="don't re-run new failures")
    h.set_defaults(func=cmd_health)

    d = es.add_parser("digest", help="write today's digest from the state directory")
    d.add_argument("-q", "--quiet", action="store_true", help="print only the path")
    d.set_defaults(func=cmd_digest)

    c = es.add_parser("cycle", help="the scheduled job: sync, health, scan, propose, digest")
    c.add_argument("--no-propose", action="store_true", help="health and digest only")
    c.set_defaults(func=cmd_cycle)


def run(args) -> int:
    try:
        return args.func(args)
    except ConfigError:
        raise
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
