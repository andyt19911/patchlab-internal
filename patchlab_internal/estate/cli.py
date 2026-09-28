"""`patchlab-internal estate ...` commands."""

from __future__ import annotations

import json
import sys

from ..config import ConfigError
from ..sandbox import docker_available
from . import digest, images, manifest, pipeline, publish, state, workflows


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
    for r in est.repos:
        for i in r.images:
            print(f"  image   : {r.name}/{i.dockerfile}" + (f" (checks: {r.name}/{i.package})" if i.package else ""))
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
                print(f"  propose  {p['key']:<22} {p['severity']:<9} {('?   ' if res.get('production_known') is False else 'prod' if p['production'] else 'dev ')}  "
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


def cmd_repair(args) -> int:
    est = _estate(args)
    _need_docker()
    pkg = est.find(args.package)
    with state.exclusive(est.state_dir):
        r = pipeline.repair_and_test(est, pkg, args.test or None, args.commit,
                                     confirm_failures=not args.no_confirm)
    d = r["decision"]
    print(f"\n{d['verdict']}: {r['proposal']['plan']['title']}\n  {d['summary']}\n  {r['dir']}")
    for g in d.get("gate", []):
        print(f"    {'ok ' if g['ok'] else 'NO '} {g['name']}: {g['detail']}")
    return {"READY": 0, "REVIEW": 0, "BLOCKED": 1, "INCONCLUSIVE": 2}[d["verdict"]]


def run_images(est: manifest.Estate, repo: manifest.Repo, propose: bool, sha: str | None = None) -> list[dict]:
    """Scan a repo's Dockerfiles; with ``propose``, build, test and decide each runtime move
    (once per commit, Dockerfile and move)."""
    sha = sha or gitops_head(est, repo)
    results = []
    for res in images.scan_repo(est, repo, sha):
        image = next(i for i in repo.images if i.dockerfile == res["dockerfile"])
        for move in res.get("moves", []) if propose else []:
            key = f"{move['runtime']}-{move['from']}-to-{move['to']}"
            _, prev = state.latest(images.image_dir(est, repo, image) / "proposals" / key, "proposal.json")
            if prev and prev.get("commit") == sha:
                continue
            results.append(images.propose_move(est, repo, image, sha, move))
    return results


def gitops_head(est: manifest.Estate, repo: manifest.Repo) -> str:
    from . import gitops
    return gitops.head(pipeline.mirror_path(est, repo.name), repo.branch)


def cmd_images(args) -> int:
    est = _estate(args)
    _need_docker()
    repos = [est.repo(n) for n in args.repo] if args.repo else [r for r in est.repos if r.images]
    worst = 0
    with state.exclusive(est.state_dir):
        for repo in repos:
            results = run_images(est, repo, args.propose, args.commit)
            for image in repo.images:
                res = state.read_json(images.image_dir(est, repo, image) / "scan.json") or {}
                print(f"{repo.name}/{image.dockerfile}" + (f": {res['error']}" if res.get("error") else ""))
                for b in res.get("bases", []):
                    sup, sc = b["support"], b["scan"]
                    life = {"eol": f"END OF LIFE since {sup.get('eol')}", "ok": f"supported to {sup.get('eol')}",
                            "unknown": "support dates unknown"}[sup["status"]]
                    vulns = sc.get("error") or (f"{sc['os']}{' (EOSL)' if sc['os_eosl'] else ''}; "
                                                f"{sum(sc['counts'].values())} vulnerabilities, "
                                                f"{len(sc['fixable'])} fixable ({sc['fixable_high']} high/critical)")
                    print(f"  {b['image']:<28} {life}; {vulns}"
                          + (f"; move to {sup['target']}" if sup.get("target") else ""))
            for r in results:
                d = r["decision"]
                print(f"\n{d['verdict']}: {r['proposal']['plan']['title']}\n  {d['summary']}\n  {r['dir']}")
                for g in d.get("gate", []):
                    print(f"    {'ok ' if g['ok'] else 'NO '} {g['name']}: {g['detail']}")
                worst = max(worst, {"READY": 0, "REVIEW": 0, "BLOCKED": 1, "INCONCLUSIVE": 2}[d["verdict"]])
    return worst


def cmd_code_scan(args) -> int:
    est = _estate(args)
    _need_docker()
    worst = 0
    with state.exclusive(est.state_dir):
        for pkg in _packages(est, args.package):
            if pkg.unsupported:
                continue
            d = pipeline.code_scan(est, pkg, args.commit)
            c = d["counts"]
            print(f"{pkg.id} @ {d['commit'][:10]}: {c['high']} high, {c['medium']} medium, {c['low']} low"
                  + ("" if d["complete"] else f"  INCOMPLETE: {d['tools']}"))
            for p in d["plans"]:
                print(f"  fix      {p['key']:<50} {p['title']}")
            worst = max(worst, 0 if d["complete"] else 2)
    return worst


def cmd_code_fix(args) -> int:
    est = _estate(args)
    _need_docker()
    pkg = est.find(args.package)
    with state.exclusive(est.state_dir):
        results = pipeline.code_fix_and_test(est, pkg, args.key, args.commit, confirm_failures=not args.no_confirm)
    worst = 0
    for r in results:
        d = r["decision"]
        print(f"\n{d['verdict']}: {r['proposal']['plan']['title']}\n  {d['summary']}\n  {r['dir']}")
        for g in d.get("gate", []):
            print(f"    {'ok ' if g['ok'] else 'NO '} {g['name']}: {g['detail']}")
        worst = max(worst, {"READY": 0, "REVIEW": 0, "BLOCKED": 1, "INCONCLUSIVE": 2}[d["verdict"]])
    return worst


def run_actions(est: manifest.Estate, repo: manifest.Repo, propose: bool, sha: str | None = None) -> dict | None:
    sha = sha or gitops_head(est, repo)
    data = workflows.latest_scan(est, repo, sha)
    if not propose or not any(f["rule"] in ("unpinned-action", "no-permissions") for f in data["findings"]):
        return None
    _, prev = state.latest(est.state_dir / "workflows" / repo.name, "proposal.json")
    if prev and prev.get("commit") == sha:
        return None
    return workflows.propose(est, repo, sha)


def cmd_actions(args) -> int:
    est = _estate(args)
    repos = [est.repo(n) for n in args.repo] if args.repo else est.repos
    worst = 0
    with state.exclusive(est.state_dir):
        for repo in repos:
            r = run_actions(est, repo, args.propose, args.commit)
            data = state.read_json(est.state_dir / "workflows" / repo.name / "scan.json") or {}
            by: dict[str, int] = {}
            for f in data.get("findings", []):
                by[f["rule"]] = by.get(f["rule"], 0) + 1
            print(f"{repo.name}: " + (", ".join(f"{n} {k}" for k, n in sorted(by.items())) or "nothing found"))
            if r:
                d = r["decision"]
                print(f"  {d['verdict']}: {r['proposal']['plan']['title']}\n  {d['summary']}\n  {r['dir']}")
                for g in d["gate"]:
                    print(f"    {'ok ' if g['ok'] else 'NO '} {g['name']}: {g['detail']}")
                worst = max(worst, 0 if d["verdict"] == "READY" else 1)
    return worst


def cmd_publish(args) -> int:
    est = _estate(args)
    heads = {r.name: gitops_head(est, r) for r in est.repos
             if (est.repos_dir / f"{r.name}.git" / "HEAD").is_file()}
    with state.exclusive(est.state_dir):
        steps = publish.run(est, heads, apply=args.apply, max_prs=args.max_prs)
    for s in steps:
        res = s.get("result", {})
        what = res.get("url") or res.get("why") or s["why"]
        print(f"{s['action'] if not res else res['status']:<8} {s['repo']:<24} {s['branch']}\n         {what}")
    if not args.apply:
        print("\n(dry run: nothing pushed. --apply publishes, when estate.toml has publish = \"draft-pr\")")
    return 1 if any(s.get("result", {}).get("status") == "failed" for s in steps) else 0


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
    """The scheduled job: sync, health (and repair, with a [repair] agent), scan, propose and
    test every fixable advisory, digest."""
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
                        h = pipeline.health(est, pkg)
                        if est.repair and h.get("failing") and not args.no_propose \
                                and not pipeline.repaired_already(est, pkg, h):
                            pipeline.repair_and_test(est, pkg)
                    elif pkg.ecosystem in manifest.SCANNERS and not pkg.unsupported:
                        pipeline.scan(est, pkg)
                        if pkg.ecosystem in manifest.PROPOSERS:
                            pipeline.propose_and_test(est, pkg)
                    if step == "propose" and not pkg.unsupported:
                        code = pipeline.code_scan(est, pkg)
                        for plan in code["plans"] if est.repair else []:
                            if not pipeline.code_fixed_already(est, pkg, code["commit"], plan["key"]):
                                pipeline.code_fix_and_test(est, pkg, plan["key"], code["commit"])
                except Exception as e:   # recorded in the digest via the missing state, and here
                    failures += 1
                    pipeline.log(f"{pkg.id}: {step} failed: {type(e).__name__}: {e}")
        for repo in est.repos:
            if repo.name in heads:
                try:
                    run_actions(est, repo, not args.no_propose, heads[repo.name])
                except Exception as e:
                    failures += 1
                    pipeline.log(f"{repo.name}: actions failed: {type(e).__name__}: {e}")
            if repo.images and repo.name in heads:
                try:
                    run_images(est, repo, not args.no_propose, heads[repo.name])
                except Exception as e:
                    failures += 1
                    pipeline.log(f"{repo.name}: images failed: {type(e).__name__}: {e}")
        if est.publish == "draft-pr" and not args.no_propose:
            try:
                for s in publish.run(est, heads, apply=True):
                    if s.get("result"):
                        pipeline.log(f"publish {s['branch']}: {s['result']['status']} "
                                     f"{s['result'].get('url') or s['result'].get('why', '')}")
            except Exception as e:
                failures += 1
                pipeline.log(f"publish failed: {type(e).__name__}: {e}")
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

    rp = es.add_parser("repair", help="hand failing tests to the [repair] agent, then test and triage its fix")
    rp.add_argument("package")
    rp.add_argument("--test", action="append", help="only failing tests whose name contains this (repeatable)")
    rp.add_argument("--commit")
    rp.add_argument("--no-confirm", action="store_true")
    rp.set_defaults(func=cmd_repair)

    cs = es.add_parser("code-scan", help="scan packages' own code (Opengrep with [sast] rules, bandit, gosec)")
    cs.add_argument("package", nargs="*")
    cs.add_argument("--commit")
    cs.set_defaults(func=cmd_code_scan)

    cf = es.add_parser("code-fix", help="hand code-scan findings to the [repair] agent, then test and triage")
    cf.add_argument("package")
    cf.add_argument("key", nargs="?", help="only this finding group (see code-scan)")
    cf.add_argument("--commit")
    cf.add_argument("--no-confirm", action="store_true")
    cf.set_defaults(func=cmd_code_fix)

    ac = es.add_parser("actions", help="scan CI workflows; --propose pins GitHub Actions to commits")
    ac.add_argument("repo", nargs="*")
    ac.add_argument("--commit")
    ac.add_argument("--propose", action="store_true")
    ac.set_defaults(func=cmd_actions)

    pb = es.add_parser("publish", help="open or update draft PRs for READY/REVIEW changes (dry run by default)")
    pb.add_argument("--apply", action="store_true", help="push branches and open draft PRs")
    pb.add_argument("--max-prs", type=int, default=5, help="new PRs a run may open (default 5)")
    pb.set_defaults(func=cmd_publish)

    h = es.add_parser("health", help="run each package's checks on the current code (no change)")
    h.add_argument("package", nargs="*")
    h.add_argument("--commit")
    h.add_argument("--no-recheck", action="store_true", help="don't re-run new failures")
    h.set_defaults(func=cmd_health)

    im = es.add_parser("images", help="scan Dockerfile base images; --propose moves runtimes past end of life")
    im.add_argument("repo", nargs="*")
    im.add_argument("--commit")
    im.add_argument("--propose", action="store_true", help="build, test and triage each runtime move")
    im.set_defaults(func=cmd_images)

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
