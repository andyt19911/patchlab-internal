"""Command-line interface.

Exit codes: 0 = PASS (or WARN without --fail-on-warn), 1 = FAIL, 2 = ERROR
(the test itself could not complete), 64 = usage/config error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, config, report, runner, settings


def _cmd_run(args) -> int:
    cfg = config.load(args.config)
    if args.no_patch:
        if args.patch or args.verify_rollback:
            raise config.ConfigError("--no-patch cannot be combined with --patch or --verify-rollback")
        patch = None
    elif args.patch:
        default_target = cfg.deploy[0].dest if cfg.deploy else None
        patch = config.parse_patch_spec(args.patch, default_target, cfg.sandbox.platform)
        if cfg.patch and cfg.patch.kind == patch.kind:
            # Keep the config's tuning (rollback, categories, ...) for the same kind.
            for attr in ("rollback", "categories", "include_preview", "microsoft_update",
                         "max_passes", "run_as", "exe_args", "timeout"):
                setattr(patch, attr, getattr(cfg.patch, attr))
    elif cfg.patch:
        patch = cfg.patch
    else:
        raise config.ConfigError("no patch given: add a [patch] table or pass --patch")
    if args.rollback and patch:
        patch.rollback = args.rollback

    reason = runner.make_platform(cfg).available()
    if reason:
        print(f"error: {cfg.sandbox.provider} sandboxes are not available: {reason}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else settings.load().reports_path()
    opts = runner.Options(
        out_dir=out, images=args.image or None, use_cache=not args.no_cache,
        keep_on_failure=args.keep_on_failure, verify_rollback=args.verify_rollback,
        jobs=args.jobs, quiet=args.quiet, run_id=args.run_id, no_patch=args.no_patch)
    rep = runner.run(cfg, patch, opts)
    paths = report.write_all(rep)

    print(f"\n{report.ICON[rep.verdict]} {rep.verdict}: {report.patch_label(rep)}")
    for t in rep.targets:
        worst = [f for f in report._sorted_findings(t) if f.severity != "info"][:3]
        ok = "no regressions" if patch else "all checks pass"
        print(f"  {t.image:<28} {t.verdict:<5}  " + ("; ".join(f.message for f in worst) if worst else ok))
    print(f"\nreports: {paths['html']}\n         {paths['markdown']}\n         {paths['json']}")
    print(f"cleanup: {rep.cleanup}")

    if rep.verdict == "ERROR":
        return 2
    if rep.verdict == "FAIL" or (rep.verdict == "WARN" and args.fail_on_warn):
        return 1
    return 0


def _cmd_validate(args) -> int:
    cfg = config.load(args.config)
    print(f"{cfg.name}: OK")
    print(f"  target : {cfg.sandbox.platform} on {cfg.sandbox.provider}")
    print(f"  images : {', '.join(cfg.sandbox.images)}")
    print(f"  deploy : {', '.join(f'{d.src} -> {d.dest}' for d in cfg.deploy) or 'none'}")
    if cfg.sandbox.install:
        print(f"  install: {' && '.join(cfg.sandbox.install)} (after deploy, patch and rollback)")
    if cfg.sandbox.sidecars:
        print(f"  sidecars: {', '.join(f'{s.name}={s.image}' for s in cfg.sandbox.sidecars)}")
    print(f"  checks : {', '.join(c.name for c in cfg.checks)}")
    print(f"  patch  : {cfg.patch.label if cfg.patch else 'none (pass --patch)'}")
    return 0


def _ask(prompt: str, default: str) -> str:
    answer = input(f"{prompt} [{default}]: ").strip()
    return answer or default


def _ask_yes(prompt: str, default: bool) -> bool:
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer in ("y", "yes")


def _cmd_setup(args) -> int:
    s = settings.load()
    flags_given = any(v is not None for v in (args.web, args.reports_dir, args.configs_dir, args.host, args.port))
    interactive = not args.non_interactive and not flags_given and sys.stdin.isatty()
    if interactive:
        print("PatchLab Internal setup (press Enter to keep the value in brackets)\n")
        s.reports_dir = _ask("Folder for run reports", s.reports_dir or str(Path.cwd() / "reports"))
        s.configs_dir = _ask("Folder containing your PatchLab Internal configs", s.configs_dir or str(Path.cwd()))
        s.web.enabled = _ask_yes("Enable the optional web front end?", s.web.enabled)
        if s.web.enabled:
            s.web.host = _ask("Front end listen address", s.web.host)
            s.web.port = int(_ask("Front end port", str(s.web.port)))
    else:
        if args.reports_dir is not None:
            s.reports_dir = str(Path(args.reports_dir).expanduser().resolve())
        if args.configs_dir is not None:
            s.configs_dir = str(Path(args.configs_dir).expanduser().resolve())
        if args.web is not None:
            s.web.enabled = args.web
        if args.host is not None:
            s.web.host = args.host
        if args.port is not None:
            s.web.port = args.port
    path = settings.save(s)
    print(f"saved {path}")
    _print_settings(s)
    if s.web.enabled and not settings.web_installed():
        print("\nnote: the front end is enabled but not installed; install it with: pip install ./web")
    return 0


def _print_settings(s) -> None:
    print(f"  reports : {s.reports_path()}")
    print(f"  configs : {s.configs_path()}")
    state = "enabled" if s.web.enabled else "disabled"
    installed = "installed" if settings.web_installed() else "not installed"
    print(f"  web     : {state}, {installed}, http://{s.web.host}:{s.web.port}")
    if s.web.enabled:
        print("            start it with: patchlab-internal web")


def _cmd_web(args) -> int:
    s = settings.load()
    action = args.action or "serve"
    if action == "status":
        print(f"settings: {settings.settings_path()}{'' if s.exists else ' (not created yet: run patchlab-internal setup)'}")
        _print_settings(s)
        return 0
    if action in ("enable", "disable"):
        s.web.enabled = action == "enable"
        if args.host:
            s.web.host = args.host
        if args.port:
            s.web.port = args.port
        print(f"web front end {action}d ({settings.save(s)})")
        if s.web.enabled and not settings.web_installed():
            print("note: it is not installed yet: pip install ./web")
        return 0
    # serve
    if not s.web.enabled:
        print("error: the web front end is disabled. Enable it with `patchlab-internal web enable` "
              "(or `patchlab-internal setup --web`).", file=sys.stderr)
        return 64
    web = settings.import_web()
    if web is None:
        print("error: the web front end is not installed: pip install ./web", file=sys.stderr)
        return 64
    return web.serve(s, host=args.host, port=args.port, open_browser=args.open,
                     allow_remote=args.allow_remote, estate=args.estate)


def _cmd_gc(args) -> int:
    if args.config:
        platform = runner.make_platform(config.load(args.config))
    else:
        from .linux import LinuxPlatform
        platform = LinuxPlatform(None)
    reason = platform.available()
    if reason:
        print(f"error: {reason}", file=sys.stderr)
        return 2
    print(platform.gc(run_id=args.run_id, include_cache=args.cache))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patchlab-internal", description="Test a patch in disposable sandboxes, report, and clean up.",
        epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("--version", action="version", version=f"patchlab_internal {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="test a patch: baseline, apply, verify, report, clean up")
    r.add_argument("config", help="path to a patchlab_internal TOML config")
    r.add_argument("--patch", metavar="SPEC", help="kind[:args]. Linux: source:fix.patch, "
                   "os-packages[:pkg,...], package-file:x.deb, script:hotfix.sh. Windows: "
                   "windows-update[:KB...], package-file:x.msu, script:fix.ps1")
    r.add_argument("--no-patch", action="store_true",
                   help="baseline only: run the checks once on the code as it is and report")
    r.add_argument("--image", action="append", metavar="IMAGE",
                   help="override target images (repeatable)")
    r.add_argument("--out", help="report directory (default: the setup reports folder, else ./reports)")
    r.add_argument("--run-id", help=argparse.SUPPRESS)   # used by the web front end
    r.add_argument("--jobs", type=int, help="targets tested in parallel (default: all)")
    r.add_argument("--no-cache", action="store_true", help="ignore cached setup images")
    r.add_argument("--verify-rollback", action="store_true",
                   help="also back the patch out and check the system recovers")
    r.add_argument("--rollback", metavar="CMD",
                   help="command that backs the patch out (source patches reverse automatically)")
    r.add_argument("--keep-on-failure", action="store_true",
                   help="keep failing sandboxes for debugging (remove later with gc)")
    r.add_argument("--fail-on-warn", action="store_true", help="exit 1 on WARN as well as FAIL")
    r.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    r.set_defaults(func=_cmd_run)

    v = sub.add_parser("validate", help="check a config file without running anything")
    v.add_argument("config")
    v.set_defaults(func=_cmd_validate)

    st = sub.add_parser("setup", help="choose report/config folders and optional features "
                        "(interactive without flags)")
    st.add_argument("--web", action=argparse.BooleanOptionalAction, default=None,
                    help="enable (--web) or disable (--no-web) the optional web front end")
    st.add_argument("--reports-dir", help="where run reports are written")
    st.add_argument("--configs-dir", help="where the front end looks for configs")
    st.add_argument("--host", help="front end listen address (default 127.0.0.1)")
    st.add_argument("--port", type=int, help="front end port (default 8750)")
    st.add_argument("--non-interactive", action="store_true", help="never prompt")
    st.set_defaults(func=_cmd_setup)

    w = sub.add_parser("web", help="optional browser front end: serve (default), enable, disable, status")
    w.add_argument("action", nargs="?", choices=["serve", "enable", "disable", "status"])
    w.add_argument("--host", help="listen address for this run (default from settings)")
    w.add_argument("--port", type=int, help="port for this run (default from settings)")
    w.add_argument("--open", action="store_true", help="open the browser")
    w.add_argument("--allow-remote", action="store_true",
                   help="allow listening on a non-loopback address (access still needs the token)")
    w.add_argument("--estate", metavar="PATH", help="estate.toml whose results the Estate page shows "
                   "(default: $PATCHLAB_INTERNAL_ESTATE_MANIFEST, then estate.toml in the configs folder)")
    w.set_defaults(func=_cmd_web)

    g = sub.add_parser("gc", help="remove leftover sandboxes from crashed/killed runs")
    g.add_argument("--config", help="clean up the provider this config uses (Hyper-V, vSphere); "
                   "default: Docker")
    g.add_argument("--cache", action="store_true", help="also remove cached Docker setup images")
    g.add_argument("--run-id", help="only remove sandboxes of this run (without it, gc removes every "
                   "PatchLab Internal sandbox of the provider, so don't run it while tests are in progress)")
    g.set_defaults(func=_cmd_gc)

    from .estate import cli as estate_cli
    estate_cli.register(sub)
    return p


def _utf8_output() -> None:
    """Redirected output on Windows defaults to cp1252, which cannot print the
    report icons; fall back to UTF-8 (or replacement characters)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if (stream.encoding or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "estate":
            from .estate import cli as estate_cli
            return estate_cli.run(args)
        return args.func(args)
    except config.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 64
