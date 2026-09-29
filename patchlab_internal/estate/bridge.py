"""Turn an estate package into what the engine and the tool containers need."""

from __future__ import annotations

import secrets
import time
from contextlib import contextmanager
from pathlib import Path

from ..config import Config, Deploy, Health, Mirror, Sandbox
from ..linux import CA_PATH, mirror_dest, sandbox_env
from ..sandbox import DockerSandbox, ExecResult
from .manifest import Estate, Package

SRC_ROOT = "/src"


# PatchLab's own check helpers (browser_smoke.mjs), copied into every sandbox.
ASSETS = Path(__file__).resolve().parent.parent / "assets"
TOOLS_DIR = "/opt/patchlab/tools"


def repo_root(pkg: Package) -> str:
    return f"{SRC_ROOT}/{pkg.repo.name}"


def package_dir(pkg: Package) -> str:
    return repo_root(pkg) if pkg.path == "." else f"{repo_root(pkg)}/{pkg.path}"


def mirrors_for(estate: Estate, pkg: Package) -> list[Mirror]:
    out = []
    for name in pkg.mirrors:
        spec = estate.mirrors[name]
        out.append(Mirror(path=estate.mirrors_dir / f"{name}.git", urls=spec.rewrite_urls()))
    return out


def sandbox_for(estate: Estate, pkg: Package) -> Sandbox:
    return Sandbox(
        images=[pkg.image], setup=list(pkg.setup), env=dict(pkg.env), install=list(pkg.install),
        workdir=package_dir(pkg), sidecars=list(pkg.sidecars), mirrors=mirrors_for(estate, pkg),
        ca_bundle=estate.ca_bundle, check_network=pkg.check_network,
        memory=pkg.memory, cpus=pkg.cpus, pids=4096)


def config_for(estate: Estate, pkg: Package, checkout: Path, commit: str) -> Config:
    """An engine config that deploys the whole repository and runs the package's checks.

    The whole repository, not just the package: test suites read files
    elsewhere in the repo (subsovereign's backend reads docs/ and the SDKs)."""
    return Config(
        name=pkg.id, path=estate.path, sandbox=sandbox_for(estate, pkg),
        deploy=[Deploy(src=checkout, dest=repo_root(pkg)), Deploy(src=ASSETS, dest=TOOLS_DIR)],
        services=[], checks=list(pkg.checks),
        health=Health(enabled=False),
        metadata={"repository": pkg.repo.url, "branch": pkg.repo.branch, "commit": commit,
                  "package": pkg.id, "image": pkg.image or ""})


def new_id(kind: str) -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{kind}-{secrets.token_hex(2)}"


class ToolBox:
    """A throw-away container with a checkout in it, for running ecosystem tools
    (npm audit, npm install --package-lock-only) that must not run on the host.

    It has the outside network (registries) but no credentials: private git
    dependencies come from the mirrors, exactly as in a test run."""

    def __init__(self, estate: Estate, pkg: Package, run_id: str, image: str | None = None,
                 extra_env: dict[str, str | None] | None = None, setup: list[str] | None = None):
        self.estate, self.pkg, self.run_id = estate, pkg, run_id
        sb = sandbox_for(estate, pkg)
        self.sb = sb
        self.setup = pkg.setup if setup is None else setup
        self.box = DockerSandbox(image or pkg.image, run_id, f"patchlab-internal-{run_id}-tool",
                                 memory=sb.memory, cpus=sb.cpus, pids=sb.pids, network="bridge",
                                 env={**sandbox_env(sb), **(extra_env or {})})

    def start(self, checkout: Path | None) -> None:
        self.box.start()
        if self.sb.ca_bundle:
            self.box.exec(f"mkdir -p {CA_PATH.rsplit('/', 1)[0]}", timeout=30)
            self.box.copy_in(self.sb.ca_bundle, CA_PATH)
        for i, m in enumerate(self.sb.mirrors):
            self.box.copy_in(m.path, mirror_dest(i, m))
        if checkout is not None:
            self.box.copy_in(checkout, repo_root(self.pkg))
        for cmd in self.setup:
            res = self.box.exec(cmd, timeout=1800)
            if not res.ok:
                raise RuntimeError(f"setup failed in tool container: {cmd}: {res.output[-500:]}")

    def run(self, command: str, timeout: int = 900, workdir: str | None = None) -> ExecResult:
        return self.box.exec(command, timeout=timeout, workdir=workdir or package_dir(self.pkg))

    def copy_out(self, src: str, dest: Path) -> bool:
        return self.box.copy_out(src, dest)

    def destroy(self) -> None:
        self.box.destroy()


@contextmanager
def toolbox(estate: Estate, pkg: Package, run_id: str, checkout: Path | None, **kw):
    tb = ToolBox(estate, pkg, run_id, **kw)
    try:
        tb.start(checkout)
        yield tb
    finally:
        tb.destroy()
