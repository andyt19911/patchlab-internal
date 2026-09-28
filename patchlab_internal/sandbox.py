"""Disposable Docker sandboxes.

Every container PatchLab Internal creates carries the label ``patchlab_internal=1`` plus a
per-run label, so a crashed or interrupted run can always be cleaned up
with ``patchlab-internal gc`` (or ``remove_run``) even if this process was killed.
"""

from __future__ import annotations

import hashlib
import io
import shlex
import subprocess
import tarfile
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

LABEL = "patchlab_internal"
RUN_LABEL = "patchlab_internal.run"
CACHE_REPO = "patchlab-internal-cache"


class SandboxError(Exception):
    pass


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout + ("\n" + self.stderr if self.stderr else "")


def _docker(*args: str, input: bytes | None = None, timeout: float | None = 120,
            check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(["docker", *args], input=input, capture_output=True,
                              timeout=timeout)
    except FileNotFoundError:
        raise SandboxError("docker CLI not found on PATH") from None
    except subprocess.TimeoutExpired:
        raise SandboxError(f"docker {args[0]} timed out") from None
    if check and proc.returncode != 0:
        raise SandboxError(f"docker {' '.join(args[:2])} failed: "
                           f"{proc.stderr.decode(errors='replace').strip()}")
    return proc


def docker_available() -> str | None:
    """Return None if the Docker daemon is reachable, else a reason."""
    try:
        _docker("info", "--format", "{{.ServerVersion}}", timeout=20)
    except SandboxError as e:
        return str(e)
    return None


def cache_tag(image: str, setup: list[str], env: dict[str, str]) -> str:
    key = hashlib.sha256(repr((image, setup, sorted(env.items()))).encode()).hexdigest()[:16]
    return f"{CACHE_REPO}:{key}"


def image_exists(tag: str) -> bool:
    return _docker("image", "inspect", tag, check=False, timeout=30).returncode == 0


class DockerSandbox:
    """One throw-away container. Use as a context manager so it is always removed."""

    caps: dict = {}   # containers cannot reboot or checkpoint

    def __init__(self, image: str, run_id: str, name: str, *, memory: str, cpus: str,
                 pids: int, network: str, env: dict[str, str]):
        self.image = image
        self.run_id = run_id
        self.name = name
        self.memory = memory
        self.cpus = cpus
        self.pids = pids
        self.network = network
        self.env = env
        self.started = False

    def start(self) -> None:
        args = [
            "run", "-d", "--name", self.name,
            "--label", f"{LABEL}=1", "--label", f"{RUN_LABEL}={self.run_id}",
            "--memory", self.memory, "--cpus", self.cpus, "--pids-limit", str(self.pids),
            "--network", self.network,
            "--security-opt", "no-new-privileges",
            "--entrypoint", "",
        ]
        for k, v in self.env.items():
            args += ["-e", f"{k}={v}"]
        args += [self.image, "sleep", "infinity"]
        # Allow time for the image pull on first use.
        _docker(*args, timeout=900)
        self.started = True

    def exec(self, command: str, timeout: int = 300, workdir: str | None = None) -> ExecResult:
        # Enforce the timeout inside the container too, otherwise a hung
        # command would outlive the host-side docker exec process.
        inner = f"timeout -s KILL {int(timeout)} sh -c {shlex.quote(command)}"
        args = ["exec"]
        if workdir:
            args += ["-w", workdir]
        args += [self.name, "sh", "-c", inner]
        start = time.monotonic()
        try:
            proc = subprocess.run(["docker", *args], capture_output=True, timeout=timeout + 30)
        except subprocess.TimeoutExpired as e:
            return ExecResult(124, _dec(e.stdout), _dec(e.stderr), time.monotonic() - start, True)
        duration = time.monotonic() - start
        # 137 = killed by SIGKILL from `timeout`.
        timed_out = proc.returncode == 137 and duration >= timeout
        return ExecResult(proc.returncode, _dec(proc.stdout), _dec(proc.stderr), duration, timed_out)

    def copy_in(self, src: Path, dest: str, exclude: list[str] | None = None) -> None:
        """Copy a host directory or file to ``dest`` in the sandbox, skipping ``exclude`` globs."""
        exclude = exclude or []
        dest = dest.rstrip("/") or "/"
        parent, _, leaf = dest.rpartition("/")
        parent = parent or "/"

        def keep(info: tarfile.TarInfo):
            rel = info.name.split("/", 1)[1] if "/" in info.name else ""
            parts = rel.split("/") if rel else []
            if any(fnmatch(p, pat) for p in parts for pat in exclude) or any(
                    fnmatch(rel, pat) for pat in exclude):
                return None
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            return info

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(str(src), arcname=leaf, filter=keep)
        self.exec(f"mkdir -p {shlex.quote(parent)}", timeout=30)
        _docker("cp", "-", f"{self.name}:{parent}", input=buf.getvalue(), timeout=300)

    def copy_out(self, src: str, dest: Path) -> bool:
        dest.parent.mkdir(parents=True, exist_ok=True)
        return _docker("cp", f"{self.name}:{src}", str(dest), check=False,
                       timeout=120).returncode == 0

    def commit(self, tag: str) -> None:
        _docker("commit", "--change", f"LABEL {LABEL}.cache=1", self.name, tag, timeout=600)

    def destroy(self) -> None:
        if self.started:
            _docker("rm", "-f", "-v", self.name, check=False, timeout=120)
            self.started = False

    def __enter__(self) -> "DockerSandbox":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()


def _dec(b: bytes | None) -> str:
    return b.decode(errors="replace") if b else ""


def _remove_by_label(label: str) -> list[str]:
    proc = _docker("ps", "-aq", "--filter", f"label={label}", check=False, timeout=60)
    ids = proc.stdout.decode().split()
    if ids:
        _docker("rm", "-f", "-v", *ids, check=False, timeout=300)
    return ids


def run_containers(run_id: str) -> list[str]:
    proc = _docker("ps", "-a", "--format", "{{.Names}}", "--filter",
                   f"label={RUN_LABEL}={run_id}", check=False, timeout=60)
    return proc.stdout.decode().split()


def remove_containers(names: list[str]) -> None:
    if names:
        _docker("rm", "-f", "-v", *names, check=False, timeout=300)


def remove_run(run_id: str) -> list[str]:
    """Force-remove every container belonging to one run."""
    return _remove_by_label(f"{RUN_LABEL}={run_id}")


def gc(include_cache: bool = False) -> tuple[list[str], list[str]]:
    """Remove all PatchLab Internal containers (and optionally cached setup images)."""
    containers = _remove_by_label(f"{LABEL}=1")
    images: list[str] = []
    if include_cache:
        proc = _docker("images", "-q", "--filter", f"label={LABEL}.cache=1", check=False)
        images = sorted(set(proc.stdout.decode().split()))
        if images:
            _docker("rmi", "-f", *images, check=False, timeout=300)
    return containers, images
