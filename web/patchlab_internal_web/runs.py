"""Launch and supervise `patchlab-internal run` processes started from the browser.

Runs execute as separate `python -m patchlab_internal run ...` processes, exactly as
if typed at a terminal, so the front end never changes how a test behaves
and a crash in the UI cannot interrupt a clean-up.
"""

from __future__ import annotations

import datetime as dt
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import patchlab_internal
from patchlab_internal.runner import new_run_id

# Where the core package lives, so `python -m patchlab_internal` works in child
# processes even from a source checkout that was never pip-installed.
CORE_ROOT = str(Path(patchlab_internal.__file__).resolve().parent.parent)


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8", **(extra or {})}
    env["PYTHONPATH"] = os.pathsep.join(p for p in (CORE_ROOT, env.get("PYTHONPATH", "")) if p)
    return env


class Busy(Exception):
    pass


@dataclass
class Job:
    run_id: str
    config: str
    patch: str | None
    images: list[str]
    started: str
    proc: subprocess.Popen | None = None
    status: str = "running"          # running | cancelling | finished | cancelled
    exit_code: int | None = None
    cancel_requested: bool = False
    argv: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "config": self.config, "patch": self.patch, "images": self.images,
                "started": self.started, "status": self.status, "exit_code": self.exit_code}


class RunManager:
    def __init__(self, reports: Path, workdir: Path, max_parallel: int = 2, command: list[str] | None = None):
        self.reports = reports
        self.workdir = workdir
        self.max_parallel = max_parallel
        self.command = command or [sys.executable, "-m", "patchlab_internal"]
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def active(self) -> list[Job]:
        with self.lock:
            return [j for j in self.jobs.values() if j.status in ("running", "cancelling")]

    def get(self, run_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(run_id)

    def start(self, config_path: Path, patch: str | None = None, images: list[str] | None = None,
              verify_rollback: bool = False, keep_on_failure: bool = False, fail_on_warn: bool = False,
              extra_env: dict[str, str] | None = None) -> Job:
        if len(self.active()) >= self.max_parallel:
            raise Busy(f"{self.max_parallel} run(s) already in progress")
        run_id = new_run_id()
        run_dir = self.reports / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        argv = [*self.command, "run", str(config_path), "--out", str(self.reports), "--run-id", run_id]
        if patch:
            argv += ["--patch", patch]
        for img in images or []:
            argv += ["--image", img]
        if verify_rollback:
            argv.append("--verify-rollback")
        if keep_on_failure:
            argv.append("--keep-on-failure")
        if fail_on_warn:
            argv.append("--fail-on-warn")
        env = child_env(extra_env)
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True   # our Ctrl-C must not kill runs mid clean-up
        job = Job(run_id, str(config_path), patch, list(images or []),
                  dt.datetime.now().astimezone().isoformat(timespec="seconds"), argv=argv)
        console = open(run_dir / "console.log", "wb")
        console.write(f"$ patchlab_internal {' '.join(argv[len(self.command):])}\n".encode())
        console.flush()
        try:
            job.proc = subprocess.Popen(argv, stdout=console, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                        cwd=self.workdir, env=env, **kwargs)
        except OSError:
            console.close()
            raise
        with self.lock:
            self.jobs[run_id] = job
        threading.Thread(target=self._wait, args=(job, console), daemon=True).start()
        return job

    def _wait(self, job: Job, console) -> None:
        code = job.proc.wait()
        console.close()
        with self.lock:
            job.exit_code = code
            job.status = "cancelled" if job.cancel_requested else "finished"

    def cancel(self, run_id: str) -> bool:
        """Ask a run to stop. It tears its sandboxes down before exiting.

        Only one interrupt is ever sent: a second one could land in the middle
        of the clean-up."""
        job = self.get(run_id)
        if not job or not job.proc:
            return False
        # A repeated click can land after the run has already stopped; it
        # asked for what happened, so it succeeds without another signal.
        if job.status in ("cancelling", "cancelled"):
            return True
        if job.status != "running":
            return False
        job.cancel_requested = True
        job.status = "cancelling"
        try:
            if sys.platform == "win32":
                job.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                job.proc.send_signal(signal.SIGINT)
        except OSError:
            return False
        return True

    def shutdown(self, wait_seconds: float = 900) -> None:
        """Cancel active runs and give them time to clean up."""
        running = self.active()
        for job in running:
            self.cancel(job.run_id)     # no-op for runs already cancelling
        deadline = time.monotonic() + wait_seconds
        for job in running:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                job.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass
