"""Cloud sandboxes: clone a real asset into an isolated network, test, destroy.

A cloud provider only has to do four things (see CloudProvider):
  clone    copy an existing instance's disks into a new, isolated instance
  run      run a script on it as root/SYSTEM and return the full stdout
  destroy  delete everything it created
  list     find leftovers by tag
CloudSandbox builds the rest on top of `run`: reliable exit codes and
stdout/stderr, guest-side timeouts, file transfer and large outputs (split
into chunks when the cloud's run-command channel truncates), and reboots.

Everything talks to the clouds through their official CLIs (aws, az,
gcloud, oci), so authentication is whatever those CLIs are configured
with: SSO profiles, service principals, workload identity, instance
principals and so on.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from ..sandbox import ExecResult, SandboxError

PS_DIR = Path(__file__).resolve().parent.parent / "ps"
LINUX_GUEST_DIR = "/var/tmp/patchlab"
WINDOWS_GUEST_DIR = r"C:\ProgramData\PatchLab Internal"
TAG_KEY, RUN_TAG_KEY, SOURCE_TAG_KEY = "patchlab_internal", "patchlab-internal-run", "patchlab-internal-source"
# Every resource of a clone carries its exact name, so teardown can match it
# exactly instead of by prefix (a prefix would also hit "<name>-replica").
CLONE_TAG_KEY = "patchlab-internal-clone"
_CMD_SHIMS = (".cmd", ".bat")


class CloudError(SandboxError):
    pass


# ---------------------------------------------------------------- CLI runner

class CLI:
    """Runs a cloud CLI and parses its JSON output. Tests substitute a fake."""

    def __init__(self, log_path: Path | None = None, env: dict | None = None):
        self.log_path = log_path
        self.env = env
        self._lock = threading.Lock()

    def available(self, exe: str) -> bool:
        return shutil.which(exe) is not None

    def __call__(self, argv: list[str], *, input: str | None = None, timeout: float = 900,
                 json_out: bool = True, check: bool = True):
        start = time.monotonic()
        try:
            proc = subprocess.run(command_line(argv), input=input, capture_output=True, text=True, timeout=timeout,
                                  env={**os.environ, **(self.env or {})}, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            raise CloudError(f"'{argv[0]}' CLI not found on PATH") from None
        except subprocess.TimeoutExpired:
            self._log(argv, None, "", time.monotonic() - start)
            raise CloudError(f"{' '.join(argv[:3])} timed out after {timeout:.0f}s") from None
        self._log(argv, proc.returncode, proc.stderr, time.monotonic() - start)
        if check and proc.returncode != 0:
            err = (proc.stderr or proc.stdout).strip().splitlines()
            raise CloudError(f"{' '.join(argv[:3])} failed: {' '.join(err[-3:])[:600]}")
        if not json_out:
            return proc.stdout
        text = proc.stdout.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def _log(self, argv, code, stderr, secs) -> None:
        if not self.log_path:
            return
        shown = " ".join(shlex.quote(a if len(a) <= 160 else a[:120] + f"...<{len(a)} chars>") for a in argv)
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%H:%M:%S')} $ {shown}\n    -> exit {code} in {secs:.1f}s\n")
                if code and stderr:
                    f.write("    " + stderr.strip()[-800:].replace("\n", "\n    ") + "\n")


def cmd_quote(arg: str) -> str:
    """Quote one argument for a Windows .cmd/.bat shim.

    Inside double quotes cmd.exe treats & | < > ^ literally, and a doubled
    quote keeps cmd in quoted mode while the program's argument parser reads
    it as a literal quote. (%NAME% can still expand if NAME is a defined
    variable; PatchLab Internal never passes such text.)
    """
    return '"' + arg.replace('"', '""') + '"'


def command_line(argv: list[str]):
    """Resolve the executable. On Windows, `az` and `gcloud` are .cmd shims that
    CreateProcess cannot find by bare name and that cmd.exe would re-parse, so
    those get an explicitly quoted command line."""
    exe = shutil.which(argv[0])
    if not exe:
        raise FileNotFoundError(argv[0])
    if sys.platform == "win32" and exe.lower().endswith(_CMD_SHIMS):
        # /s makes cmd strip exactly the outer pair of quotes around the whole line.
        inner = " ".join([cmd_quote(exe), *(cmd_quote(a) for a in argv[1:])])
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        return f'"{comspec}" /d /s /c "{inner}"'
    return [exe, *argv[1:]]


def tags(clone: "Clone", source: str | None = None) -> dict[str, str]:
    return {TAG_KEY: "1", RUN_TAG_KEY: clone.run_id, SOURCE_TAG_KEY: (source or clone.asset)[:200],
            CLONE_TAG_KEY: clone.name}


def poll(what: str, fn, timeout: float, interval: float = 10, cancel=None):
    """Call fn() until it returns a truthy value; raise CloudError on timeout."""
    deadline = time.monotonic() + timeout
    last = None
    while True:
        if cancel is not None and cancel.is_set():
            raise CloudError(f"cancelled while waiting for {what}")
        try:
            value = fn()
            if value:
                return value
        except CloudError as e:
            last = e
        if time.monotonic() > deadline:
            raise CloudError(f"timed out after {timeout:.0f}s waiting for {what}" + (f" ({last})" if last else ""))
        time.sleep(interval)


# ---------------------------------------------------------------- provider contract

@dataclass
class Clone:
    """What a provider created. Filled in as resources are created, so a
    failure half-way through can still be cleaned up."""
    name: str
    asset: str
    run_id: str
    os: str = ""                 # "linux" | "windows"
    instance: str = ""           # provider's instance id/name
    location: str = ""           # region / zone / resource group
    resources: list[tuple[str, str]] = field(default_factory=list)   # (kind, id) created
    info: dict = field(default_factory=dict)

    def add(self, kind: str, rid: str) -> None:
        self.resources.append((kind, rid))


class CloudProvider:
    name = ""
    cli_exe = ""
    # Largest script `run` accepts inline, and largest stdout it returns intact.
    # Bigger scripts, files and outputs are moved in chunks.
    max_script_chars = 40000
    max_output_chars = 20000
    # Seconds between checks of an asynchronous run command.
    poll_interval = 3.0

    def __init__(self, options: dict, cli: CLI):
        self.o = options
        self.cli = cli

    def check(self) -> str | None:
        if not self.cli.available(self.cli_exe):
            return f"the '{self.cli_exe}' CLI is not installed"
        return None

    def clone(self, clone: Clone, expected_os: str, timeout: float, cancel=None) -> None:
        raise NotImplementedError

    def wait_agent(self, clone: Clone, timeout: float, cancel=None) -> None:
        """Wait until the instance runs and its command channel is online."""
        raise NotImplementedError

    def run(self, clone: Clone, script: str, timeout: int) -> str:
        """Run ``script`` (bash on Linux, PowerShell on Windows) as root/SYSTEM; return stdout."""
        raise NotImplementedError

    def upload(self, clone: Clone, data: bytes, key: str) -> str | None:
        """Optionally stage bytes in cloud storage; return a URL the guest can GET."""
        return None

    def destroy(self, clone: Clone) -> None:
        raise NotImplementedError

    def cleanup_name(self, clone: Clone) -> str:
        """The name list_clones() reports for this clone (and destroy_named() accepts)."""
        return clone.name

    def list_clones(self, run_id: str | None = None) -> list[str]:
        """Names of clones with resources left over (instances, disks, images...)."""
        raise NotImplementedError

    def destroy_named(self, name: str) -> None:
        """Delete every resource tagged with exactly this clone name."""
        raise NotImplementedError


# ---------------------------------------------------------------- guest wrappers

_RESULT = re.compile(r"@@PLRESULT\s*\n(.*?)\n@@PLEND", re.S)
_RESULT_FILE = re.compile(r"@@PLRESULTFILE (\S+) (\d+)")


def _b64(data: bytes | str) -> str:
    return base64.b64encode(data.encode("utf-8") if isinstance(data, str) else data).decode("ascii")


def linux_wrapper(script: str | None, timeout: int, inline_limit: int, path: str | None = None) -> str:
    """Bash wrapper: runs the script as root with a timeout and frames the result."""
    load = (f"printf '%s' '{_b64(script)}' | base64 -d > \"$f\"" if script is not None
            else f"cp '{path}' \"$f\"")
    return f"""#!/bin/bash
S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
d={LINUX_GUEST_DIR}; $S mkdir -p "$d"; $S chmod 1777 "$d"
id=$(date +%s%N)$$; f="$d/x-$id.sh"
{load}
$S timeout -k 10 {int(timeout)} bash "$f" >"$f.out" 2>"$f.err" </dev/null
rc=$?
r="$d/r-$id"
{{ printf 'rc=%s\\nto=%s\\nout=' "$rc" "$([ "$rc" = 124 ] && echo 1 || echo 0)"
   base64 -w0 < "$f.out"; printf '\\nerr='; base64 -w0 < "$f.err"; printf '\\n'; }} > "$r"
rm -f "$f" "$f.out" "$f.err"
n=$(wc -c < "$r")
if [ "$n" -le {int(inline_limit)} ]; then echo "@@PLRESULT"; cat "$r"; echo "@@PLEND"; rm -f "$r"
else echo "@@PLRESULTFILE $r $n"; fi
"""


def windows_wrapper(script: str | None, timeout: int, inline_limit: int, path: str | None = None) -> str:
    """PowerShell wrapper (5.1 compatible) around Invoke-PatchLabInternalGuestScript."""
    fn = (PS_DIR / "guest-exec.ps1").read_text(encoding="utf-8")
    fn = fn[fn.index("function Invoke-PatchLabInternalGuestScript"):]
    call = (f"-ScriptText ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{_b64(script)}')))"
            if script is not None else f"-ScriptPath '{path}'")
    return f"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{fn}
$r = Invoke-PatchLabInternalGuestScript {call} -TimeoutSeconds {int(timeout)}
function ConvertTo-PL64([string]$t) {{ [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)) }}
$text = "rc=$($r.exit_code)`nto=$([int][bool]$r.timed_out)`nout=$(ConvertTo-PL64 $r.stdout)`nerr=$(ConvertTo-PL64 $r.stderr)`n"
if ($text.Length -le {int(inline_limit)}) {{ '@@PLRESULT'; $text.TrimEnd(); '@@PLEND' }}
else {{
    $p = Join-Path (Join-Path $env:ProgramData 'PatchLab Internal') ('r-' + [guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($p, $text)
    "@@PLRESULTFILE $p $((Get-Item $p).Length)"
}}
"""


def parse_framed(text: str) -> dict[str, str]:
    fields = {}
    for line in text.strip().splitlines():
        k, sep, v = line.partition("=")
        if sep:
            fields[k.strip()] = v.strip()
    return fields


# ---------------------------------------------------------------- sandbox

class CloudSandbox:
    """Sandbox interface (like DockerSandbox / WindowsSandbox) over a cloud clone."""

    def __init__(self, provider: CloudProvider, asset: str, name: str, run_id: str, expected_os: str,
                 clone_timeout: float = 3600):
        self.provider = provider
        self.clone = Clone(name=name, asset=asset, run_id=run_id)
        self.name = name
        self.expected_os = expected_os
        self.clone_timeout = clone_timeout
        self.started = False
        self.caps = {"reboot": True, "checkpoint": False, "system_tasks": True}

    @property
    def os(self) -> str:
        return self.clone.os or self.expected_os

    @property
    def cleanup_name(self) -> str:
        return self.provider.cleanup_name(self.clone)

    @property
    def guest_dir(self) -> str:
        return WINDOWS_GUEST_DIR if self.os == "windows" else LINUX_GUEST_DIR

    def gpath(self, *parts: str) -> str:
        sep = "\\" if self.os == "windows" else "/"
        return sep.join([self.guest_dir, *parts])

    # -- lifecycle
    def start(self, cancel=None) -> None:
        # Mark started first: a clone that fails half-way must still be destroyed.
        self.started = True
        self.provider.clone(self.clone, self.expected_os, self.clone_timeout, cancel)

    def destroy(self) -> None:
        if self.started:
            self.provider.destroy(self.clone)
            self.started = False

    # -- command execution
    def _raw(self, script: str, timeout: int = 300) -> str:
        return self.provider.run(self.clone, script, timeout)

    def exec(self, script: str, timeout: int = 300, workdir: str | None = None) -> ExecResult:
        start = time.monotonic()
        wrap = windows_wrapper if self.os == "windows" else linux_wrapper
        limit = self.provider.max_output_chars - 200
        wrapped = wrap(script, timeout, limit)
        if len(wrapped) > self.provider.max_script_chars:
            # Too big for one command: stage the script as a file first.
            path = self.gpath(f"s-{uuid.uuid4().hex}.{'ps1' if self.os == 'windows' else 'sh'}")
            self._put_chunks(script.encode("utf-8"), path)
            wrapped = wrap(None, timeout, limit, path=path)
        raw = self._raw(wrapped, timeout + 300)
        m = _RESULT.search(raw)
        if m:
            fields = parse_framed(m.group(1))
        else:
            mf = _RESULT_FILE.search(raw)
            if not mf:
                raise CloudError(f"no result from the guest (output: {raw.strip()[-300:]!r})")
            fields = parse_framed(self._get_chunks(mf.group(1), int(mf.group(2)), delete=True).decode("utf-8"))
        try:
            return ExecResult(
                exit_code=int(fields.get("rc", "255")),
                stdout=base64.b64decode(fields.get("out", "")).decode("utf-8", "replace"),
                stderr=base64.b64decode(fields.get("err", "")).decode("utf-8", "replace"),
                duration=time.monotonic() - start,
                timed_out=fields.get("to") == "1")
        except (ValueError, TypeError) as e:
            raise CloudError(f"garbled result from the guest: {e}") from None

    # -- chunked file transfer over the command channel
    def _chunk_ok(self, raw: str, what: str) -> None:
        if "@@PLOK" not in raw:
            raise CloudError(f"{what} failed in the guest: {raw.strip()[-300:]!r}")

    def _put_chunks(self, data: bytes, path: str) -> None:
        room = self.provider.max_script_chars - 800
        size = max(1024, (room // 4) * 3)
        windows = self.os == "windows"
        for i in range(0, max(len(data), 1), size):
            chunk = _b64(data[i:i + size])
            if windows:
                mode = "Create" if i == 0 else "Append"
                script = (f"$b=[Convert]::FromBase64String('{chunk}'); "
                          f"New-Item -ItemType Directory -Force -Path (Split-Path -Parent '{path}') | Out-Null; "
                          f"$s=[IO.File]::Open('{path}','{mode}'); $s.Write($b,0,$b.Length); $s.Close(); '@@PLOK'")
            else:
                redir = ">" if i == 0 else ">>"
                script = (f"S=\"\"; [ \"$(id -u)\" = 0 ] || S=\"sudo -n\"; $S mkdir -p \"$(dirname '{path}')\" && "
                          f"printf '%s' '{chunk}' | base64 -d | $S sh -c 'cat {redir} \"$1\"' _ '{path}' && echo @@PLOK")
            self._chunk_ok(self._raw(script, 120), "file upload")

    def _get_chunks(self, path: str, size: int, delete: bool = False) -> bytes:
        room = self.provider.max_output_chars - 200
        step = max(1024, (room // 4) * 3)
        out = bytearray()
        windows = self.os == "windows"
        for off in range(0, size, step):
            if windows:
                script = (f"$f=[IO.File]::OpenRead('{path}'); [void]$f.Seek({off},'Begin'); "
                          f"$b=New-Object byte[] {step}; $n=$f.Read($b,0,{step}); $f.Close(); "
                          f"'@@PLDATA ' + [Convert]::ToBase64String($b,0,$n); '@@PLOK'")
            else:
                script = (f"S=\"\"; [ \"$(id -u)\" = 0 ] || S=\"sudo -n\"; "
                          f"echo \"@@PLDATA $($S tail -c +{off + 1} '{path}' | head -c {step} | base64 -w0)\" && echo @@PLOK")
            raw = self._raw(script, 120)
            self._chunk_ok(raw, "file download")
            m = re.search(r"@@PLDATA ([A-Za-z0-9+/=]*)", raw)
            out += base64.b64decode(m.group(1) if m else "")
        if delete:
            rm = (f"Remove-Item -Force '{path}'; '@@PLOK'" if windows
                  else f"S=\"\"; [ \"$(id -u)\" = 0 ] || S=\"sudo -n\"; $S rm -f '{path}'; echo @@PLOK")
            self._raw(rm, 60)
        return bytes(out)

    def _file_size(self, path: str) -> int | None:
        if self.os == "windows":
            raw = self._raw(f"if (Test-Path -LiteralPath '{path}') {{ '@@PLSIZE ' + (Get-Item -LiteralPath '{path}').Length }}; '@@PLOK'", 60)
        else:
            raw = self._raw(f"S=\"\"; [ \"$(id -u)\" = 0 ] || S=\"sudo -n\"; "
                            f"[ -f '{path}' ] && echo \"@@PLSIZE $($S wc -c < '{path}')\"; echo @@PLOK", 60)
        self._chunk_ok(raw, "stat")
        m = re.search(r"@@PLSIZE (\d+)", raw)
        return int(m.group(1)) if m else None

    # -- file copy (sandbox interface)
    def copy_in(self, src: Path, dest: str, exclude: list[str] | None = None) -> None:
        windows = self.os == "windows"
        if src.is_file():
            data, archive = src.read_bytes(), False
        else:
            data, archive = pack(src, exclude or [], "zip" if windows else "tar"), True
        key = f"{self.clone.run_id}/{self.name}/{uuid.uuid4().hex}{'.zip' if windows else '.tgz'}"
        staged = self.gpath(f"in-{uuid.uuid4().hex}{'.zip' if windows else '.tgz'}")
        url = self.provider.upload(self.clone, data, key)
        if url:
            fetch = (f"Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{staged}'" if windows
                     else f"curl -fsSL -o '{staged}' '{url}'")
        else:
            self._put_chunks(data, staged)
            fetch = ""
        if windows:
            place = (f"if (Test-Path -LiteralPath '{dest}') {{ Remove-Item -LiteralPath '{dest}' -Recurse -Force }}; "
                     + (f"Expand-Archive -LiteralPath '{staged}' -DestinationPath '{dest}' -Force; Remove-Item -Force '{staged}'"
                        if archive else
                        f"New-Item -ItemType Directory -Force -Path (Split-Path -Parent '{dest}') | Out-Null; "
                        f"Move-Item -LiteralPath '{staged}' -Destination '{dest}' -Force"))
            script = "$ErrorActionPreference='Stop'\n" + (fetch + "\n" if fetch else "") + place
        else:
            place = (f"rm -rf '{dest}' && mkdir -p '{dest}' && tar -xzf '{staged}' -C '{dest}' && rm -f '{staged}'"
                     if archive else f"mkdir -p \"$(dirname '{dest}')\" && mv -f '{staged}' '{dest}'")
            script = "set -e\n" + (fetch + "\n" if fetch else "") + place
        res = self.exec(script, timeout=1800)
        if not res.ok:
            raise CloudError(f"copying {src.name} into the clone failed: {res.output.strip()[-300:]}")

    def copy_out(self, src: str, dest: Path) -> bool:
        size = self._file_size(src)
        if size is None:
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self._get_chunks(src, size))
        return True

    # -- boots and reboots
    def boot_time(self) -> str:
        cmd = ("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
               if self.os == "windows" else "cat /proc/sys/kernel/random/boot_id")
        res = self.exec(cmd, timeout=60)
        if not res.ok or not res.stdout.strip():
            raise CloudError(f"guest not ready: {res.output.strip()[:200]}")
        return res.stdout.strip()

    def wait_ready(self, timeout: int, previous_boot: str | None = None, cancel=None) -> float:
        start = time.monotonic()
        self.provider.wait_agent(self.clone, timeout, cancel)

        def ready():
            bt = self.boot_time()
            return previous_boot is None or bt != previous_boot

        poll("the guest to answer commands", ready, max(60, timeout - (time.monotonic() - start)),
             interval=10, cancel=cancel)
        return time.monotonic() - start

    def reboot(self, timeout: int, cancel=None) -> float:
        before = self.boot_time()
        if self.os == "windows":
            self.exec("shutdown.exe /r /t 10 /f /d p:2:17", timeout=60)
        else:
            self.exec("nohup sh -c 'sleep 10; systemctl reboot || reboot' >/dev/null 2>&1 &", timeout=60)
        time.sleep(20)
        return self.wait_ready(timeout, previous_boot=before, cancel=cancel)

    def checkpoint(self, name: str) -> None:
        raise CloudError("checkpoints are not supported for cloud clones; use rollback = \"uninstall\" or a script")

    restore = checkpoint


def pack(src: Path, exclude: list[str], fmt: str) -> bytes:
    """Archive a directory's contents (tar.gz for Linux guests, zip for Windows)."""
    def skipped(rel: str) -> bool:
        return any(fnmatch(part, pat) for part in rel.split("/") for pat in exclude)

    buf = io.BytesIO()
    files = sorted(p for p in src.rglob("*") if not skipped(p.relative_to(src).as_posix()))
    if fmt == "zip":
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in files:
                if p.is_file():
                    z.write(p, p.relative_to(src).as_posix())
    else:
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for p in files:
                info = t.gettarinfo(str(p), p.relative_to(src).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                if p.is_file():
                    with open(p, "rb") as fh:
                        t.addfile(info, fh)
                elif p.is_dir():
                    t.addfile(info)
    return buf.getvalue()
