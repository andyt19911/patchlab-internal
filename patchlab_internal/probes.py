"""OS health probes: capture a snapshot of system state inside a sandbox.

The probe is one POSIX shell script so it works on Debian/Ubuntu, RHEL-family
and Alpine images without installing anything. Output is split into
``@@section`` blocks and parsed on the host.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from fnmatch import fnmatch

from .sandbox import DockerSandbox

PROBE_SCRIPT = r"""
echo "@@os"
( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" ) || uname -s
echo "@@kernel"
uname -r
echo "@@pkgmgr"
if command -v dpkg-query >/dev/null 2>&1; then echo dpkg
elif command -v rpm >/dev/null 2>&1; then echo rpm
elif command -v apk >/dev/null 2>&1; then echo apk
else echo none; fi
echo "@@packages"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 2>/dev/null \
    | awk -F'\t' '$1 ~ /^ii/ {print $2 "\t" $3}'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | sed -E 's/^(.+)-([0-9][^-]*-r[0-9]+)$/\1\t\2/'
fi
echo "@@pkgdb"
if command -v dpkg >/dev/null 2>&1; then
  dpkg --audit 2>&1
  if command -v apt-get >/dev/null 2>&1; then
    out=$(apt-get check -q 2>&1) || printf 'apt-get check failed:\n%s\n' "$out" | tail -n 6
  fi
elif command -v dnf >/dev/null 2>&1; then
  dnf -q check 2>&1
elif command -v rpm >/dev/null 2>&1; then
  rpm -Va --nofiles --nodigest --nosignature 2>&1
fi
echo "@@brokenlibs"
if command -v ldd >/dev/null 2>&1; then
  for d in $LIB_SCAN_PATHS; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] && [ -x "$f" ] || continue
      ldd "$f" 2>/dev/null | grep 'not found' | sed "s|^[[:space:]]*|$f: |"
    done
  done | sort -u
else
  echo "?unavailable"
fi
echo "@@listening"
for f in /proc/net/tcp /proc/net/tcp6; do
  [ -r "$f" ] && awk 'NR>1 && $4=="0A" {print $2}' "$f"
done
echo "@@watch"
for p in $WATCH_PATHS; do
  [ -e "$p" ] || continue
  find "$p" -xdev -type f 2>/dev/null | head -n 20000 | while IFS= read -r f; do
    sha256sum "$f" 2>/dev/null
  done
done
echo "@@end"
"""


@dataclass
class Snapshot:
    os: str = ""
    kernel: str = ""
    pkgmgr: str = ""
    packages: dict[str, str] = field(default_factory=dict)
    pkgdb_issues: list[str] = field(default_factory=list)
    broken_libs: list[str] = field(default_factory=list)
    broken_libs_available: bool = True
    listening: list[int] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    # Windows-only state (empty on Linux)
    services_down: list[str] = field(default_factory=list)
    problem_devices: list[str] = field(default_factory=list)
    # "Log/Provider/EventId" -> {"level": ..., "count": n, "message": first line}
    events: dict[str, dict] = field(default_factory=dict)
    pending_reboot: list[str] = field(default_factory=list)
    last_boot: str = ""

    def to_dict(self) -> dict:
        return {
            "os": self.os, "kernel": self.kernel, "pkgmgr": self.pkgmgr,
            "package_count": len(self.packages), "pkgdb_issues": self.pkgdb_issues,
            "broken_libs": self.broken_libs, "listening_ports": self.listening,
            "watched_files": len(self.files), "error": self.error,
            "services_down": self.services_down, "problem_devices": self.problem_devices,
            "events": self.events, "pending_reboot": self.pending_reboot,
            "last_boot": self.last_boot,
        }


def parse(output: str) -> Snapshot:
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        m = re.fullmatch(r"@@(\w+)", line.strip())
        if m:
            current = m.group(1)
            sections.setdefault(current, [])
        elif current:
            sections[current].append(line)

    snap = Snapshot()
    snap.os = "\n".join(sections.get("os", [])).strip()
    snap.kernel = "\n".join(sections.get("kernel", [])).strip()
    snap.pkgmgr = "\n".join(sections.get("pkgmgr", [])).strip()
    for line in sections.get("packages", []):
        name, sep, version = line.partition("\t")
        if sep and name:
            snap.packages[name.strip()] = version.strip()
    snap.pkgdb_issues = [l.rstrip() for l in sections.get("pkgdb", []) if l.strip()]
    libs = [l.strip() for l in sections.get("brokenlibs", []) if l.strip()]
    if libs == ["?unavailable"]:
        snap.broken_libs_available = False
        libs = []
    # "path: libfoo.so.1 => not found" -> "path: libfoo.so.1"
    snap.broken_libs = sorted({re.sub(r"\s*=>\s*not found.*$", "", l) for l in libs})
    ports = set()
    for addr in sections.get("listening", []):
        _, _, port = addr.strip().rpartition(":")
        if port:
            try:
                ports.add(int(port, 16))
            except ValueError:
                pass
    snap.listening = sorted(ports)
    for line in sections.get("watch", []):
        digest, _, path = line.partition("  ")
        if path:
            snap.files[path] = digest
    if "end" not in sections:
        snap.error = "probe output was truncated"
    return snap


def capture(sandbox: DockerSandbox, watch_paths: list[str], lib_scan_paths: list[str],
            ignore_files: list[str] = ()) -> Snapshot:
    env = (f"WATCH_PATHS={shlex.quote(' '.join(watch_paths))} "
           f"LIB_SCAN_PATHS={shlex.quote(' '.join(lib_scan_paths))}")
    res = sandbox.exec(f"{env}; export WATCH_PATHS LIB_SCAN_PATHS\n{PROBE_SCRIPT}", timeout=600)
    snap = parse(res.stdout)
    snap.files = {p: d for p, d in snap.files.items()
                  if not any(fnmatch(p, pat) for pat in ignore_files)}
    if res.timed_out:
        snap.error = "health probe timed out"
    return snap
