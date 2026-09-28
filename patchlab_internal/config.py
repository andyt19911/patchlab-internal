"""Load and validate PatchLab Internal configuration files (TOML)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PLATFORMS = {
    # platform: (providers, patch kinds)
    "linux": (("docker", "aws", "azure", "gcp", "oci"), ("source", "os-packages", "package-file", "script")),
    "windows": (("hyperv", "vsphere", "local", "aws", "azure", "gcp", "oci"),
                ("windows-update", "package-file", "script")),
}
PATCH_KINDS = tuple(sorted({k for _, kinds in PLATFORMS.values() for k in kinds}))

# Windows Update classifications installed by default for "windows-update"
# patches. This mirrors what Windows Autopatch / Windows Update for Business
# quality-update rings deliver: monthly cumulative + security + critical fixes.
DEFAULT_WU_CATEGORIES = ["Security Updates", "Critical Updates", "Update Rollups", "Updates"]

DEFAULT_WATCH_REGISTRY = [
    # Protocol/cipher and authentication hardening that updates commonly change.
    r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Kdc",
    r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    r"HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers",
]


class ConfigError(Exception):
    pass


@dataclass
class Check:
    """A command run in the sandbox before and after the patch."""

    name: str
    run: str
    category: str = "functional"
    timeout: int = 300
    # A failing critical check fails the run; a non-critical one only warns.
    critical: bool = True
    # How to read per-test results: None (exit code only), "tap" (stdout),
    # or "junit:/path/in/sandbox.xml".
    results: str | None = None
    # Warn when the patched run is this much slower (0.5 = 50% slower).
    perf_tolerance: float | None = None


@dataclass
class Deploy:
    """A host directory copied into the sandbox before testing."""

    src: Path
    dest: str
    exclude: list[str] = field(default_factory=list)


@dataclass
class Patch:
    kind: str
    description: str = ""
    # source: a unified diff; package-file: .deb/.rpm/.apk files; script: a shell script.
    files: list[Path] = field(default_factory=list)
    # source: directory in the sandbox the diff applies to.
    target: str | None = None
    # os-packages: packages to upgrade (empty = every pending update).
    packages: list[str] = field(default_factory=list)
    # script: inline command (alternative to a script file).
    run: str | None = None
    # How --verify-rollback backs the patch out. Linux: a shell command.
    # Windows: "uninstall" (remove the installed updates, the realistic
    # production back-out), "checkpoint" (revert the VM) or a PowerShell script.
    rollback: str | None = None
    timeout: int = 1800
    # windows-update: KB filter lives in `packages`; these tune what is picked.
    categories: list[str] = field(default_factory=lambda: list(DEFAULT_WU_CATEGORIES))
    include_preview: bool = False
    microsoft_update: bool = True   # also .NET and other Microsoft products
    max_passes: int = 3             # re-scan after reboots until nothing is left
    # Windows: run patch installers as SYSTEM via a scheduled task (the
    # Windows Update API and wusa refuse to install from remote sessions).
    run_as: str = "system"
    # package-file: arguments for .exe installers.
    exe_args: str = "/quiet /norestart"

    @property
    def label(self) -> str:
        if self.description:
            return self.description
        if self.kind == "os-packages":
            return "OS package updates: " + (", ".join(self.packages) or "all pending")
        if self.kind == "windows-update":
            return "Windows Update: " + (", ".join(self.packages) or
                                         "all pending " + "/".join(self.categories))
        if self.files:
            return f"{self.kind}: " + ", ".join(f.name for f in self.files)
        return f"{self.kind}: {self.run}"


@dataclass
class Sandbox:
    images: list[str]
    setup: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    memory: str = "2g"
    cpus: str = "2"
    pids: int = 2048
    network: str = "bridge"
    cache: bool = True
    platform: str = "linux"
    provider: str = "docker"
    # Windows guests
    username: str = "Administrator"      # password comes from PATCHLAB_INTERNAL_GUEST_PASSWORD
    boot_timeout: int = 2700             # updates can take a long time to finish on reboot
    settle_seconds: int = 120            # let delayed-start services come up before probing
    max_reboots: int = 4
    provider_options: dict = field(default_factory=dict)   # [sandbox.hyperv] / [sandbox.vsphere]


@dataclass
class Health:
    """Built-in OS health probes captured before and after the patch."""

    enabled: bool = True
    watch_paths: list[str] = field(default_factory=lambda: ["/etc"])
    # Glob patterns for watched files that change routinely and are not config.
    ignore_files: list[str] = field(default_factory=lambda: ["/etc/ld.so.cache"])
    # Windows: registry keys whose values are compared before/after.
    watch_registry: list[str] = field(default_factory=list)
    # Windows: ignore listening ports at or above this (dynamic RPC range).
    ignore_ports_from: int = 49152
    # Windows: automatic services not to flag when stopped (empty = built-in list).
    ignore_services: list[str] = field(default_factory=list)
    lib_scan_paths: list[str] = field(
        default_factory=lambda: ["/usr/bin", "/usr/sbin", "/usr/local/bin"]
    )


@dataclass
class Config:
    name: str
    path: Path
    sandbox: Sandbox
    deploy: list[Deploy]
    services: list[str]
    checks: list[Check]
    health: Health
    patch: Patch | None = None

    @property
    def base_dir(self) -> Path:
        return self.path.parent


def _require(table: dict, key: str, where: str):
    if key not in table:
        raise ConfigError(f"{where}: missing required key '{key}'")
    return table[key]


def _str_list(value, where: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: expected a string or list of strings")
    return value


def _parse_patch(table: dict, base: Path, platform: str, where: str = "[patch]") -> Patch:
    kind = _require(table, "kind", where)
    kinds = PLATFORMS[platform][1]
    if kind not in kinds:
        raise ConfigError(f"{where}: kind must be one of {', '.join(kinds)} on {platform}")
    files = [(base / f).resolve() for f in _str_list(table.get("files", table.get("file", [])), where)]
    patch = Patch(
        kind=kind,
        description=table.get("description", ""),
        files=files,
        target=table.get("target"),
        packages=_str_list(table.get("packages", []), where),
        run=table.get("run"),
        rollback=table.get("rollback"),
        timeout=int(table.get("timeout", 1800 if platform == "linux" else 7200)),
        categories=_str_list(table.get("categories", DEFAULT_WU_CATEGORIES), where),
        include_preview=bool(table.get("include_preview", False)),
        microsoft_update=bool(table.get("microsoft_update", True)),
        max_passes=int(table.get("max_passes", 3)),
        run_as=str(table.get("run_as", "system")),
        exe_args=str(table.get("exe_args", "/quiet /norestart")),
    )
    validate_patch(patch)
    return patch


def validate_patch(patch: Patch) -> None:
    if patch.kind in ("source", "package-file") and not patch.files:
        raise ConfigError(f"{patch.kind} patch needs at least one file")
    if patch.kind == "source" and not patch.target:
        raise ConfigError("source patch needs a 'target' directory in the sandbox")
    if patch.kind == "script" and not (patch.files or patch.run):
        raise ConfigError("script patch needs a script file or a 'run' command")
    if patch.kind == "windows-update":
        bad = [k for k in patch.packages if not k.upper().startswith("KB") or not k[2:].isdigit()]
        if bad:
            raise ConfigError(f"windows-update filters must be KB numbers like KB5044281: {bad}")
        patch.packages = [k.upper() for k in patch.packages]
    if patch.run_as not in ("system", "user"):
        raise ConfigError("run_as must be 'system' or 'user'")
    for f in patch.files:
        if not f.is_file():
            raise ConfigError(f"patch file not found: {f}")


def parse_patch_spec(spec: str, default_target: str | None, platform: str = "linux") -> Patch:
    """Parse a command-line patch spec.

    Linux
      source:fix.patch            apply a diff to the first deployed directory
      os-packages                 install every pending OS update
      os-packages:openssl,libssl3 upgrade only these packages
      package-file:a.deb,b.deb    install vendor-supplied packages
      script:hotfix.sh            run an arbitrary patch script
    Windows
      windows-update              every pending quality/security update (as Autopatch would)
      windows-update:KB5044281    only these KBs
      package-file:x.msu,y.msi    install .msu/.cab/.msi/.msp/.exe files
      script:hotfix.ps1           run a PowerShell patch script
    """
    kind, _, arg = spec.partition(":")
    # Windows paths contain a drive-letter colon: "script:C:\x.ps1" keeps it.
    kinds = PLATFORMS[platform][1]
    if kind not in kinds:
        raise ConfigError(f"unknown patch kind '{kind}' for {platform} (expected {', '.join(kinds)})")
    items = [a for a in arg.split(",") if a] if arg else []
    if kind in ("os-packages", "windows-update"):
        patch = Patch(kind=kind, packages=items)
        if platform == "windows":
            patch.timeout = 7200
    else:
        patch = Patch(kind=kind, files=[Path(i).resolve() for i in items], target=default_target)
        if platform == "windows":
            patch.timeout = 7200
    validate_patch(patch)
    return patch


def load(path: str | Path) -> Config:
    path = Path(path).resolve()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    base = path.parent

    # include = ["checks.toml"]: share checks/services/deploy/health between configs
    # (e.g. the same checks for Hyper-V testing and vSphere production).
    for inc in _str_list(data.get("include", []), "include"):
        inc_path = (base / inc).resolve()
        try:
            extra = tomllib.loads(inc_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"included file not found: {inc_path}") from None
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{inc_path}: {e}") from None
        for key in ("checks", "deploy", "services"):
            if key in extra:
                items = extra[key]
                if key == "deploy":  # paths in the included file are relative to it
                    items = [{**d, "src": str((inc_path.parent / d["src"]).resolve())} for d in items]
                data[key] = list(data.get(key, [])) + list(items)
        if "health" in extra and "health" not in data:
            data["health"] = extra["health"]

    sb = _require(data, "sandbox", str(path))
    sandbox = Sandbox(
        images=_str_list(_require(sb, "images", "[sandbox]"), "[sandbox].images"),
        setup=_str_list(sb.get("setup", []), "[sandbox].setup"),
        env={str(k): str(v) for k, v in sb.get("env", {}).items()},
        memory=str(sb.get("memory", "2g")),
        cpus=str(sb.get("cpus", "2")),
        pids=int(sb.get("pids", 2048)),
        network=str(sb.get("network", "bridge")),
        cache=bool(sb.get("cache", True)),
        platform=str(sb.get("platform", "linux")),
        username=str(sb.get("username", "Administrator")),
        boot_timeout=int(sb.get("boot_timeout", 2700)),
        settle_seconds=int(sb.get("settle_seconds", 120)),
        max_reboots=int(sb.get("max_reboots", 4)),
    )
    if not sandbox.images:
        raise ConfigError("[sandbox].images must list at least one image")
    if sandbox.platform not in PLATFORMS:
        raise ConfigError(f"[sandbox].platform must be one of {', '.join(PLATFORMS)}")
    providers = PLATFORMS[sandbox.platform][0]
    sandbox.provider = str(sb.get("provider", providers[0]))
    if sandbox.provider not in providers:
        raise ConfigError(f"[sandbox].provider for {sandbox.platform} must be one of {', '.join(providers)}")
    opts = sb.get(sandbox.provider, {})
    if not isinstance(opts, dict):
        raise ConfigError(f"[sandbox.{sandbox.provider}] must be a table")
    sandbox.provider_options = opts
    windows = sandbox.platform == "windows"

    deploy = []
    for i, d in enumerate(data.get("deploy", [])):
        where = f"[[deploy]] #{i + 1}"
        src = (base / _require(d, "src", where)).resolve()
        if not src.is_dir():
            raise ConfigError(f"{where}: source directory not found: {src}")
        deploy.append(Deploy(src=src, dest=_require(d, "dest", where),
                             exclude=_str_list(d.get("exclude", []), where)))

    checks = []
    for i, c in enumerate(data.get("checks", [])):
        where = f"[[checks]] #{i + 1}"
        results = c.get("results")
        if results is not None and results != "tap" and not results.startswith("junit:"):
            raise ConfigError(f"{where}: results must be 'tap' or 'junit:/path'")
        checks.append(Check(
            name=_require(c, "name", where),
            run=_require(c, "run", where),
            category=c.get("category", "functional"),
            timeout=int(c.get("timeout", 300)),
            critical=bool(c.get("critical", True)),
            results=results,
            perf_tolerance=c.get("perf_tolerance"),
        ))
    names = [c.name for c in checks]
    if len(names) != len(set(names)):
        raise ConfigError("check names must be unique")
    if not checks:
        raise ConfigError("define at least one [[checks]] entry")

    h = data.get("health", {})
    health = Health(
        enabled=bool(h.get("enabled", True)),
        watch_paths=_str_list(h.get("watch_paths", [r"C:\Windows\System32\drivers\etc"]
                                    if windows else ["/etc"]), "[health].watch_paths"),
        ignore_files=_str_list(h.get("ignore_files", [] if windows else ["/etc/ld.so.cache"]),
                               "[health].ignore_files"),
        lib_scan_paths=_str_list(
            h.get("lib_scan_paths", ["/usr/bin", "/usr/sbin", "/usr/local/bin"]),
            "[health].lib_scan_paths",
        ),
        watch_registry=_str_list(h.get("watch_registry", DEFAULT_WATCH_REGISTRY if windows else []),
                                 "[health].watch_registry"),
        ignore_ports_from=int(h.get("ignore_ports_from", 49152 if windows else 65536)),
        ignore_services=_str_list(h.get("ignore_services", []), "[health].ignore_services"),
    )

    patch = _parse_patch(data["patch"], base, sandbox.platform) if "patch" in data else None

    return Config(
        name=data.get("name", path.stem),
        path=path,
        sandbox=sandbox,
        deploy=deploy,
        services=_str_list(data.get("services", []), "services"),
        checks=checks,
        health=health,
        patch=patch,
    )
