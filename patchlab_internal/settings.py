"""User settings written by `patchlab-internal setup` and `patchlab-internal web enable|disable`.

Stored as TOML in:
  $PATCHLAB_INTERNAL_HOME/settings.toml                  if PATCHLAB_INTERNAL_HOME is set
  %APPDATA%\\PatchLab Internal\\settings.toml            on Windows
  $XDG_CONFIG_HOME/patchlab_internal/settings.toml elsewhere (~/.config/patchlab_internal)
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_WEB_PORT = 8750


def settings_dir() -> Path:
    if os.environ.get("PATCHLAB_INTERNAL_HOME"):
        return Path(os.environ["PATCHLAB_INTERNAL_HOME"])
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "PatchLab Internal"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "patchlab_internal"


def settings_path() -> Path:
    return settings_dir() / "settings.toml"


@dataclass
class WebSettings:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = DEFAULT_WEB_PORT
    max_parallel_runs: int = 2


@dataclass
class Settings:
    reports_dir: str = ""          # empty: ./reports relative to where you run patchlab_internal
    configs_dir: str = ""          # where the front end looks for configs
    web: WebSettings = field(default_factory=WebSettings)
    exists: bool = False

    def reports_path(self) -> Path:
        return Path(self.reports_dir).expanduser() if self.reports_dir else Path("reports")

    def configs_path(self) -> Path:
        return Path(self.configs_dir).expanduser() if self.configs_dir else Path.cwd()


def load(path: Path | None = None) -> Settings:
    path = path or settings_path()
    s = Settings()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return s
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{path}: {e}") from None
    s.exists = True
    general = data.get("general", {})
    s.reports_dir = str(general.get("reports_dir", ""))
    s.configs_dir = str(general.get("configs_dir", ""))
    w = data.get("web", {})
    s.web = WebSettings(enabled=bool(w.get("enabled", False)), host=str(w.get("host", "127.0.0.1")),
                        port=int(w.get("port", DEFAULT_WEB_PORT)),
                        max_parallel_runs=int(w.get("max_parallel_runs", 2)))
    return s


def _q(value: str) -> str:
    # TOML literal strings keep Windows paths readable; fall back to escaping if needed.
    if "'" not in value and "\n" not in value:
        return f"'{value}'"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def save(s: Settings, path: Path | None = None) -> Path:
    path = path or settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# PatchLab Internal settings (written by `patchlab-internal setup`; safe to edit)\n\n"
        "[general]\n"
        f"reports_dir = {_q(s.reports_dir)}\n"
        f"configs_dir = {_q(s.configs_dir)}\n\n"
        "[web]\n"
        "# Optional browser front end: `patchlab-internal web enable` / `patchlab-internal web disable`\n"
        f"enabled = {'true' if s.web.enabled else 'false'}\n"
        f"host = {_q(s.web.host)}\n"
        f"port = {int(s.web.port)}\n"
        f"max_parallel_runs = {int(s.web.max_parallel_runs)}\n",
        encoding="utf-8")
    return path


def import_web():
    """Import the optional front end, or return None if it is not installed.

    In a source checkout the package sits in ../web next to this package, so
    it works without a separate `pip install ./web`.
    """
    try:
        import patchlab_internal_web
        return patchlab_internal_web
    except ImportError:
        pass
    checkout = Path(__file__).resolve().parent.parent / "web"
    if (checkout / "patchlab_internal_web" / "__init__.py").is_file():
        sys.path.insert(0, str(checkout))
        try:
            import patchlab_internal_web
            return patchlab_internal_web
        except ImportError:
            return None
    return None


def web_installed() -> bool:
    return import_web() is not None
