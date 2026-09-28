"""The estate manifest (estate.toml): every repository, package and check PatchLab Internal maintains."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Check, ConfigError, Sidecar, parse_sidecars

# "sql" is a schema with no package manager: health checks only, nothing to scan.
ECOSYSTEMS = ("npm", "python", "cargo", "go", "gradle", "swift", "sql")
# Ecosystems the estate layer can scan and propose updates for today. The
# others can still have health checks; their advisories are reported as not scanned.
PROPOSERS = ("npm",)
# Ecosystems whose advisories are scanned and reported (proposals need a PROPOSER).
SCANNERS = ("npm", "python", "go", "cargo")
PUBLISH_MODES = ("report-only", "draft-pr")

# Values that look like real credentials. estate.toml is committed and its env
# reaches sandboxes, so it may only hold throwaway test values.
SECRET_PATTERNS = [
    (re.compile(r"\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk-(ant-|proj-|live_)?[A-Za-z0-9_-]{20,}"), "API secret key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"), "Stripe live key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), "Google API key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}"), "npm token"),
]
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")


@dataclass
class MirrorSpec:
    """A private git repository the host fetches so sandboxes can install it without a token."""

    name: str
    url: str

    def rewrite_urls(self) -> list[str]:
        """The spellings of this remote that package managers hand to git.

        git applies the longest matching insteadOf prefix, so the ".git" forms
        win over the bare ones for URLs that carry the suffix."""
        m = re.fullmatch(r"https://([^/]+)/([^/]+)/([^/]+?)(?:\.git)?/?", self.url)
        if not m:
            raise ConfigError(f"mirror '{self.name}': url must look like https://host/owner/repo")
        host, owner, repo = m.groups()
        forms = []
        for base in (f"https://{host}/{owner}/{repo}", f"ssh://git@{host}/{owner}/{repo}",
                     f"git@{host}:{owner}/{repo}", f"git://{host}/{owner}/{repo}"):
            forms += [base + ".git", base]
        return forms


@dataclass
class Package:
    repo: "Repo"
    path: str
    ecosystem: str
    image: str | None = None
    setup: list[str] = field(default_factory=list)
    install: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    sidecars: list[Sidecar] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    mirrors: list[str] = field(default_factory=list)
    check_network: str = "isolated"
    memory: str = "4g"
    cpus: str = "2"
    # Set when this package can't be built on the runner (macOS-only SDKs):
    # every report says it was not verified, and why.
    unsupported: str | None = None
    lockfile: str | None = None
    # What the checks do not prove (a live service they stub, a platform they
    # skip). Every proposal for this package says so, so a green gate is never
    # read as more than it is.
    not_covered: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.repo.name}/{self.path}" if self.path != "." else self.repo.name

    @property
    def slug(self) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "-", self.id).strip("-")


@dataclass
class Repo:
    name: str
    url: str
    branch: str = "main"
    packages: list[Package] = field(default_factory=list)


@dataclass
class Estate:
    path: Path
    workdir: Path
    publish: str = "report-only"
    ca_bundle: Path | None = None
    mirrors: dict[str, MirrorSpec] = field(default_factory=dict)
    repos: list[Repo] = field(default_factory=list)
    # Dependency updates the tool will never propose (name -> reason).
    ignore: dict[str, str] = field(default_factory=dict)

    def packages(self) -> list[Package]:
        return [p for r in self.repos for p in r.packages]

    def find(self, ident: str) -> Package:
        """Look a package up by "repo/path" (or "repo" for a single-package repo)."""
        for p in self.packages():
            if p.id == ident:
                return p
        repo = [p for p in self.packages() if p.repo.name == ident]
        if len(repo) == 1:
            return repo[0]
        known = ", ".join(p.id for p in self.packages())
        raise ConfigError(f"no package '{ident}' in {self.path.name} (known: {known})")

    def repo(self, name: str) -> Repo:
        for r in self.repos:
            if r.name == name:
                return r
        raise ConfigError(f"no repo '{name}' in {self.path.name}")

    @property
    def repos_dir(self) -> Path:
        return self.workdir / "repos"

    @property
    def mirrors_dir(self) -> Path:
        return self.workdir / "mirrors"

    @property
    def state_dir(self) -> Path:
        return self.workdir / "state"


def _strs(value, where: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: expected a string or list of strings")
    return value


def _req(table: dict, key: str, where: str):
    if key not in table:
        raise ConfigError(f"{where}: missing required key '{key}'")
    return table[key]


def find_secrets(value: str) -> list[str]:
    return [what for pattern, what in SECRET_PATTERNS if pattern.search(value)]


def _checks(items: list, where: str) -> list[Check]:
    out = []
    for i, c in enumerate(items):
        w = f"{where} check #{i + 1}"
        results = c.get("results")
        if results is not None and results != "tap" and not str(results).startswith("junit:"):
            raise ConfigError(f"{w}: results must be 'tap' or 'junit:/path'")
        out.append(Check(name=str(_req(c, "name", w)), run=str(_req(c, "run", w)),
                         category=str(c.get("category", "functional")),
                         timeout=int(c.get("timeout", 1200)), critical=bool(c.get("critical", True)),
                         results=results, perf_tolerance=c.get("perf_tolerance")))
    names = [c.name for c in out]
    if len(names) != len(set(names)):
        raise ConfigError(f"{where}: check names must be unique")
    return out


def load(path: str | Path) -> Estate:
    path = Path(path).expanduser().resolve()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"estate manifest not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None

    est = data.get("estate", {})
    workdir = Path(str(est.get("workdir", "~/.local/share/patchlab-internal/estate"))).expanduser()
    if not workdir.is_absolute():
        workdir = (path.parent / workdir).resolve()
    estate = Estate(path=path, workdir=workdir, publish=str(est.get("publish", "report-only")))
    if estate.publish not in PUBLISH_MODES:
        raise ConfigError(f"[estate].publish must be one of {', '.join(PUBLISH_MODES)}")
    # Host-specific settings can come from the environment, so one committed
    # estate.toml works on every runner.
    if os.environ.get("PATCHLAB_INTERNAL_ESTATE_WORKDIR"):
        estate.workdir = Path(os.environ["PATCHLAB_INTERNAL_ESTATE_WORKDIR"]).expanduser().resolve()
    ca = os.environ.get("PATCHLAB_INTERNAL_CA_BUNDLE") or est.get("ca_bundle")
    if ca:
        estate.ca_bundle = Path(str(ca)).expanduser().resolve()
        if not estate.ca_bundle.is_file():
            raise ConfigError(f"CA bundle not found: {estate.ca_bundle}")
    estate.ignore = {str(k): str(v) for k, v in data.get("ignore", {}).items()}

    for i, m in enumerate(data.get("mirror", [])):
        w = f"[[mirror]] #{i + 1}"
        spec = MirrorSpec(name=str(_req(m, "name", w)), url=str(_req(m, "url", w)))
        if not NAME.fullmatch(spec.name):
            raise ConfigError(f"{w}: invalid name {spec.name!r}")
        spec.rewrite_urls()  # validates the URL
        estate.mirrors[spec.name] = spec

    for i, r in enumerate(data.get("repo", [])):
        w = f"[[repo]] #{i + 1}"
        repo = Repo(name=str(_req(r, "name", w)), url=str(_req(r, "url", w)),
                    branch=str(r.get("branch", "main")))
        if not NAME.fullmatch(repo.name):
            raise ConfigError(f"{w}: invalid name {repo.name!r}")
        if not repo.url.startswith("https://"):
            raise ConfigError(f"{w}: url must be https://")
        for j, p in enumerate(r.get("package", [])):
            pw = f"{repo.name} package #{j + 1}"
            pkg = Package(repo=repo, path=str(p.get("path", ".")).strip("/") or ".",
                          ecosystem=str(_req(p, "ecosystem", pw)))
            if pkg.ecosystem not in ECOSYSTEMS:
                raise ConfigError(f"{pw}: ecosystem must be one of {', '.join(ECOSYSTEMS)}")
            if ".." in Path(pkg.path).parts or Path(pkg.path).is_absolute():
                raise ConfigError(f"{pw}: path must stay inside the repository")
            pkg.unsupported = p.get("unsupported")
            pkg.image = p.get("image")
            pkg.setup = _strs(p.get("setup", []), f"{pw} setup")
            pkg.install = _strs(p.get("install", []), f"{pw} install")
            pkg.env = {str(k): str(v) for k, v in p.get("env", {}).items()}
            pkg.sidecars = parse_sidecars(p.get("sidecars", []), f"{pw} sidecars")
            pkg.checks = _checks(p.get("checks", []), pw)
            pkg.mirrors = _strs(p.get("mirrors", []), f"{pw} mirrors")
            pkg.check_network = str(p.get("check_network", "isolated"))
            pkg.memory = str(p.get("memory", "4g"))
            pkg.cpus = str(p.get("cpus", "2"))
            pkg.lockfile = p.get("lockfile")
            pkg.not_covered = _strs(p.get("not_covered", []), f"{pw} not_covered")
            if not pkg.unsupported:
                if not pkg.image:
                    raise ConfigError(f"{pw}: image is required (or mark the package unsupported)")
                if not pkg.checks:
                    raise ConfigError(f"{pw}: define at least one check (or mark it unsupported)")
            for name in pkg.mirrors:
                if name not in estate.mirrors:
                    raise ConfigError(f"{pw}: unknown mirror '{name}' (declare it with [[mirror]])")
            if pkg.check_network not in ("open", "isolated"):
                raise ConfigError(f"{pw}: check_network must be 'open' or 'isolated'")
            repo.packages.append(pkg)
        estate.repos.append(repo)

    names = [r.name for r in estate.repos]
    if len(names) != len(set(names)):
        raise ConfigError("repo names must be unique")
    ids = [p.id for p in estate.packages()]
    if len(ids) != len(set(ids)):
        raise ConfigError("package paths must be unique within a repo")
    problems = secret_problems(estate)
    if problems:
        raise ConfigError("estate.toml must hold only throwaway test values, but these look like "
                          "real credentials: " + "; ".join(problems))
    return estate


def secret_problems(estate: Estate) -> list[str]:
    problems = []
    for p in estate.packages():
        values = [(f"{p.id} env {k}", v) for k, v in p.env.items()]
        values += [(f"{p.id} sidecar {s.name} env {k}", v) for s in p.sidecars for k, v in s.env.items()]
        values += [(f"{p.id} check {c.name}", c.run) for c in p.checks]
        values += [(f"{p.id} install", c) for c in p.install + p.setup]
        for where, v in values:
            for what in find_secrets(v):
                problems.append(f"{where} ({what})")
    return problems
