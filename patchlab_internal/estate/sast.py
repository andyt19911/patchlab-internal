"""Code scanning: find vulnerabilities in a package's own code, and hand each one to the repair agent.

Tools, all pinned so a scan is repeatable:

- Opengrep, with the rules the estate names in ``[sast] rules`` (Caer's own
  rulesets: injection sinks, unsafe deserialisation, quantum-vulnerable crypto).
  It runs in its own image with no network, on a read-only copy of the checkout.
- bandit for Python and gosec for Go, in a tool container (bridge.ToolBox).

A finding is identified by tool, rule, file and the text of the flagged line,
so it keeps its identity when code above it moves.

Blocking findings (Opengrep ERROR, bandit HIGH, gosec HIGH) outside test code
become fix plans, one per rule and file. The repair agent gets a brief with the
locations; its change is tested like any other (baseline, apply, verify, roll
back), and the gate needs the finding gone on a re-scan, no new findings, no
regressions, and no suppression comment added. An agent that judges a finding
a false positive says so instead of changing code, and a person decides.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import bridge, gitops, state
from .repair import VERDICT_PATH

OPENGREP_VERSION = "1.4.2"
# Opengrep's published sha256 for opengrep_musllinux_x86 v1.4.2, as Caer pins it.
OPENGREP_SHA256 = "409c1cf9728f21c401b3ab443d6c1f29e9d26fc22fbf242c30d269e6119ac04c"
OPENGREP_IMAGE = f"patchlab-opengrep:{OPENGREP_VERSION}"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_IMAGE = f"patchlab-gitleaks:{GITLEAKS_VERSION}"
BANDIT = "bandit==1.9.4"
GOSEC = "github.com/securego/gosec/v2/cmd/gosec@v2.29.0"

# Test code is scanned and listed but never gets a fix plan: a test that calls
# eval() on its own fixture is not a vulnerability.
TEST_CODE = re.compile(r"(^|/)(__tests__|tests?|spec|testdata|fixtures?|e2e)/|\.(test|spec)\.[cm]?[jt]sx?$|"
                       r"(^|/)test_[^/]*\.py$|_test\.(py|go)$|(^|/)conftest\.py$")
EXCLUDE_DIRS = ("node_modules", ".venv", "venv", "dist", "build", ".git", "vendor", "target", ".next")
# Comments that silence a scanner. An agent adding one has hidden a finding, not fixed it.
SUPPRESSION = re.compile(r"#\s*nosec|//\s*#?nosec|nosemgrep|noopengrep|eslint-disable|noqa:\s*S\d|"
                         r"@SuppressWarnings|#\s*type:\s*ignore", re.I)


@dataclass
class Finding:
    tool: str
    rule: str
    file: str          # repo-relative
    line: int
    severity: str      # high / medium / low
    message: str
    code: str = ""
    cwe: str = ""

    @property
    def fingerprint(self) -> str:
        text = re.sub(r"\s+", " ", self.code).strip()
        return hashlib.sha256(f"{self.tool}|{self.rule}|{self.file}|{text or self.line}".encode()).hexdigest()[:16]

    @property
    def blocking(self) -> bool:
        return self.severity == "high" and not TEST_CODE.search(self.file)

    def to_dict(self) -> dict:
        return {**self.__dict__, "fingerprint": self.fingerprint, "blocking": self.blocking}


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    tools: dict[str, str] = field(default_factory=dict)      # tool -> "ok" or the error
    rules: dict = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return all(v == "ok" for v in self.tools.values()) and bool(self.tools)

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings], "tools": self.tools, "rules": self.rules,
                "complete": self.complete,
                "counts": {s: sum(1 for f in self.findings if f.severity == s) for s in ("high", "medium", "low")}}


def result_from(d: dict) -> Result:
    keep = ("tool", "rule", "file", "line", "severity", "message", "code", "cwe")
    return Result([Finding(**{k: f[k] for k in keep}) for f in d.get("findings", [])],
                  dict(d.get("tools", {})), dict(d.get("rules", {})))


# ---------------------------------------------------------------- parsers

def _rel(path: str, prefix: str) -> str:
    path = path.removeprefix("./")
    return path[len(prefix):].lstrip("/") if prefix and path.startswith(prefix) else path


def parse_opengrep(text: str, prefix: str = "/src") -> list[Finding]:
    data = json.loads(text)
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in data.get("results", []):
        ex = r.get("extra", {})
        cwe = (ex.get("metadata") or {}).get("cwe", "")
        out.append(Finding("opengrep", r["check_id"].rsplit(".", 1)[-1], _rel(r["path"], prefix),
                           int(r["start"]["line"]), sev.get(ex.get("severity", ""), "low"),
                           " ".join(str(ex.get("message", "")).split()), ex.get("lines", ""),
                           cwe[0] if isinstance(cwe, list) and cwe else str(cwe)))
    return out


def parse_bandit(text: str, prefix: str) -> list[Finding]:
    data = json.loads(text)
    out = []
    for r in data.get("results", []):
        code = "\n".join(line.split(" ", 1)[-1] for line in r.get("code", "").splitlines()
                         if line.split(" ", 1)[0] == str(r["line_number"]))
        # bandit's own high-severity, low-confidence results are mostly noise.
        sev = r["issue_severity"].lower()
        if sev == "high" and r.get("issue_confidence") == "LOW":
            sev = "medium"
        out.append(Finding("bandit", r["test_id"], _rel(r["filename"], prefix), int(r["line_number"]), sev,
                           r["issue_text"], code, f"CWE-{(r.get('issue_cwe') or {}).get('id', '')}".rstrip("-")))
    return out


def parse_gosec(text: str, prefix: str) -> list[Finding]:
    data = json.loads(text)
    out = []
    for r in data.get("Issues") or []:
        sev = r["severity"].lower()
        if sev == "high" and r.get("confidence") == "LOW":
            sev = "medium"
        line = str(r.get("line", "0")).split("-")[0]
        out.append(Finding("gosec", r["rule_id"], _rel(r["file"], prefix), int(line), sev, r["details"],
                           r.get("code", ""), f"CWE-{(r.get('cwe') or {}).get('id', '')}".rstrip("-")))
    return out


# ---------------------------------------------------------------- running

def _docker(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _build_tool(estate, tag: str, dockerfile: str, base: str, build_args: dict[str, str], run_line: str) -> str | None:
    """Build one of PatchLab's scanner images once per runner. None, or why it failed."""
    if _docker("image", "inspect", tag, timeout=60).returncode == 0:
        return None
    from . import images
    err = images.pull(base)
    if err:
        return f"could not pull {base}: {err}"
    import tempfile
    with tempfile.TemporaryDirectory(dir=estate.workdir) as ctx:
        text = (bridge.ASSETS / dockerfile).read_text(encoding="utf-8")
        if estate.ca_bundle:
            # A runner behind a TLS-inspecting proxy: its CA bundle is mounted for the
            # downloads only, and never stays in the image.
            shutil.copy(estate.ca_bundle, Path(ctx) / "ca.crt")
            mounts = " ".join(f"--mount=type=bind,source=ca.crt,target={t}"
                              for t in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"))
            text = text.replace(f"RUN {run_line}", f"RUN {mounts} {run_line}", 1)
        (Path(ctx) / "Dockerfile").write_text(text, encoding="utf-8")
        args = ["build", "-q", "-t", tag]
        for k, v in build_args.items():
            args += ["--build-arg", f"{k}={v}"]
        res = _docker(*args, ctx, timeout=1200)
    return None if res.returncode == 0 else f"building {tag} failed: {res.stderr.strip()[-300:]}"


def ensure_opengrep(estate) -> str | None:
    # A runner that can't reach the Alpine package CDN names an Alpine-based image
    # that already has libstdc++ (e.g. node:24-alpine); no packages are installed then.
    base = os.environ.get("PATCHLAB_INTERNAL_OPENGREP_BASE") or "alpine:3.23"
    args = {"BASE": base, "OPENGREP_VERSION": OPENGREP_VERSION, "OPENGREP_SHA256": OPENGREP_SHA256}
    if os.environ.get("PATCHLAB_INTERNAL_OPENGREP_BASE"):
        args["APK_PACKAGES"] = ""
    return _build_tool(estate, OPENGREP_IMAGE, "opengrep.Dockerfile", base, args, "if [")


def ensure_gitleaks(estate) -> str | None:
    go = "golang:1.26-bookworm"
    return _build_tool(estate, GITLEAKS_IMAGE, "gitleaks.Dockerfile", go,
                       {"GO_IMAGE": go, "GITLEAKS_VERSION": GITLEAKS_VERSION}, "CGO_ENABLED=0")


def rules_dir(estate) -> tuple[Path | None, dict]:
    """Export the rule directories ``[sast] rules`` names ("repo:path") from the
    synced mirrors, at their branch heads. The commit is recorded with every scan."""
    specs = (estate.sast or {}).get("rules", [])
    if not specs:
        return None, {}
    meta, parts = {}, []
    for spec in specs:
        repo_name, _, path = spec.partition(":")
        repo = estate.repo(repo_name)
        mirror = estate.repos_dir / f"{repo.name}.git"
        sha = gitops.head(mirror, repo.branch)
        meta[spec] = sha
        parts.append((mirror, sha, path))
    key = hashlib.sha256(json.dumps(sorted(meta.items())).encode()).hexdigest()[:12]
    dest = estate.workdir / "sast-rules" / key
    if not dest.is_dir():
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.mkdir(parents=True, exist_ok=True)
        for i, (mirror, sha, path) in enumerate(parts):
            archive = subprocess.run(["git", "-C", str(mirror), "archive", sha, path],
                                     capture_output=True, check=True).stdout
            sub = tmp / str(i)
            sub.mkdir()
            subprocess.run(["tar", "-x", "-C", str(sub)], input=archive, check=True)
            # Only rule files: a README or test fixture next to them is not a rule.
            for f in sub.rglob("*"):
                if f.is_file() and f.suffix not in (".yml", ".yaml"):
                    f.unlink()
        tmp.rename(dest)
    return dest, meta


def opengrep(estate, checkout: Path, pkg) -> tuple[list[Finding], str, dict]:
    rules, meta = rules_dir(estate)
    if rules is None:
        return [], "no [sast] rules configured", {}
    err = ensure_opengrep(estate)
    if err:
        return [], err, meta
    target = "/src" if pkg.path == "." else f"/src/{pkg.path}"
    excludes = [a for d in EXCLUDE_DIRS for a in ("--exclude", d)]
    res = _sandboxed(OPENGREP_IMAGE, checkout, "scan", "--config", "/rules", "--json", "--quiet",
                     "--metrics", "off", *excludes, target, mounts=((rules, "/rules"),))
    try:
        return parse_opengrep(res.stdout, "/src"), "ok", meta
    except (json.JSONDecodeError, KeyError) as e:
        return [], f"opengrep failed ({e}): {(res.stderr or res.stdout).strip()[-300:]}", meta


def _sandboxed(image: str, checkout: Path, *args: str, mounts: tuple = ()) -> subprocess.CompletedProcess:
    extra = [a for src, dst in mounts for a in ("-v", f"{src}:{dst}:ro")]
    return _docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:exec", "-e", "HOME=/tmp",
                   "-v", f"{checkout}:/src:ro", *extra, image, *args, timeout=1800)


def gitleaks(estate, checkout: Path, pkg) -> tuple[list[Finding], str]:
    """Credentials committed in the package's files. Values are redacted by gitleaks
    itself, so no secret reaches PatchLab's state or a brief."""
    err = ensure_gitleaks(estate)
    if err:
        return [], err
    target = "/src" if pkg.path == "." else f"/src/{pkg.path}"
    res = _sandboxed(GITLEAKS_IMAGE, checkout, "dir", target, "--redact", "--no-banner", "--exit-code", "0",
                     "--report-format", "json", "--report-path", "/dev/stdout", "--log-level", "error")
    try:
        return parse_gitleaks(res.stdout, "/src"), "ok"
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return [], f"gitleaks failed ({e}): {(res.stderr or res.stdout).strip()[-300:]}"


def parse_gitleaks(text: str, prefix: str) -> list[Finding]:
    out = []
    for r in json.loads(text or "[]") or []:
        out.append(Finding("gitleaks", r["RuleID"], _rel(r["File"], prefix), int(r["StartLine"]), "high",
                           f"{r.get('Description') or 'Credential'} committed to the repository. Removing it "
                           "from the code does not revoke it: it must be rotated.",
                           str(r.get("Match", ""))[:200], "CWE-798"))
    return out


def bandit(tb, pkg) -> tuple[list[Finding], str]:
    setup = tb.run(f"python3 -m venv /tmp/bandit && /tmp/bandit/bin/pip install -q "
                   f"--disable-pip-version-check {shlex.quote(BANDIT)}", timeout=600)
    if not setup.ok:
        return [], f"could not install {BANDIT}: {setup.output.strip()[-300:]}"
    excl = ",".join(f"./{d}" for d in EXCLUDE_DIRS)
    res = tb.run(f"/tmp/bandit/bin/bandit -r . -f json -q -x {excl} 2>/dev/null", timeout=1200)
    prefix = bridge.package_dir(pkg)
    base = "" if pkg.path == "." else pkg.path + "/"
    try:
        found = parse_bandit(res.stdout, prefix)
    except (json.JSONDecodeError, KeyError) as e:
        return [], f"bandit did not return JSON: {e}"
    for f in found:
        f.file = base + f.file.removeprefix("./")
    return found, "ok"


def gosec(tb, pkg) -> tuple[list[Finding], str]:
    res = tb.run(f"go run {GOSEC} -fmt json -quiet -exclude-dir=testdata ./... 2>/dev/null", timeout=1800)
    root = bridge.repo_root(pkg)
    try:
        return parse_gosec(res.stdout or '{"Issues": []}', root), "ok" if res.stdout.strip() else \
            "gosec produced no output"
    except (json.JSONDecodeError, KeyError) as e:
        return [], f"gosec did not return JSON: {e}"


def scan_checkout(estate, pkg, checkout: Path) -> Result:
    """Every tool that applies to the package, on ``checkout`` as it is on disk."""
    result = Result()
    found, status, meta = opengrep(estate, checkout, pkg)
    result.findings += found
    result.tools["opengrep"] = status
    result.rules = meta
    # Repo-level files (CI workflows) belong to the repo's first package, so they are scanned once.
    if pkg.repo.packages and pkg.repo.packages[0] is pkg:
        from . import workflows
        result.findings += [Finding("actions", f["rule"], f["file"], f["line"], f["severity"], f["message"],
                                    f["code"], "CWE-94" if f["rule"] == "script-injection" else "")
                            for f in workflows.scan_checkout(checkout)]
        result.tools["actions"] = "ok"
    found, status = gitleaks(estate, checkout, pkg)
    result.findings += found
    result.tools["gitleaks"] = status
    if pkg.ecosystem in ("python", "go") and pkg.image:
        with bridge.toolbox(estate, pkg, bridge.new_id("sast"), checkout) as tb:
            if pkg.ecosystem == "python":
                found, status = bandit(tb, pkg)
                result.findings += found
                result.tools["bandit"] = status
            else:
                found, status = gosec(tb, pkg)
                result.findings += found
                result.tools["gosec"] = status
    result.findings.sort(key=lambda f: (f.severity != "high", f.file, f.line))
    return result


def scan(estate, pkg, sha: str, patch: Path | None = None) -> Result:
    checkout = gitops.checkout(estate.repos_dir / f"{pkg.repo.name}.git", sha, estate.workdir / "tmp")
    try:
        if patch is not None and patch.stat().st_size:
            gitops.git("apply", str(patch), cwd=checkout)
        return scan_checkout(estate, pkg, checkout)
    finally:
        gitops.remove_checkout(checkout)


# ---------------------------------------------------------------- plans and the brief

def plans(result: Result) -> list[dict]:
    """One fix plan per rule and file, for blocking findings."""
    groups: dict[tuple, list[Finding]] = {}
    for f in result.findings:
        if f.blocking:
            groups.setdefault((f.tool, f.rule, f.file), []).append(f)
    out = []
    for (tool, rule, file), fs in groups.items():
        key = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{rule}-{file}").strip("-")[:80]
        out.append({"kind": "code", "key": key, "tool": tool, "rule": rule, "file": file,
                    "title": f"{rule} in {file} ({len(fs)} location(s))",
                    "fingerprints": [f.fingerprint for f in fs], "findings": [f.to_dict() for f in fs]})
    return out




def write_brief(pkg, sha: str, plan: dict) -> str:
    fs = plan["findings"]
    L = [f"# Fix a security finding in {pkg.id}", "",
         f"Repository {pkg.repo.url}, commit {sha[:12]}. Your working directory is the repository root.", "",
         f"{plan['tool']} rule `{plan['rule']}` flags `{plan['file']}`" + (f" ({fs[0]['cwe']})." if fs[0]["cwe"]
                                                                            else "."), "",
         fs[0]["message"], ""]
    for f in fs:
        L += [f"- line {f['line']}: `{f['code'].strip()[:200]}`"]
    if plan["tool"] == "gitleaks":
        L += ["", "This is a credential committed to the repository (the value is redacted above). Replace it "
              "with a read from configuration, the way this repository already reads its other secrets "
              "(environment variables, a settings module). If it is a throwaway test value in non-test "
              "code, move it into test setup. Never paste a real value anywhere."]
    L += ["", "## Rules", "",
          "- Fix the vulnerability itself: validate or escape the input, use the safe API, or remove the "
          "dangerous call. Keep the behaviour callers rely on.",
          "- Never add a suppression comment (nosec, nosemgrep, eslint-disable, noqa) and never rename "
          "or wrap the call just to hide it from the scanner. PatchLab re-scans, and a suppression is "
          "shown to a person as not fixed.",
          f"- If, after reading the code, you are sure this is a false positive (the input can never be "
          f"attacker-controlled), change nothing and write `FALSE_POSITIVE: <why>` to {VERDICT_PATH}. "
          "A person will decide.",
          "- Change as little as possible. Do not add or upgrade dependencies. Do not edit tests unless a "
          "test depends on the vulnerable behaviour itself.",
          "- Follow the repository's CLAUDE.md and contributing rules if it has them.",
          "- Do not commit; the change is taken from the working tree. PatchLab runs the package's full "
          "checks before and after your change, rolls it back to check, and re-scans.", ""]
    return "\n".join(L)


def suppressions_added(patch_text: str) -> list[str]:
    return [line[1:].strip()[:160] for line in patch_text.splitlines()
            if line.startswith("+") and not line.startswith("+++") and SUPPRESSION.search(line)]


def save(estate, pkg, sha: str, result: Result) -> dict:
    data = {"package": pkg.id, "commit": sha, **result.to_dict(), "plans": plans(result)}
    state.write_json(estate.state_dir / pkg.slug / "sast.json", data)
    return data
