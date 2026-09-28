"""HTTP server for the PatchLab Internal front end (standard library only).

Security model: the front end can start runs that clone production systems
using the credentials of the user who started it, so
  * it listens on 127.0.0.1 unless --allow-remote is given;
  * every request needs a per-session token (printed at start-up and
    exchanged for an HttpOnly, SameSite=Strict cookie);
  * state-changing requests also need an X-PatchLabInternal-Request header, which
    cross-site pages cannot send without a CORS preflight we never allow;
  * the Host header must name this server (defeats DNS rebinding);
  * pages ship with a strict Content-Security-Policy and no inline script.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import os
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from patchlab_internal import __version__ as core_version
from patchlab_internal import config as core_config
from patchlab_internal import settings as core_settings

from . import __version__, store
from .runs import Busy, RunManager, child_env

STATIC = Path(__file__).resolve().parent / "static"
COOKIE = "patchlab_internal_token"
PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
# Reports are generated HTML with inline styles and no scripts.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"
TOOLS = [("docker", "Linux container targets"), ("pwsh", "PowerShell 7 (vSphere, local, tests)"),
         ("powershell", "Windows PowerShell (Hyper-V)"), ("aws", "AWS clones"), ("az", "Azure clones"),
         ("gcloud", "Google Cloud clones"), ("oci", "Oracle Cloud clones")]


class HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class App:
    def __init__(self, s: core_settings.Settings, token: str, allowed_hosts: set[str] | None,
                 runs: RunManager | None = None):
        self.settings = s
        self.reports = s.reports_path().resolve()
        self.configs = s.configs_path().resolve()
        self.reports.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.allowed_hosts = allowed_hosts        # None = any (remote mode)
        self.runs = runs or RunManager(self.reports, self.configs, s.web.max_parallel_runs)

    # ---------------------------------------------------------------- API handlers
    def session(self, h, q):
        return {"version": __version__, "core_version": core_version, "reports_dir": str(self.reports),
                "configs_dir": str(self.configs), "settings_file": str(core_settings.settings_path()),
                "max_parallel_runs": self.runs.max_parallel}

    def runs_list(self, h, q):
        active = {j.run_id: j for j in self.runs.active()}
        out = store.list_runs(self.reports)
        for r in out:
            job = self.runs.get(r["run_id"])
            r["job"] = job.to_dict() if job else None
            r["active"] = r["run_id"] in active
        return {"runs": out}

    def run_detail(self, h, q, run_id):
        try:
            data = store.load_run(self.reports, run_id)
        except store.NotFound:
            raise HTTPError(404, "no such run") from None
        job = self.runs.get(run_id)
        data["job"] = job.to_dict() if job else None
        data["active"] = bool(job and job.status in ("running", "cancelling"))
        return data

    def run_console(self, h, q, run_id):
        try:
            text, offset = store.read_console(self.reports, run_id, int(q.get("offset", ["0"])[0]))
        except (store.NotFound, ValueError):
            raise HTTPError(404, "no such run") from None
        job = self.runs.get(run_id)
        return {"text": text, "offset": offset,
                "active": bool(job and job.status in ("running", "cancelling"))}

    def run_start(self, h, q, body):
        rel = str(body.get("config") or "")
        try:
            path = store.inside(self.configs, rel)
        except store.NotFound:
            raise HTTPError(400, "config must be inside the configs folder") from None
        if not path.is_file():
            raise HTTPError(400, f"config not found: {rel}")
        try:
            cfg = core_config.load(path)
        except core_config.ConfigError as e:
            raise HTTPError(400, f"config is not valid: {e}") from None
        patch = (body.get("patch") or "").strip() or None
        if patch:
            kind = patch.partition(":")[0]
            if kind not in core_config.PLATFORMS[cfg.sandbox.platform][1]:
                raise HTTPError(400, f"patch kind '{kind}' is not valid for {cfg.sandbox.platform}")
        elif not cfg.patch:
            raise HTTPError(400, "this config has no [patch] table: choose a patch")
        images = [i for i in body.get("images") or [] if i in cfg.sandbox.images]
        extra_env = {}
        if body.get("guest_password"):
            # Handed to that run's process only; never stored or logged.
            extra_env["PATCHLAB_INTERNAL_GUEST_PASSWORD"] = str(body["guest_password"])
        try:
            job = self.runs.start(path, patch, images, bool(body.get("verify_rollback")),
                                  bool(body.get("keep_on_failure")), bool(body.get("fail_on_warn")), extra_env)
        except Busy as e:
            raise HTTPError(409, str(e)) from None
        return {"run_id": job.run_id, "job": job.to_dict()}

    def run_cancel(self, h, q, body, run_id):
        if not self.runs.cancel(run_id):
            raise HTTPError(409, "that run is not in progress")
        return {"ok": True}

    def run_delete(self, h, q, run_id):
        job = self.runs.get(run_id)
        if job and job.status in ("running", "cancelling"):
            raise HTTPError(409, "cancel the run before deleting it")
        try:
            d = store.run_dir(self.reports, run_id)
        except store.NotFound:
            raise HTTPError(404, "no such run") from None
        shutil.rmtree(d)
        return {"ok": True}

    def configs_list(self, h, q):
        return {"configs": store.list_configs(self.configs), "root": str(self.configs)}

    def config_detail(self, h, q):
        rel = q.get("path", [""])[0]
        try:
            path = store.inside(self.configs, rel)
        except store.NotFound:
            raise HTTPError(404, "no such config") from None
        if not path.is_file() or path.suffix != ".toml":
            raise HTTPError(404, "no such config")
        info = store.describe_config(self.configs, path) or {"path": rel, "valid": False,
                                                              "error": "include file (shared checks), not a runnable config"}
        info["text"] = path.read_text(encoding="utf-8", errors="replace")
        return info

    def gc(self, h, q, body):
        # gc removes every PatchLab Internal sandbox of the provider, so it must not run
        # while a run is using one.
        if self.runs.active():
            raise HTTPError(409, "wait for the runs in progress to finish before cleaning up; "
                                 "clean-up would remove their sandboxes too")
        rel = str(body.get("config") or "")
        try:
            path = store.inside(self.configs, rel)
        except store.NotFound:
            raise HTTPError(400, "config must be inside the configs folder") from None
        proc = subprocess.run([*self.runs.command, "gc", "--config", str(path)], capture_output=True, text=True,
                              timeout=3600, cwd=self.configs, env=child_env())
        return {"exit_code": proc.returncode, "output": (proc.stdout + proc.stderr).strip()}

    def environment(self, h, q):
        tools = [{"name": n, "purpose": p, "path": shutil.which(n)} for n, p in TOOLS]
        return {"python": sys.version.split()[0], "platform": sys.platform, "tools": tools,
                "secrets": {k: bool(os.environ.get(k)) for k in
                            ("PATCHLAB_INTERNAL_GUEST_PASSWORD", "PATCHLAB_INTERNAL_VCENTER_USER", "PATCHLAB_INTERNAL_VCENTER_PASSWORD")}}

    # ---------------------------------------------------------------- routing
    def route(self, h: "Handler") -> None:
        url = urllib.parse.urlsplit(h.path)
        path, q = url.path, urllib.parse.parse_qs(url.query)
        method = h.command

        if not self.host_ok(h.headers.get("Host", "")):
            raise HTTPError(421, "unexpected Host header")

        if method == "GET" and path == "/":
            token = q.get("token", [None])[0]
            if token and hmac.compare_digest(token, self.token):
                # Swap the URL token for a cookie and drop it from the address bar.
                h.send_response(303)
                h.send_header("Location", "/")
                h.send_header("Set-Cookie", f"{COOKIE}={self.token}; HttpOnly; SameSite=Strict; Path=/")
                h.send_header("Content-Length", "0")
                h.end_headers()
                return
            return h.send_file(STATIC / "index.html", csp=PAGE_CSP)
        if method == "GET" and path.startswith("/static/"):
            try:
                return h.send_file(store.inside(STATIC, path[len("/static/"):]), csp=PAGE_CSP)
            except store.NotFound:
                raise HTTPError(404, "not found") from None

        if not self.authorised(h):
            raise HTTPError(401, "open the link printed by `patchlab-internal web` (it carries your access token)")

        if path.startswith("/files/"):
            run_id, _, rel = path[len("/files/"):].partition("/")
            try:
                f = store.inside(store.run_dir(self.reports, run_id), urllib.parse.unquote(rel))
            except store.NotFound:
                raise HTTPError(404, "not found") from None
            if not f.is_file():
                raise HTTPError(404, "not found")
            return h.send_file(f, csp=REPORT_CSP, text_logs=True)

        if not path.startswith("/api/"):
            raise HTTPError(404, "not found")
        parts = path[len("/api/"):].strip("/").split("/")

        if method in ("POST", "DELETE"):
            if h.headers.get("X-PatchLabInternal-Request") != "1":
                raise HTTPError(403, "missing X-PatchLabInternal-Request header")
        body = h.read_json() if method == "POST" else {}

        match (method, parts):
            case ("GET", ["session"]):
                return h.send_json(self.session(h, q))
            case ("GET", ["runs"]):
                return h.send_json(self.runs_list(h, q))
            case ("POST", ["runs"]):
                return h.send_json(self.run_start(h, q, body), 201)
            case ("GET", ["runs", run_id]):
                return h.send_json(self.run_detail(h, q, run_id))
            case ("GET", ["runs", run_id, "console"]):
                return h.send_json(self.run_console(h, q, run_id))
            case ("POST", ["runs", run_id, "cancel"]):
                return h.send_json(self.run_cancel(h, q, body, run_id))
            case ("DELETE", ["runs", run_id]):
                return h.send_json(self.run_delete(h, q, run_id))
            case ("GET", ["configs"]):
                return h.send_json(self.configs_list(h, q))
            case ("GET", ["config"]):
                return h.send_json(self.config_detail(h, q))
            case ("POST", ["gc"]):
                return h.send_json(self.gc(h, q, body))
            case ("GET", ["environment"]):
                return h.send_json(self.environment(h, q))
        raise HTTPError(404, "not found")

    def authorised(self, h) -> bool:
        cookie = SimpleCookie(h.headers.get("Cookie", ""))
        value = cookie[COOKIE].value if COOKIE in cookie else ""
        header = h.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            value = value or header[7:]
        return bool(value) and hmac.compare_digest(value, self.token)

    def host_ok(self, host: str) -> bool:
        if self.allowed_hosts is None:
            return True
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name.lower() in self.allowed_hosts


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchLab Internal"
    sys_version = ""
    app: App = None   # set on the subclass created by make_server

    def log_message(self, fmt, *args):
        if os.environ.get("PATCHLAB_INTERNAL_WEB_ACCESS_LOG"):
            super().log_message(fmt, *args)

    def _handle(self):
        try:
            self.app.route(self)
        except HTTPError as e:
            self.send_json({"error": str(e)}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # keep the server up; report the failure to the page
            self.send_json({"error": f"{type(e).__name__}: {e}"}, 500)

    do_GET = do_POST = do_DELETE = _handle

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise HTTPError(413, "request too large")
        if not length:
            return {}
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise HTTPError(415, "expected application/json")
        try:
            data = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            raise HTTPError(400, "invalid JSON") from None
        if not isinstance(data, dict):
            raise HTTPError(400, "expected a JSON object")
        return data

    def _common_headers(self, csp: str) -> None:
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def send_json(self, data, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers("default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path, csp: str, text_logs: bool = False) -> None:
        if not path.is_file():
            raise HTTPError(404, "not found")
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if text_logs and (path.suffix in (".log", ".md", ".patch", ".txt") or ctype == "application/octet-stream"):
            ctype = "text/plain"
        if ctype.startswith("text/") or ctype in ("application/json", "application/javascript"):
            ctype += "; charset=utf-8"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._common_headers(csp)
        self.end_headers()
        self.wfile.write(data)


def allowed_hosts_for(host: str, port: int) -> set[str] | None:
    names = {"127.0.0.1", "localhost", "[::1]"}
    if host in ("0.0.0.0", "::"):
        return None
    names.add(host.lower() if ":" not in host else f"[{host.lower()}]")
    return names


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(s: core_settings.Settings, host: str, port: int, token: str | None = None,
                runs: RunManager | None = None) -> tuple[ThreadingHTTPServer, App]:
    token = token or os.environ.get("PATCHLAB_INTERNAL_WEB_TOKEN") or secrets.token_urlsafe(24)
    app = App(s, token, allowed_hosts_for(host, port), runs)
    handler = type("PatchLabInternalHandler", (Handler,), {"app": app})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd, app


def serve(s: core_settings.Settings, host: str | None = None, port: int | None = None,
          open_browser: bool = False, allow_remote: bool = False) -> int:
    host = host or s.web.host
    port = port if port is not None else s.web.port
    if not is_loopback(host) and not allow_remote:
        print(f"error: refusing to listen on {host}: the front end can start runs with your cloud "
              "credentials. Use 127.0.0.1 (and an SSH tunnel), or pass --allow-remote.", file=sys.stderr)
        return 64
    httpd, app = make_server(s, host, port)
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{shown}:{httpd.server_address[1]}/?token={app.token}"
    print(f"PatchLab Internal front end {__version__} (core {core_version})")
    print(f"  reports: {app.reports}\n  configs: {app.configs}")
    print(f"\n  open: {url}\n\nPress Ctrl-C to stop (active runs are cancelled and cleaned up first).")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
        if app.runs.active():
            print(f"cancelling {len(app.runs.active())} active run(s); waiting for their clean-up...")
        app.runs.shutdown()
    finally:
        httpd.server_close()
    return 0


__all__ = ["App", "make_server", "serve"]
