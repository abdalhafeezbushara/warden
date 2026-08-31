"""Local, read-only dashboard for Warden sessions.

A dependency-free HTTP server bound to 127.0.0.1 on a fresh port. It serves
static assets from warden/dashboard/ and a small JSON API backed by the recorded
session logs. It reads only; it never mutates a session or reaches the network.

Mirrors the safety posture of the rest of Warden: loopback only, no remote
requests, no analytics, nothing leaves the machine.
"""

from __future__ import annotations

import json
import platform
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import behavior, sessions
from . import __version__, backends

ASSETS = Path(__file__).resolve().parent / "dashboard"
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            # A loopback bind alone does not stop browser DNS rebinding. Accept
            # only the hostnames Warden itself prints/uses for this exact port.
            host = (self.headers.get("Host") or "").lower()
            port = self.server.server_address[1]
            if host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
                return self._send(421, b"untrusted host", "text/plain; charset=utf-8")
            if path == "/" or path == "/index.html":
                return self._asset("index.html")
            if path.startswith("/api/"):
                return self._api(path)
            if path in ("/app.js", "/styles.css", "/favicon.svg"):
                return self._asset(path.lstrip("/"))
        except BrokenPipeError:
            return
        except Exception:  # never expose local paths or log internals to a page
            return self._json({"error": "internal error"}, 500)
        self._send(404, b"not found", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    def _asset(self, name: str):
        # Path traversal guard: only serve files that live directly in ASSETS.
        target = (ASSETS / name).resolve()
        if ASSETS not in target.parents and target != ASSETS / name:
            return self._send(403, b"forbidden", "text/plain")
        if not target.exists():
            return self._send(404, b"not found", "text/plain")
        ctype = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def _api(self, path: str):
        if path == "/api/capabilities":
            backend = backends.selected()
            return self._json({
                "version": __version__,
                "python": platform.python_version(),
                "platform": platform.system(),
                "backend": backend,
                "enforcement": backend != "none",
                "hard_egress": backend == "seatbelt",
                "strict_read": backend in ("seatbelt", "bubblewrap"),
                "deep_recording": sys.platform == "darwin",
                "behavioral_integrity": True,
            })
        if path == "/api/overview":
            overview = sessions.overview()
            overview["behavior"] = behavior.dashboard_state()
            return self._json(overview)
        if path == "/api/behavior":
            return self._json(behavior.dashboard_state())
        if path == "/api/baselines":
            return self._json(behavior.list_baselines())
        if path == "/api/sessions":
            return self._json(sessions.list_summaries())
        if path.startswith("/api/session/"):
            sid = path[len("/api/session/"):]
            # sid is a filename stem like 20260830-231719; reject anything else.
            if not sid.replace("-", "").isalnum():
                return self._json({"error": "bad session id"}, 400)
            if sid not in sessions.list_session_ids():
                return self._json({"error": "no such session"}, 404)
            summary = sessions.summarize(sid)
            manifest = behavior.build_manifest(summary)
            summary["behavior"] = manifest
            try:
                baseline = behavior.baseline_for_manifest(manifest)
                summary["behavior_diff"] = behavior.diff(manifest, baseline) if baseline else None
            except behavior.BehaviorError as exc:
                summary["behavior_diff"] = {"status": "untrusted-baseline", "error": str(exc)}
            return self._json(summary)
        return self._json({"error": "unknown endpoint"}, 404)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/"


def serve(open_browser: bool = True) -> None:
    server = DashboardServer()
    url = server.url
    print(f"Warden dashboard: {url}")
    print("Read-only and bound to this machine. Press Ctrl-C to stop.")
    if open_browser:
        try:
            webbrowser.open_new_tab(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nwarden: dashboard stopped.")
        server.shutdown()
