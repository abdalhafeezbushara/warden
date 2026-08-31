"""Local, read-only dashboard for Warden sessions.

A dependency-free HTTP server bound to 127.0.0.1 on a fresh port. It serves
static assets from warden/dashboard/ and a small JSON API backed by the recorded
session logs. It reads only; it never mutates a session or reaches the network.

Mirrors the safety posture of the rest of Warden: loopback only, no remote
requests, no analytics, nothing leaves the machine.
"""

from __future__ import annotations

import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import sessions

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
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/" or path == "/index.html":
                return self._asset("index.html")
            if path.startswith("/api/"):
                return self._api(path)
            if path in ("/app.js", "/styles.css", "/favicon.svg"):
                return self._asset(path.lstrip("/"))
        except BrokenPipeError:
            return
        except Exception as exc:  # never leak internals
            return self._json({"error": "internal error", "detail": str(exc)[:200]}, 500)
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
        if path == "/api/overview":
            return self._json(sessions.overview())
        if path == "/api/sessions":
            return self._json(sessions.list_summaries())
        if path.startswith("/api/session/"):
            sid = path[len("/api/session/"):]
            # sid is a filename stem like 20260830-231719; reject anything else.
            if not sid.replace("-", "").isalnum():
                return self._json({"error": "bad session id"}, 400)
            if sid not in sessions.list_session_ids():
                return self._json({"error": "no such session"}, 404)
            return self._json(sessions.summarize(sid))
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
