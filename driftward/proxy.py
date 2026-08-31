"""Driftward egress proxy: records and enforces network access by host.

A threaded HTTP/HTTPS proxy bound to loopback. Every request is recorded to the
flight recorder, then allowed or denied against the policy's host list:

  * HTTPS via CONNECT: we log host:port and tunnel bytes without decrypting
    (no MITM, no certificate games) when allowed; refuse with 403 when not.
  * Plain HTTP: we log method + full URL, then proxy or refuse.

Because the Seatbelt profile pins egress to loopback, a well-behaved tool that
honors HTTP(S)_PROXY reaches the internet only through here, and anything that
tries a direct socket to a real host is blocked by Seatbelt instead. Either way
nothing leaves the machine unrecorded.

Host matching supports leading-wildcard globs like ``*.githubusercontent.com``.
Deny always wins over allow.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    for pat in patterns:
        pat = pat.lower()
        if pat == host or fnmatch.fnmatch(host, pat):
            return True
        # allow "example.com" to also match subdomains implicitly? No — explicit
        # only, to avoid surprising over-permission. Users write *.example.com.
    return False


class _Decision:
    def __init__(self, policy, cache=None):
        self.allow = list(policy.network.allow)
        self.deny = list(policy.network.deny)
        self.allow_private = bool(getattr(policy.network, "allow_private", False))
        # In 'warn' mode a would-be-denied host is recorded but let through — a
        # monitor mode for teams adopting Driftward before they tighten the list.
        self.warn_mode = policy.on_violation == "warn"
        # In 'ask' mode an unlisted host is decided by a live approval cache.
        self.ask_mode = policy.on_violation == "ask"
        self.cache = cache  # approvals.DecisionCache or None

    def verdict(self, host: str) -> str:
        # An explicit deny is firm — never overridden by warn or ask.
        if host_matches(host, self.deny):
            return "deny"
        if host_matches(host, self.allow):
            return "allow"
        # Unlisted host.
        if self.ask_mode and self.cache is not None:
            return self.cache.resolve(host)  # 'allow' or 'deny'
        if self.warn_mode:
            return "warn"
        return "deny"  # default-deny

    @staticmethod
    def passes(verdict: str) -> bool:
        """Whether traffic is allowed to flow (allow or warn)."""
        return verdict in ("allow", "warn")


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, recorder, policy, cache=None):
        self.recorder = recorder
        self.decision = _Decision(policy, cache=cache)
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def port(self) -> int:
        return self.server_address[1]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence stdlib access logging
        pass

    # ---- HTTPS tunneling ----
    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        verdict = self.server.decision.verdict(host)
        self.server.recorder.emit(
            "net.connect",
            {"host": host, "port": port, "scheme": "https", "verdict": verdict},
        )
        if not _Decision.passes(verdict):
            self._refuse(host)
            return
        try:
            upstream = _connect_upstream(host, port, self.server.decision.allow_private)
        except OSError as exc:
            self.send_error(502, f"upstream error: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._pump(self.connection, upstream)

    # ---- plain HTTP ----
    def do_GET(self):
        self._http()

    def do_POST(self):
        self._http()

    def do_PUT(self):
        self._http()

    def do_HEAD(self):
        self._http()

    def do_DELETE(self):
        self._http()

    def _http(self):
        parts = urlsplit(self.path)
        host = parts.hostname or ""
        verdict = self.server.decision.verdict(host)
        self.server.recorder.emit(
            "net.request",
            {"host": host, "method": self.command, "url": self.path, "verdict": verdict},
        )
        if not _Decision.passes(verdict):
            self._refuse(host)
            return
        # Minimal forward proxy for plain HTTP.
        port = parts.port or 80
        try:
            upstream = _connect_upstream(host, port, self.server.decision.allow_private)
        except OSError as exc:
            self.send_error(502, f"upstream error: {exc}")
            return
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        req = f"{self.command} {path} HTTP/1.0\r\n"
        for k, v in self.headers.items():
            if k.lower() in ("proxy-connection", "connection"):
                continue
            req += f"{k}: {v}\r\n"
        req += "Connection: close\r\n\r\n"
        upstream.sendall(req.encode("latin-1"))
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            upstream.sendall(self.rfile.read(length))
        # Relay the response through self.wfile (a buffered writer). Writing to
        # self.connection (the raw socket) would AttributeError — it has no
        # .write()/.flush() — and break every allowed plain-HTTP request.
        self._pump_one(upstream, self.wfile)

    def _refuse(self, host: str):
        body = (
            f"Driftward blocked egress to '{host}'. "
            "Host is not in the policy allow-list.\n"
        ).encode("utf-8")
        self.send_response(403, "Blocked by Driftward")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket):
        socks = [a, b]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 60)
                if not r:
                    break
                for s in r:
                    other = b if s is a else a
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    @staticmethod
    def _pump_one(src: socket.socket, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.write(data)
            dst.flush()
        except OSError:
            pass
        finally:
            try:
                src.close()
            except OSError:
                pass


def start_proxy(recorder, policy, cache=None) -> ProxyServer:
    server = ProxyServer(recorder, policy, cache=cache)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _address_allowed(address: str, allow_private: bool) -> bool:
    """Whether a resolved address is safe for the proxy to dial.

    Connecting to a validated IP, rather than resolving again afterward, also
    closes the DNS-rebinding/TOCTOU path to localhost and cloud metadata.
    """
    if allow_private:
        return True
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_global
    except ValueError:
        return False


def _connect_upstream(host: str, port: int, allow_private: bool = False) -> socket.socket:
    """Resolve once, reject non-public destinations, then dial the validated IP."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    last_error: OSError | None = None
    rejected = 0
    for family, socktype, proto, _, sockaddr in infos:
        if not _address_allowed(sockaddr[0], allow_private):
            rejected += 1
            continue
        upstream = socket.socket(family, socktype, proto)
        upstream.settimeout(10)
        try:
            upstream.connect(sockaddr)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    if rejected and rejected == len(infos):
        raise OSError("destination resolves only to private or non-routable addresses")
    raise last_error or OSError("no usable address for upstream host")
