"""Authenticated parent-side launcher for wrapped stdio MCP servers.

The untrusted agent receives a loopback endpoint and a random bearer token, but
the broker accepts only exact server definitions snapshotted before the agent
started. It cannot be used as a general process-launch escape hatch.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Callable

from .mcp import McpServer


BROKER_ENV = "DRIFTWARD_MCP_BROKER"
TOKEN_ENV = "DRIFTWARD_MCP_TOKEN"
MAX_HANDSHAKE = 64 * 1024


def _source_key(value: str) -> str:
    return str(Path(value).expanduser().resolve())


def _recv_line(conn: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= MAX_HANDSHAKE:
        # Read the short handshake one byte at a time so a fast MCP server's
        # first stdout frame can never be consumed as line-buffer remainder.
        chunk = conn.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            return bytes(data)
        data.extend(chunk)
    raise ValueError("invalid or oversized MCP broker handshake")


def _reply(conn: socket.socket, *, ok: bool, error: str | None = None) -> None:
    payload = {"ok": ok}
    if error:
        payload["error"] = error
    conn.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")


class McpBroker:
    """One-run broker with an immutable definition allow-list."""

    def __init__(self, servers: list[McpServer], *, recorder=None,
                 command_factory: Callable[[McpServer, Path], list[str]] | None = None):
        self._registrations = {
            (_source_key(server.source), server.name, server.definition_sha256): server
            for server in servers if server.wrapped_valid
        }
        self.recorder = recorder
        self.token = secrets.token_urlsafe(32)
        self._command_factory = command_factory
        self._stop = threading.Event()
        self._processes: set[subprocess.Popen] = set()
        self._process_lock = threading.Lock()
        self._client_threads: set[threading.Thread] = set()
        self._client_lock = threading.Lock()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.25)
        self.port = int(self._listener.getsockname()[1])
        self.address = f"127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._serve, name="driftward-mcp-broker", daemon=True)

    @property
    def registration_count(self) -> int:
        return len(self._registrations)

    def start(self) -> "McpBroker":
        self._thread.start()
        if self.recorder:
            self.recorder.emit("mcp.broker.started", {
                "port": self.port, "registrations": self.registration_count,
            })
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(conn,),
                                      name="driftward-mcp-client", daemon=True)
            with self._client_lock:
                self._client_threads.add(thread)
            thread.start()

    def _grant_file(self, server: McpServer) -> Path:
        from .runner import _driftward_home

        directory = _driftward_home() / "mcp-grants"
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        fd, name = tempfile.mkstemp(prefix="grant-", suffix=".json", dir=str(directory))
        try:
            os.fchmod(fd, 0o600)
            payload = json.dumps(server.to_grant(), separators=(",", ":")).encode("utf-8")
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        return Path(name)

    def _inner_command(self, server: McpServer, grant: Path) -> list[str]:
        if self._command_factory:
            return self._command_factory(server, grant)
        return [sys.executable, "-m", "driftward", "mcp", "_serve", "--grant", str(grant)]

    def _handle(self, conn: socket.socket) -> None:
        grant = None
        proc = None
        approved = False
        try:
            conn.settimeout(5)
            request = json.loads(_recv_line(conn).decode("utf-8"))
            supplied = str(request.get("token") or "")
            if not hmac.compare_digest(supplied, self.token):
                raise PermissionError("MCP broker authentication failed")
            key = (
                _source_key(str(request.get("source") or "")),
                str(request.get("name") or ""),
                str(request.get("definition") or ""),
            )
            server = self._registrations.get(key)
            if server is None:
                raise PermissionError("MCP definition was not registered before the agent started")
            with self._process_lock:
                active = sum(1 for item in self._processes if item.poll() is None)
            if active >= 16:
                raise PermissionError("MCP broker process limit reached")

            grant = self._grant_file(server)
            command = self._inner_command(server, grant)
            # Approval precedes process startup so no server stdout can race the
            # line-oriented handshake. The shim sends no MCP bytes until this.
            _reply(conn, ok=True)
            approved = True
            conn.settimeout(None)
            proc = subprocess.Popen(command, stdin=conn, stdout=conn, start_new_session=True)
            with self._process_lock:
                self._processes.add(proc)
            if self.recorder:
                self.recorder.emit("mcp.broker.launch", {
                    "name": server.name,
                    "definition_sha256": server.definition_sha256,
                })
            proc.wait()
        except (ValueError, KeyError, TypeError, json.JSONDecodeError,
                PermissionError, OSError) as exc:
            if not approved:
                try:
                    _reply(conn, ok=False, error=str(exc))
                except OSError:
                    pass
            if self.recorder:
                self.recorder.emit("mcp.broker.denied", {"reason": str(exc)})
        finally:
            if proc is not None:
                with self._process_lock:
                    self._processes.discard(proc)
            if grant is not None:
                try:
                    grant.unlink()
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass
            with self._client_lock:
                self._client_threads.discard(threading.current_thread())

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._process_lock:
            processes = list(self._processes)
        for proc in processes:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except OSError:
                    pass
        for proc in processes:
            try:
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        self._thread.join(timeout=1)
        # Recorder events must never arrive after the caller seals the parent
        # session. Handshakes have a five-second timeout, so this is bounded.
        with self._client_lock:
            clients = list(self._client_threads)
        for thread in clients:
            thread.join(timeout=6)
        if self.recorder:
            self.recorder.emit("mcp.broker.stopped", {})


def start_for_configs(configs: list[str] | None = None, *, recorder=None) -> McpBroker | None:
    """Snapshot wrapped definitions from standard and explicitly supplied configs."""
    from . import mcp

    servers = mcp.configured(None, deduplicate=False)
    standard = {str(path.expanduser().resolve()) for path in mcp.discovery_paths()}
    for raw in configs or []:
        candidate = Path(raw).expanduser()
        if str(candidate.resolve()) not in standard:
            servers.extend(mcp.configured([candidate], deduplicate=False))
    eligible = [server for server in servers if server.wrapped_valid]
    if not eligible:
        return None
    return McpBroker(eligible, recorder=recorder).start()


def run_shim(name: str, source: str, definition: str) -> int:
    """Bridge this process's stdio to the parent broker."""
    address = os.environ.get(BROKER_ENV)
    token = os.environ.get(TOKEN_ENV)
    if not address or not token:
        raise RuntimeError(
            "no parent MCP broker is available; run the agent through `driftward run` "
            "or launch this server with `driftward mcp run`")
    host, separator, raw_port = address.rpartition(":")
    if not separator or host not in ("127.0.0.1", "localhost"):
        raise RuntimeError("invalid Driftward MCP broker address")
    conn = socket.create_connection(("127.0.0.1", int(raw_port)), timeout=5)
    request = {
        "token": token, "name": name, "source": _source_key(source),
        "definition": definition,
    }
    conn.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
    response = json.loads(_recv_line(conn).decode("utf-8"))
    if not response.get("ok"):
        conn.close()
        raise RuntimeError(str(response.get("error") or "MCP broker refused the launch"))
    conn.settimeout(None)

    def upload() -> None:
        try:
            while True:
                chunk = sys.stdin.buffer.read(64 * 1024)
                if not chunk:
                    break
                conn.sendall(chunk)
            conn.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, OSError):
            pass

    thread = threading.Thread(target=upload, name="driftward-mcp-stdin", daemon=True)
    thread.start()
    try:
        while True:
            chunk = conn.recv(64 * 1024)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    finally:
        conn.close()
    return 0
