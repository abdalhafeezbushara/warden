"""Stdio-to-remote bridge that turns a remote MCP server into a local principal.

A remote (`url`) MCP server can't be sandboxed directly — there is no local
process. This bridge is that process: the agent speaks ordinary stdio JSON-RPC to
it, and it relays to the server's Streamable-HTTP endpoint. Run under Warden with
egress locked to exactly the declared host, the remote server gains what a stdio
server has: a confined identity, a recorded flight log, and drift.

Scope: MCP Streamable HTTP (the current transport). Client→server messages are
POSTed; a response arrives as `application/json` or a `text/event-stream`, and
server messages carried on those streams are written back to stdout. Legacy
HTTP+SSE two-endpoint servers and unsolicited server GET streams are the next
increment; they are reported honestly, not silently mishandled.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request

SESSION_HEADER = "Mcp-Session-Id"


def _sse_messages(response):
    """Yield each SSE event's `data` payload (one JSON-RPC message) from a
    streaming response, joining multi-line data and ignoring comments/other
    fields, per the text/event-stream grammar."""
    data_lines: list[str] = []
    for raw in response:
        line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
        if line == "":
            if data_lines:
                yield "\n".join(data_lines)
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        yield "\n".join(data_lines)


class _Bridge:
    def __init__(self, url: str, headers: dict | None = None, timeout: float = 300.0):
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout
        self.session_id: str | None = None
        self._initialized = False
        self._out_lock = threading.Lock()
        self._sem = threading.BoundedSemaphore(32)

    def _write(self, message: str) -> None:
        payload = (message.strip() + "\n").encode("utf-8")
        with self._out_lock:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()

    def _post(self, body: bytes):
        request = urllib.request.Request(self.url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
        for name, value in self.headers.items():
            request.add_header(name, value)
        if self.session_id:
            request.add_header(SESSION_HEADER, self.session_id)
        return urllib.request.urlopen(request, timeout=self.timeout)

    def _error_reply(self, request_id, message: str) -> None:
        # Speak JSON-RPC back to the agent instead of dying silently, so a blocked
        # or failed endpoint surfaces as a tool error, not a hang.
        if request_id is None:
            return
        self._write(json.dumps({
            "jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32001, "message": f"warden bridge: {message}"}}))

    def _handle(self, line: str) -> None:
        try:
            request_id = None
            try:
                request_id = json.loads(line).get("id")
            except (ValueError, AttributeError):
                pass
            try:
                response = self._post(line.encode("utf-8"))
            except urllib.error.HTTPError as exc:
                self._error_reply(request_id, f"HTTP {exc.code} from endpoint")
                return
            except (urllib.error.URLError, OSError) as exc:
                self._error_reply(request_id, f"cannot reach endpoint ({exc})")
                return
            with response:
                new_session = response.headers.get(SESSION_HEADER)
                if new_session:
                    self.session_id = new_session
                content_type = (response.headers.get("Content-Type") or "").lower()
                if "text/event-stream" in content_type:
                    for message in _sse_messages(response):
                        self._write(message)
                else:
                    body = response.read().decode("utf-8", "replace").strip()
                    if body:
                        self._write(body)
        except Exception:  # never let one message kill the bridge
            pass

    def _handle_async(self, line: str) -> None:
        try:
            self._handle(line)
        finally:
            self._sem.release()

    def run(self) -> int:
        threads: list[threading.Thread] = []
        for raw in sys.stdin.buffer:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            method = None
            try:
                method = json.loads(line).get("method")
            except (ValueError, AttributeError):
                pass
            # Establish the session synchronously (the `initialize` handshake must
            # complete before dependent requests, which otherwise race it). Once
            # initialized, relay concurrently so tool calls don't serialize.
            if not self._initialized:
                self._handle(line)
                if method == "initialize":
                    self._initialized = True
                continue
            self._sem.acquire()
            thread = threading.Thread(target=self._handle_async, args=(line,), daemon=True)
            thread.start()
            threads.append(thread)
            threads = [t for t in threads if t.is_alive()]
        for thread in threads:
            thread.join(timeout=self.timeout)
        return 0


def _bridge_sse(url: str, headers: dict, timeout: float) -> int:
    """Legacy two-endpoint HTTP+SSE transport: a long-lived GET stream carries
    server→client messages (its first `endpoint` event names the POST URL for
    client→server messages)."""
    from urllib.parse import urljoin

    out_lock = threading.Lock()
    post_url = {"value": None}
    ready = threading.Event()
    pending: set = set()
    pending_lock = threading.Lock()
    drained = threading.Event()
    drained.set()

    def write(message: str) -> None:
        with out_lock:
            sys.stdout.buffer.write((message.strip() + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
        # A response clears its request id; when none are outstanding, an exiting
        # bridge may stop waiting.
        try:
            rid = json.loads(message).get("id")
        except (ValueError, AttributeError):
            rid = None
        if rid is not None:
            with pending_lock:
                pending.discard(rid)
                if not pending:
                    drained.set()

    get = urllib.request.Request(url, method="GET")
    get.add_header("Accept", "text/event-stream")
    for name, value in headers.items():
        get.add_header(name, value)
    stream = urllib.request.urlopen(get, timeout=timeout)

    def reader() -> None:
        event, data_lines = "message", []
        for raw in stream:
            line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
            if line == "":
                if data_lines:
                    data = "\n".join(data_lines)
                    if event == "endpoint":
                        post_url["value"] = urljoin(url, data)
                        ready.set()
                    else:
                        write(data)
                event, data_lines = "message", []
                continue
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())

    threading.Thread(target=reader, name="warden-mcp-sse", daemon=True).start()
    if not ready.wait(timeout=timeout) or not post_url["value"]:
        raise RuntimeError("remote server did not announce an SSE endpoint "
                           "(is it Streamable HTTP? drop transport=sse)")

    def post(body: bytes) -> None:
        request = urllib.request.Request(post_url["value"], data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        for name, value in headers.items():
            request.add_header(name, value)
        urllib.request.urlopen(request, timeout=timeout).read()

    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            continue
        try:
            rid = json.loads(line).get("id")
        except (ValueError, AttributeError):
            rid = None
        if rid is not None:
            with pending_lock:
                pending.add(rid)
                drained.clear()
        try:
            post(line.encode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            print(f"warden mcp bridge: POST failed: {exc}", file=sys.stderr)
    # stdin closed — let responses still in flight on the SSE stream arrive.
    drained.wait(timeout=min(timeout, 30.0))
    return 0


def bridge(url: str, headers: dict | None = None, timeout: float = 300.0,
           transport: str = "streamable-http") -> int:
    if transport == "sse":
        return _bridge_sse(url, headers or {}, timeout)
    return _Bridge(url, headers, timeout).run()
