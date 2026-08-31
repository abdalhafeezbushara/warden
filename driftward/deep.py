"""Comprehensive behavioral recording via macOS Endpoint Security (`eslogger`).

Driftward's egress proxy records the network completely — and it has to, because
Endpoint Security has NO network-connect event (only UNIX-domain sockets); real
IP telemetry needs a Network Extension. So the two are complementary: the proxy
owns the network, and this module owns the *filesystem and process* story that
Seatbelt only enforces but cannot record — every file opened, every process
executed, every file created by the agent's process subtree.

Architecture (so the hard logic is testable without root):
  * ``parse_event``   — pure function: one raw eslogger JSON object → a normalized
    event, using the exact ES field paths (process.audit_token.pid, etc.).
  * ``SubtreeTracker`` — keeps the set of (pid, pidversion) belonging to the
    monitored child's process subtree, seeded from the child pid and grown via
    fork/exec parent links. eslogger has no pid filter, so we filter here.
  * ``DeepRecorder``  — consumes a line iterator (live or replayed), keeps only
    subtree events, and emits them into the signed session log.

Live capture (``sudo eslogger --format json exec fork open create``) requires the
terminal to have **Full Disk Access** (a one-time System Settings grant; TCC will
not let code grant it). The parser and tracker are fully unit-tested against
synthetic JSONL matching the real schema; only the subprocess plumbing is live-only.

Reference: Apple eslogger(1); ES field layout cross-checked against open-source
ES parsers. ES explicitly warns the JSON is not a stable API — so parse tolerantly.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field

# Default event set: moderate-volume, high-signal. `open` and `write` are
# firehoses; `open` is opt-in (see DEEP_FILE_EVENTS), `write` is never default.
# `exit` is always included so the subtree tracker can prune exited pids and not
# mis-attribute a later process that reuses the same pid.
DEEP_EVENTS = ["exec", "fork", "exit", "create", "uipc_connect"]
DEEP_FILE_EVENTS = DEEP_EVENTS + ["open"]


def _dig(d: dict, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _pid(token: dict | None) -> int | None:
    if not isinstance(token, dict):
        return None
    return token.get("pid")


def parse_event(raw: dict) -> dict | None:
    """Normalize one raw eslogger event. Returns None for events we ignore.

    Normalized shape:
      {kind, pid, pidversion, ppid, actor, ... event-specific fields}
    where `pid`/`pidversion` identify the process that the subtree tracker keys
    on (for exec/fork this is the NEW/child process so the tree grows correctly).
    """
    ev = raw.get("event")
    if not isinstance(ev, dict) or not ev:
        return None
    kind = next(iter(ev), None)
    body = ev.get(kind) or {}
    proc = raw.get("process") or {}
    actor_pid = _pid(proc.get("audit_token"))
    actor_pidversion = _dig(proc, "audit_token", "pidversion")
    actor_path = _dig(proc, "executable", "path")
    ts = raw.get("time")

    if kind == "exec":
        target = body.get("target") or {}
        return {
            "kind": "proc.exec",
            "pid": _pid(target.get("audit_token")),
            "pidversion": _dig(target, "audit_token", "pidversion"),
            "ppid": _pid(target.get("parent_audit_token")) or target.get("ppid"),
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": _dig(target, "executable", "path"),
            "args": body.get("args"),
            "ts": ts,
        }
    if kind == "fork":
        child = body.get("child") or {}
        return {
            "kind": "proc.fork",
            "pid": _pid(child.get("audit_token")),
            "pidversion": _dig(child, "audit_token", "pidversion"),
            "ppid": actor_pid,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": _dig(child, "executable", "path"),
            "ts": ts,
        }
    if kind == "exit":
        return {
            "kind": "proc.exit",
            "pid": actor_pid,
            "pidversion": actor_pidversion,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "ts": ts,
        }
    if kind == "open":
        return {
            "kind": "fs.open",
            "pid": actor_pid,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": _dig(body, "file", "path"),
            "actor_path": actor_path,
            "ts": ts,
        }
    if kind == "create":
        dest = body.get("destination") or {}
        if "existing_file" in dest:
            path = _dig(dest, "existing_file", "path")
        else:
            d = _dig(dest, "new_path", "dir", "path")
            name = _dig(dest, "new_path", "filename")
            path = f"{d}/{name}" if d and name else (d or name)
        return {
            "kind": "fs.create",
            "pid": actor_pid,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": path,
            "actor_path": actor_path,
            "ts": ts,
        }
    if kind == "write":
        return {
            "kind": "fs.write",
            "pid": actor_pid,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": _dig(body, "target", "path"),
            "actor_path": actor_path,
            "ts": ts,
        }
    if kind == "uipc_connect":
        return {
            "kind": "ipc.connect",
            "pid": actor_pid,
            "actor_pid": actor_pid,
            "actor_pidversion": actor_pidversion,
            "path": _dig(body, "file", "path"),
            "ts": ts,
        }
    return None


@dataclass
class SubtreeTracker:
    """Track the process *instances* belonging to the monitored child's subtree.

    Descendants are keyed on the ``(pid, pidversion)`` pair from the ES audit
    token, which uniquely identifies a process instance — so a later, unrelated
    process that *reuses* a pid (different pidversion) is not mistaken for the
    agent. The root is matched by bare pid because it is Driftward's own child and
    stays alive for the whole session (its pid cannot be reused meanwhile). Exit
    events prune membership so a freed pid can't be inherited by a stranger.
    """
    root_pid: int
    members: set = field(default_factory=set)  # {(pid, pidversion)}

    def __post_init__(self):
        self.members = set()

    def _is_member(self, pid, pidversion) -> bool:
        if pid is None:
            return False
        if pid == self.root_pid:  # root: alive all session, safe to match by pid
            return True
        return (pid, pidversion) in self.members

    def observe(self, event: dict) -> bool:
        """Update membership from a normalized event; return True if in-subtree."""
        kind = event.get("kind")
        actor = event.get("actor_pid")
        actor_ver = event.get("actor_pidversion")

        if kind == "proc.exit":
            self.members.discard((event.get("pid"), event.get("pidversion")))
            return self._is_member(actor, actor_ver)

        if kind in ("proc.exec", "proc.fork"):
            # The new process joins iff the process that spawned it is tracked.
            if self._is_member(actor, actor_ver):
                pid, ver = event.get("pid"), event.get("pidversion")
                if pid is not None:
                    self.members.add((pid, ver))
                return True
            return False

        # Non-spawn event: in-subtree iff the acting instance is tracked.
        return self._is_member(actor, actor_ver)

    @property
    def pids(self) -> set:
        """Distinct pids currently tracked (root + live descendants)."""
        return {self.root_pid} | {p for p, _ in self.members}


class DeepRecorder:
    """Consume normalized eslogger events, filter to the subtree, emit to the log."""

    def __init__(self, recorder, root_pid: int):
        self.recorder = recorder
        self.tracker = SubtreeTracker(root_pid)
        self.counts: dict[str, int] = {}

    def feed_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            raw = json.loads(line)
        except (ValueError, TypeError):
            return
        self.feed_raw(raw)

    def feed_raw(self, raw: dict) -> None:
        ev = parse_event(raw)
        if not ev:
            return
        in_subtree = self.tracker.observe(ev)
        if not in_subtree or ev["kind"] == "proc.exit":
            return  # exits update the tracker but aren't recorded as activity
        kind = ev["kind"]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        # Record a compact form (drop the raw pidversion noise from the log).
        self.recorder.emit(kind, {k: ev[k] for k in ev
                                  if k in ("pid", "path", "args", "actor_path") and ev[k] is not None})

    def summary(self) -> dict:
        return {"events": dict(self.counts), "tracked_pids": len(self.tracker.pids)}


class DeepStream:
    """Capture eslogger events starting BEFORE the child launches, so the child's
    very first fork/exec (which happen while eslogger is still ~1s from ready if
    started after) are not missed. Raw lines are buffered until the child's pid
    is known via attach(); then the buffer is replayed through a DeepRecorder
    (whose subtree tracker keeps only the child's events) and live lines follow.

    Only the LiveCapture subprocess is live-only (needs sudo + Full Disk Access);
    the buffer/attach logic is unit-tested.
    """

    MAX_BUFFER = 20000  # cap so the pre-attach window can't grow unbounded

    def __init__(self, recorder, events: list[str]):
        import threading

        self.recorder = recorder
        self.events = events
        self._lock = threading.Lock()
        self._buffer: list[str] = []
        self._dr: DeepRecorder | None = None
        self._stop = threading.Event()
        self._capture = None
        self._thread = None
        self.reason: str | None = None

    def start(self) -> bool:
        import threading

        if not eslogger_available():
            return False
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        return True

    def _reader(self):
        try:
            self._capture = LiveCapture(self.events)
            for line in self._capture.lines():
                if self._stop.is_set():
                    break
                self._ingest(line)
        except Exception as exc:  # FDA denied, sudo failed — non-fatal
            self.reason = str(exc)[:200]

    def _ingest(self, line: str):
        with self._lock:
            if self._dr is None:
                if len(self._buffer) < self.MAX_BUFFER:
                    self._buffer.append(line)
            else:
                self._dr.feed_line(line)

    def attach(self, root_pid: int):
        """Child pid is now known: create the recorder, replay the buffered
        pre-launch window, then feed live lines through it."""
        with self._lock:
            self._dr = DeepRecorder(self.recorder, root_pid)
            for line in self._buffer:
                self._dr.feed_line(line)
            self._buffer.clear()

    def finish(self) -> dict:
        self._stop.set()
        if self._capture:
            self.reason = self._capture.stop()
        summary = self._dr.summary() if self._dr else {"events": {}, "tracked_pids": 0}
        summary["buffered_replayed"] = self._dr is not None
        return summary


def eslogger_available() -> bool:
    return shutil.which("eslogger") is not None


def live_command(events: list[str]) -> list[str]:
    """The command to stream ES events. Requires sudo + Full Disk Access."""
    return ["sudo", "eslogger", "--format", "json", *events]


FDA_HINT = ("eslogger needs Full Disk Access. Grant it to your terminal in "
            "System Settings > Privacy & Security > Full Disk Access, then re-run.")


def interpret_stderr(text: str) -> str:
    """Turn an eslogger failure into an actionable message."""
    t = (text or "").lower()
    if "not permitted" in t or "full disk access" in t or "es_new_client" in t:
        return FDA_HINT
    if "sudo" in t and ("password" in t or "askpass" in t):
        return "eslogger needs sudo; run with cached credentials (sudo -v) or as root."
    return (text or "eslogger produced no output").strip()[:200]


class LiveCapture:
    """Own a live `sudo eslogger` subprocess, capturing stdout lines and stderr.

    Live-only (needs sudo + Full Disk Access), so not exercised by the unit
    suite; kept thin, with all parsing/tracking in the tested classes above.
    """

    def __init__(self, events: list[str]):
        self.proc = subprocess.Popen(
            live_command(events), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def lines(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            yield line

    def stop(self) -> str:
        """Terminate and return an interpreted reason (e.g. the FDA hint)."""
        try:
            self.proc.terminate()
        except Exception:
            pass
        err = ""
        try:
            _, err = self.proc.communicate(timeout=2)
        except Exception:
            pass
        return interpret_stderr(err)


def stream_lines(events: list[str]):
    """Back-compat generator wrapper around LiveCapture."""
    cap = LiveCapture(events)
    try:
        yield from cap.lines()
    finally:
        cap.stop()
