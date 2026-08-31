"""Orchestrate a monitored run: proxy up, policy enforced, child recorded."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from . import backends
from .policy import Policy
from .proxy import start_proxy
from .recorder import Recorder


def _session_dir() -> Path:
    base = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden")) / "sessions"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _start_deep(rec, root_pid: int, files: bool):
    """Best-effort: start an eslogger stream feeding a DeepRecorder. Returns a
    (thread, stop) pair or None. Any failure is non-fatal — normal recording
    continues. Live capture needs sudo + Full Disk Access (macOS)."""
    import threading

    from . import deep

    if not deep.eslogger_available():
        rec.emit("deep.unavailable", {"reason": "eslogger not found"})
        return None
    events = deep.DEEP_FILE_EVENTS if files else deep.DEEP_EVENTS
    dr = deep.DeepRecorder(rec, root_pid)
    stop = threading.Event()
    state = {"capture": None, "reason": None}

    def pump():
        try:
            cap = deep.LiveCapture(events)
            state["capture"] = cap
            for line in cap.lines():
                if stop.is_set():
                    break
                dr.feed_line(line)
        except Exception as exc:  # FDA denied, sudo failed, etc. — stay non-fatal
            rec.emit("deep.error", {"error": str(exc)[:200]})

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    rec.emit("deep.started", {"events": events, "root_pid": root_pid})
    return (t, stop, dr, state)


def run(argv: list[str], policy: Policy, *, enforce: bool, session: str | None = None,
        agent: str | None = None, deep: bool = False, deep_files: bool = False,
        quiet: bool = False) -> int:
    """Run `argv` under Warden. If enforce is False, record-only (no sandbox).

    deep=True additionally streams macOS Endpoint Security events (via eslogger)
    for the child's process subtree — comprehensive file/process recording. It is
    best-effort and needs sudo + Full Disk Access; failure never breaks the run.
    """
    if not argv:
        raise ValueError("nothing to run")

    # Millisecond suffix so two sessions started in the same second don't collide
    # (which would overwrite the earlier log).
    stamp = session or (time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}")
    log_path = _session_dir() / f"{stamp}.log"
    rec = Recorder(log_path)
    rec.start(
        {
            "argv": argv,
            "policy": policy.name,
            "agent": agent,
            "enforce": enforce,
            "cwd": os.getcwd(),
            "warden_pid": os.getpid(),
        }
    )

    approval_cache = None
    if policy.on_violation == "ask":
        from . import approvals
        # Interactive TTY prompt when possible; otherwise fail safe (auto-deny).
        decider = approvals.tty_decider() if sys.stdin.isatty() else approvals.auto_decider(approvals.DENY)
        approval_cache = approvals.DecisionCache(decider)
        if not sys.stdin.isatty():
            print("warden: on_violation=ask but no TTY — unlisted hosts will be denied.",
                  file=sys.stderr)

    proxy = start_proxy(rec, policy, cache=approval_cache)
    proxy_url = f"http://127.0.0.1:{proxy.port}"
    rec.emit("proxy.up", {"port": proxy.port})

    child_env = dict(os.environ)
    child_env.update(
        {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
            "WARDEN_ACTIVE": "1",
            "WARDEN_SESSION": stamp,
        }
    )

    cleanup = None
    if enforce:
        try:
            cmd, cleanup, backend = backends.wrap(policy, argv, proxy.port)
            rec.emit("policy.compiled", {"backend": backend})
        except backends.BackendUnavailable:
            # No enforcement backend here. Degrade to recording rather than fail:
            # egress is still captured through the proxy, and the report says so.
            print("warden: no enforcement backend on this platform — recording only "
                  "(egress still contained via proxy).", file=sys.stderr)
            rec.emit("enforce.unavailable", {"platform": sys.platform})
            enforce = False
            cmd = list(argv)
    else:
        cmd = list(argv)

    rec.emit("child.start", {"cmd": cmd})
    started = time.time()
    interrupted = False
    proc = None
    deep_handle = None
    devnull = None
    try:
        # Popen (not run) so we can seal cleanly on Ctrl-C while still letting the
        # signal reach the child, which shares our foreground process group.
        if quiet:
            devnull = open(os.devnull, "wb")
            proc = subprocess.Popen(cmd, env=child_env, stdout=devnull, stderr=devnull)
        else:
            proc = subprocess.Popen(cmd, env=child_env)
        if deep:
            deep_handle = _start_deep(rec, proc.pid, deep_files)
        code = proc.wait()
    except FileNotFoundError as exc:
        rec.emit("child.error", {"error": str(exc)})
        code = 127
    except KeyboardInterrupt:
        interrupted = True
        rec.emit("child.interrupt", {"signal": "SIGINT"})
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                code = proc.wait()
        else:
            code = 130
    finally:
        if deep_handle:
            _, stop, dr, state = deep_handle
            stop.set()
            reason = None
            if state.get("capture"):
                reason = state["capture"].stop()
            summ = dr.summary()
            total = sum(summ["events"].values())
            if total == 0 and reason:
                summ["note"] = reason
                print(f"warden: deep recording captured nothing — {reason}", file=sys.stderr)
            rec.emit("deep.summary", summ)
        if cleanup:
            cleanup()
        if devnull:
            devnull.close()

    if approval_cache and approval_cache.learned:
        learned = sorted(approval_cache.learned)
        rec.emit("approval.learned", {"hosts": learned})
        print(f"warden: approved this session — add to your allow-list: {', '.join(learned)}",
              file=sys.stderr)

    rec.emit("child.exit", {"code": code, "duration_s": round(time.time() - started, 3),
                            "interrupted": interrupted})
    rec.seal({"exit_code": code, "interrupted": interrupted})
    proxy.shutdown()
    proxy.server_close()

    if not quiet:
        print(f"\nwarden: session recorded → {log_path}", file=sys.stderr)
        print(f"warden: run 'warden report {log_path.name}' to see what happened", file=sys.stderr)
    return code
