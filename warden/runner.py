"""Orchestrate a monitored run: proxy up, policy enforced, child recorded."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

from . import backends, childenv
from .policy import Policy
from .proxy import start_proxy
from .recorder import Recorder


def _session_dir() -> Path:
    base = _warden_home()
    sessions = base / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    return sessions


def _warden_home() -> Path:
    """Warden's control-plane directory, locked to the owner (0700). Holds the
    signing key and session logs — the agent must never reach these."""
    home = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden"))
    home.mkdir(parents=True, exist_ok=True)
    try:
        home.chmod(0o700)
    except OSError:
        pass
    return home


# Grace period for eslogger's ES client to come up before we launch the child,
# so the child's earliest fork/exec are captured (they were missed when eslogger
# started after the child). Overridable for tests.
DEEP_READY_GRACE_S = 1.5


def _executable_identity(argv: list[str]) -> tuple[str | None, str | None]:
    """Resolve and hash the launched executable while it still represents the run.

    The digest is evidence of a runtime change, not a package provenance claim.
    Failures are deliberately non-fatal: recording must still work for virtual
    commands and unusual executable types.
    """
    import shutil

    resolved = shutil.which(argv[0]) or argv[0]
    try:
        real = os.path.realpath(resolved)
        digest = hashlib.sha256()
        with open(real, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return real, digest.hexdigest()
    except (OSError, TypeError, ValueError):
        return str(resolved) if resolved else None, None


def _policy_digest(policy: Policy) -> str:
    payload = json.dumps(policy.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _start_deep_stream(rec, files: bool):
    """Start eslogger capture BEFORE the child. Returns a DeepStream (buffering
    until attach) or None. Best-effort; failure never breaks the run."""
    from . import deep

    if not deep.eslogger_available():
        rec.emit("deep.unavailable", {"reason": "eslogger not found"})
        return None
    events = deep.DEEP_FILE_EVENTS if files else deep.DEEP_EVENTS
    stream = deep.DeepStream(rec, events)
    if not stream.start():
        rec.emit("deep.unavailable", {"reason": "could not start eslogger"})
        return None
    rec.emit("deep.started", {"events": events})
    return stream


def run(argv: list[str], policy: Policy, *, enforce: bool, session: str | None = None,
        agent: str | None = None, deep: bool = False, deep_files: bool = False,
        quiet: bool = False, timeout: float | None = None,
        allow_record_fallback: bool = False, subject: dict | None = None,
        env_overrides: dict[str, str] | None = None,
        mcp_configs: list[str] | None = None, enable_mcp_broker: bool = True) -> int:
    """Run `argv` under Warden. If enforce is False, record-only (no sandbox).

    deep=True additionally streams macOS Endpoint Security events (via eslogger)
    for the child's process subtree — comprehensive file/process recording. It is
    best-effort and needs sudo + Full Disk Access; failure never breaks the run.
    timeout kills the child after N seconds (used for time-boxed detonation).
    """
    if not argv:
        raise ValueError("nothing to run")

    # Protect Warden's own control plane: the agent must never read the signing
    # key or session logs (that would let it forge/alter its own receipts), nor
    # write into Warden's home. Injected into every policy regardless of the
    # user's rules.
    home = _warden_home()
    extra_reads: list[str] = []
    # Under strict-read, reads under $HOME are denied except the allow-list — but
    # the agent's OWN binary is often installed under $HOME (npm global, ~/.local,
    # nvm). Always allow reading/exec of the executable being run, or the sandbox
    # can't even launch it ("execvp: No such file or directory").
    if policy.strict_read:
        import shutil as _shutil

        which = _shutil.which(argv[0]) or argv[0]
        real = os.path.realpath(which)
        extra_reads = [which, real,
                       os.path.dirname(which) + "/**", os.path.dirname(real) + "/**"]
        # Node/npm-installed agents are a symlink to a .js that needs its whole
        # package tree (and deps) readable, not just its bin dir.
        if "/node_modules/" in real:
            extra_reads.append(real.split("/node_modules/")[0] + "/node_modules/**")
        # Wrapped MCP configs execute the small public Warden shim from inside
        # this sandbox. Its source is safe to expose; WARDEN_HOME remains denied.
        warden_bin = _shutil.which("warden")
        if warden_bin:
            warden_real = os.path.realpath(warden_bin)
            extra_reads.extend([warden_bin, warden_real,
                                os.path.dirname(warden_bin) + "/**",
                                os.path.dirname(warden_real) + "/**"])
        extra_reads.append(str(Path(__file__).resolve().parent) + "/**")
    policy = replace(
        policy,
        filesystem=replace(
            policy.filesystem,
            deny=list(policy.filesystem.deny) + [str(home) + "/**"],
            read=list(policy.filesystem.read) + extra_reads,
        ),
    )

    # Millisecond suffix so two sessions started in the same second don't collide
    # (which would overwrite the earlier log).
    stamp = session or (time.strftime("%Y%m%d-%H%M%S")
                        + f"-{int(time.time() * 1000) % 1000:03d}-{os.getpid()}")
    log_path = _session_dir() / f"{stamp}.log"
    rec = Recorder(log_path)
    executable, executable_sha256 = _executable_identity(argv)
    rec.start(
        {
            "argv": argv,
            "policy": policy.name,
            "policy_sha256": _policy_digest(policy),
            "agent": agent,
            # An explicit behavioral principal (e.g. an MCP server run as its own
            # identity) so its capabilities baseline and drift are tracked apart
            # from the agent that launched it.
            "subject": subject,
            "enforce": enforce,
            "cwd": os.getcwd(),
            "platform": platform.system().lower(),
            "executable": executable,
            "executable_sha256": executable_sha256,
            "warden_pid": os.getpid(),
        }
    )

    # Record whether the macOS Keychain was left readable, so the flight report
    # is explicit about it (an agent that logs in via the keychain needs this;
    # the report should never leave that access invisible).
    if sys.platform == "darwin":
        from .policy import keychain_allowed
        rec.emit("policy.keychain", {"readable": keychain_allowed(policy)})

    approval_cache = None
    if policy.on_violation == "ask":
        from . import approvals
        # Interactive TTY prompt when possible; otherwise fail safe (auto-deny).
        decider = approvals.tty_decider() if sys.stdin.isatty() else approvals.auto_decider(approvals.DENY)
        approval_cache = approvals.DecisionCache(decider)
        if not sys.stdin.isatty():
            print("warden: on_violation=ask but no TTY — unlisted hosts will be denied.",
                  file=sys.stderr)

    broker = None
    if enable_mcp_broker and (subject or {}).get("kind") != "mcp":
        from . import mcp, mcp_broker
        broker = mcp_broker.start_for_configs(mcp_configs, recorder=rec)
        # Remote (url/SSE) MCP servers can't be sandboxed — there's no local
        # process — but the agent still needs to reach the ones it's configured
        # for, and that traffic should be recorded, not silently blocked by
        # default-deny egress. Allow-list exactly the declared endpoints and log
        # them as declared, so a rug-pulled URL is visible in the flight report.
        remotes = mcp.remote_endpoints(mcp_configs)
        new_hosts = sorted({r["host"] for r in remotes} - set(policy.network.allow))
        if new_hosts:
            policy = replace(policy, network=replace(
                policy.network, allow=sorted(set(policy.network.allow) | set(new_hosts))))
            for remote in remotes:
                rec.emit("mcp.remote.declared", {"name": remote["name"], "host": remote["host"]})
            print(f"warden: {len(new_hosts)} declared remote MCP endpoint(s) allow-listed and "
                  f"recorded (not sandboxed): {', '.join(new_hosts)}", file=sys.stderr)

    proxy = start_proxy(rec, policy, cache=approval_cache)
    proxy_url = f"http://127.0.0.1:{proxy.port}"
    rec.emit("proxy.up", {"port": proxy.port})

    # Scrub the environment to a safe allow-list so shell secrets (AWS keys,
    # GitHub token, DB URLs) don't leak into the agent. Only safe base vars, the
    # agent's own provider keys, and policy-allow-listed names pass through.
    overrides = dict(env_overrides or {})
    overrides.update({
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url, "https_proxy": proxy_url, "ALL_PROXY": proxy_url,
        "WARDEN_ACTIVE": "1", "WARDEN_SESSION": stamp,
    })
    if broker:
        from .mcp_broker import BROKER_ENV, TOKEN_ENV
        overrides[BROKER_ENV] = broker.address
        overrides[TOKEN_ENV] = broker.token
    child_env = childenv.build_child_env(policy, overrides, agent=agent)
    # Record credential *names*, never values.  This makes a new environment
    # grant visible in behavior diffs even when the process never uses it.
    credential_names = sorted((childenv.provider_keys_for(agent) | set(policy.env_allow))
                              & set(child_env))
    rec.emit("env.allowed", {"names": credential_names})
    scrubbed = childenv.scrubbed_names(policy, agent=agent)
    if scrubbed:
        rec.emit("env.scrubbed", {"count": len(scrubbed), "names": scrubbed[:50]})

    cleanup = None
    if enforce:
        try:
            cmd, cleanup, backend = backends.wrap(
                policy, argv, proxy.port, broker_port=broker.port if broker else None)
            rec.emit("policy.compiled", {"backend": backend})
        except backends.BackendUnavailable:
            unavailable = backends.unavailable_reason()
            print(f"warden: enforcement unavailable — {unavailable}",
                  file=sys.stderr)
            rec.emit("enforce.unavailable", {"platform": sys.platform, "reason": unavailable})
            if not allow_record_fallback:
                print("warden: refusing to run without enforcement. Use 'warden record' "
                      "or --allow-record-fallback to opt in.", file=sys.stderr)
                code = 125
                rec.emit("child.exit", {"code": code, "duration_s": 0.0,
                                        "interrupted": False, "not_started": True})
                if broker:
                    broker.close()
                rec.seal({"exit_code": code, "enforcement_unavailable": True})
                proxy.shutdown()
                proxy.server_close()
                return code
            print("warden: explicit fallback enabled — proxy-honoring egress is captured; "
                  "there is no OS sandbox.", file=sys.stderr)
            enforce = False
            cmd = list(argv)
    else:
        cmd = list(argv)

    # Start deep capture BEFORE the child and give eslogger a moment to be ready,
    # so the child's first fork/exec aren't lost to eslogger's startup latency.
    deep_stream = None
    if deep:
        deep_stream = _start_deep_stream(rec, deep_files)
        if deep_stream:
            time.sleep(DEEP_READY_GRACE_S)

    rec.emit("child.start", {"cmd": cmd})
    started = time.time()
    interrupted = False
    proc = None
    devnull = None
    try:
        # Popen (not run) so we can seal cleanly on Ctrl-C while still letting the
        # signal reach the child, which shares our foreground process group.
        if quiet:
            devnull = open(os.devnull, "wb")
            proc = subprocess.Popen(cmd, env=child_env, stdout=devnull, stderr=devnull)
        else:
            proc = subprocess.Popen(cmd, env=child_env)
        if deep_stream:
            deep_stream.attach(proc.pid)  # child pid known → replay buffer + go live
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rec.emit("child.timeout", {"timeout_s": timeout})
            proc.terminate()
            try:
                code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
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
        if deep_stream:
            summ = deep_stream.finish()
            total = sum(summ.get("events", {}).values())
            if total == 0 and deep_stream.reason:
                summ["note"] = deep_stream.reason
                print(f"warden: deep recording captured nothing — {deep_stream.reason}",
                      file=sys.stderr)
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
    if broker:
        broker.close()
    rec.seal({"exit_code": code, "interrupted": interrupted})
    proxy.shutdown()
    proxy.server_close()

    if not quiet:
        print(f"\nwarden: session recorded → {log_path}", file=sys.stderr)
        print(f"warden: run 'warden report {log_path.name}' to see what happened", file=sys.stderr)
    return code
