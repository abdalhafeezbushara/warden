"""Read and summarize recorded sessions. Shared by the CLI report and dashboard."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from .recorder import read_log, verify_log


def sessions_dir() -> Path:
    base = Path(os.environ.get("DRIFTWARD_HOME", Path.home() / ".driftward")) / "sessions"
    base.mkdir(parents=True, exist_ok=True)
    return base


def list_session_ids() -> list[str]:
    return sorted((p.stem for p in sessions_dir().glob("*.log")), reverse=True)


def _events(records: list[dict]) -> list[dict]:
    return [r["event"] for r in records]


def summarize(session_id: str) -> dict:
    """One session → a summary dict for lists and detail views."""
    path = sessions_dir() / f"{session_id}.log"
    records = read_log(path)
    events = _events(records)
    start = next((e for e in events if e["kind"] == "session.start"), {"data": {}})
    exit_e = next((e for e in events if e["kind"] == "child.exit"), {"data": {}})
    degraded = any(e["kind"] == "enforce.unavailable" for e in events)
    timed_out = any(e["kind"] == "child.timeout" for e in events)
    compiled = next((e for e in events if e["kind"] == "policy.compiled"), {"data": {}})
    scrubbed = next((e for e in events if e["kind"] == "env.scrubbed"), {"data": {}})
    env_allowed = next((e for e in events if e["kind"] == "env.allowed"), {"data": {}})
    deep_summary_e = next((e for e in events if e["kind"] == "deep.summary"), {"data": {}})
    ok, integrity_msg = verify_log(path)

    allowed, blocked, warned = [], [], []
    deep_events, deep_counts = [], {}
    timeline = []
    for e in events:
        if e["kind"] in ("proc.exec", "proc.fork", "fs.open", "fs.create", "fs.write", "ipc.connect"):
            deep_counts[e["kind"]] = deep_counts.get(e["kind"], 0) + 1
            if len(deep_events) < 500:  # cap the detail payload
                deep_events.append({"kind": e["kind"], "ts": e["ts"], **e["data"]})
    for e in events:
        if e["kind"] in ("net.connect", "net.request"):
            d = e["data"]
            host = d.get("host", "?")
            verdict = d.get("verdict")
            entry = {
                "ts": e["ts"],
                "kind": e["kind"],
                "host": host,
                "verdict": verdict,
                "port": d.get("port"),
                "detail": d.get("url") or f"{d.get('scheme','https')}:{d.get('port','')}",
                "method": d.get("method"),
            }
            if verdict == "allow":
                allowed.append(entry)
            elif verdict == "warn":
                warned.append(entry)
            else:
                blocked.append(entry)
        if e["kind"] in ("net.connect", "net.request", "child.start", "child.exit",
                         "child.timeout", "session.start", "policy.compiled", "proxy.up",
                         "enforce.unavailable", "env.allowed", "env.scrubbed", "deep.summary",
                         "mcp.broker.started", "mcp.broker.launch", "mcp.broker.denied",
                         "mcp.broker.stopped"):
            timeline.append({"ts": e["ts"], "kind": e["kind"], "data": e["data"]})

    sd = start.get("data", {})
    exit_code = exit_e.get("data", {}).get("code")
    not_started = bool(exit_e.get("data", {}).get("not_started"))
    if not ok:
        status = "tampered"
    elif timed_out:
        status = "timed-out"
    elif degraded:
        status = "degraded"
    elif exit_code is None:
        status = "running"
    elif exit_code != 0:
        status = "failed"
    else:
        status = "completed"
    result = {
        "id": session_id,
        "ts": start.get("ts"),
        "agent": sd.get("agent"),
        "subject": sd.get("subject"),
        "argv": sd.get("argv", []),
        "command": " ".join(sd.get("argv", [])) if sd.get("argv") else "",
        "policy": sd.get("policy"),
        "policy_sha256": sd.get("policy_sha256"),
        "platform": sd.get("platform"),
        "executable": sd.get("executable"),
        "executable_sha256": sd.get("executable_sha256"),
        "mode": "degraded" if degraded else ("observe" if not sd.get("enforce") else "enforce"),
        "status": status,
        "backend": compiled.get("data", {}).get("backend"),
        "degraded": degraded,
        "not_started": not_started,
        "timed_out": timed_out,
        "env_scrubbed": scrubbed.get("data", {"count": 0, "names": []}),
        "env_allowed": env_allowed.get("data", {}).get("names", []),
        "deep_summary": deep_summary_e.get("data", {}),
        "cwd": sd.get("cwd"),
        "exit": exit_code,
        "duration_s": exit_e.get("data", {}).get("duration_s"),
        "allowed": allowed,
        "blocked": blocked,
        "warned": warned,
        "allowed_count": len(allowed),
        "blocked_count": len(blocked),
        "warned_count": len(warned),
        "records": len(records),
        "integrity_ok": ok,
        "integrity_msg": integrity_msg,
        "timeline": timeline,
        "deep_events": deep_events,
        "deep_counts": deep_counts,
    }
    from . import intelligence
    base = {
        "id": session_id, "allowed": allowed, "blocked": blocked, "warned": warned,
        "integrity_ok": ok, "degraded": degraded, "not_started": not_started,
        "timed_out": timed_out,
    }
    result["risk"] = intelligence.session_risk(base)
    result["host_classes"] = {
        e["host"]: intelligence.classify_host(e["host"])[0]
        for e in (allowed + blocked + warned)
    }
    return result


def list_summaries() -> list[dict]:
    out = []
    for sid in list_session_ids():
        try:
            s = summarize(sid)
        except Exception as exc:  # a corrupt log should not break the list
            out.append({"id": sid, "error": str(exc), "integrity_ok": False,
                        "blocked_count": 0, "allowed_count": 0})
            continue
        # Slim it for the list view.
        row = {k: s[k] for k in (
            "id", "ts", "agent", "subject", "command", "policy", "mode", "status", "backend", "exit",
            "duration_s", "allowed_count", "blocked_count", "integrity_ok")}
        row["risk"] = s.get("risk", {})
        row["warned_count"] = s.get("warned_count", 0)
        row["env_scrubbed_count"] = s.get("env_scrubbed", {}).get("count", 0)
        out.append(row)
    return out


def drift() -> list[dict]:
    """Detect behavioral drift ("rug pulls"): a command/agent that contacted a
    host in a later run which it never contacted in earlier runs. A skill that
    was clean last week and phones home this week shows up here.
    """
    by_key: dict[str, list[dict]] = {}
    for sid in list_session_ids():
        try:
            s = summarize(sid)
        except Exception:
            continue
        key = s.get("agent") or s.get("command") or sid
        by_key.setdefault(key, []).append(s)

    findings = []
    for key, runs in by_key.items():
        if len(runs) < 2:
            continue
        runs.sort(key=lambda r: r.get("ts") or 0)  # oldest first
        seen: set[str] = set()
        for i, r in enumerate(runs):
            hosts = ({e["host"] for e in r["allowed"]} | {e["host"] for e in r["blocked"]}
                     | {e["host"] for e in r.get("warned", [])})
            if i == 0:
                seen = set(hosts)
                continue
            new = hosts - seen
            if new:
                findings.append({
                    "key": key,
                    "session": r["id"],
                    "new_hosts": sorted(new),
                    "run_index": i + 1,
                    "total_runs": len(runs),
                })
            seen |= hosts
    return findings


def overview() -> dict:
    summaries = [summarize(sid) for sid in list_session_ids()]
    host_counter: Counter = Counter()
    blocked_counter: Counter = Counter()
    agents: Counter = Counter()
    total_blocked = 0
    tampered = 0
    degraded = 0
    failed = 0
    high_risk = 0
    timed_out = 0
    for s in summaries:
        for a in s["allowed"]:
            host_counter[a["host"]] += 1
        for b in s["blocked"]:
            blocked_counter[b["host"]] += 1
            total_blocked += 1
        if s.get("agent"):
            agents[s["agent"]] += 1
        if not s["integrity_ok"]:
            tampered += 1
        if s.get("degraded"):
            degraded += 1
        if s.get("status") == "failed":
            failed += 1
        if s.get("timed_out"):
            timed_out += 1
        if s.get("risk", {}).get("level") in ("high", "critical"):
            high_risk += 1
    return {
        "sessions": len(summaries),
        "blocked_total": total_blocked,
        "tampered_sessions": tampered,
        "degraded_sessions": degraded,
        "failed_sessions": failed,
        "timed_out_sessions": timed_out,
        "high_risk_sessions": high_risk,
        "top_hosts": host_counter.most_common(10),
        "top_blocked": blocked_counter.most_common(10),
        "agents": dict(agents),
        "drift": drift(),
        "recent": [{k: s.get(k) for k in (
            "id", "ts", "agent", "subject", "command", "mode", "status", "backend", "exit",
            "blocked_count", "integrity_ok", "risk")}
                   for s in summaries[:5]],
    }
