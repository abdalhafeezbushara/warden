"""Render a human-readable report from a recorded session log."""

from __future__ import annotations

from pathlib import Path

from .recorder import read_log, verify_log


def _fmt_meta(records: list[dict]) -> dict:
    start = next((r["event"] for r in records if r["event"]["kind"] == "session.start"), None)
    end = next((r["event"] for r in records if r["event"]["kind"] == "child.exit"), None)
    return {"start": start["data"] if start else {}, "exit": end["data"] if end else {}}


def build_report(path: str | Path) -> str:
    records = read_log(path)
    meta = _fmt_meta(records)
    ok, verify_msg = verify_log(path)

    net_allow, net_block, net_warn = [], [], []
    deep_counts: dict[str, int] = {}
    deep_events = []
    for r in records:
        e = r["event"]
        if e["kind"] in ("net.connect", "net.request"):
            d = e["data"]
            host = d.get("host", "?")
            target = host if e["kind"] == "net.connect" else f"{d.get('method','')} {d.get('url','')}"
            v = d.get("verdict")
            if v == "allow":
                net_allow.append(target)
            elif v == "warn":
                net_warn.append(target)
            else:
                net_block.append(target)
        elif e["kind"] in ("proc.exec", "proc.fork", "fs.open", "fs.create", "fs.write", "ipc.connect"):
            deep_counts[e["kind"]] = deep_counts.get(e["kind"], 0) + 1
            if len(deep_events) < 40:
                d = e["data"]
                deep_events.append((e["kind"], d.get("path") or " ".join(d.get("args", [])) or ""))

    start = meta["start"]
    argv = " ".join(start.get("argv", []))
    enforce = start.get("enforce")
    agent = start.get("agent")
    degraded = any(r["event"]["kind"] == "enforce.unavailable" for r in records)
    compiled = next((r["event"]["data"] for r in records
                     if r["event"]["kind"] == "policy.compiled"), {})
    backend = compiled.get("backend")
    keychain = next((r["event"]["data"] for r in records
                     if r["event"]["kind"] == "policy.keychain"), None)
    env_allowed = next((r["event"]["data"].get("names", []) for r in records
                        if r["event"]["kind"] == "env.allowed"), [])
    mcp_remote = [r["event"]["data"] for r in records
                  if r["event"]["kind"] == "mcp.remote.declared"]

    lines = []
    lines.append("╭─ Warden flight report ─────────────────────────────────")
    if agent:
        lines.append(f"│ agent   : {agent}")
    lines.append(f"│ command : {argv}")
    if degraded:
        mode = "DEGRADED (enforcement unavailable)"
    elif enforce and backend == "seatbelt":
        mode = "ENFORCE (filesystem + process + hard egress pin)"
    elif enforce:
        mode = "ENFORCE (filesystem + process; proxy-observed egress)"
    else:
        mode = "OBSERVE (no OS sandbox; proxy-honoring egress only)"
    lines.append(f"│ policy  : {start.get('policy','?')}   mode: {mode}")
    if keychain is not None and keychain.get("readable"):
        lines.append("│ keychain: READABLE (agent authenticates via macOS Keychain; "
                     "other secrets denied)")
    if env_allowed:
        lines.append(f"│ credentials available by name: {', '.join(env_allowed)}")
    if mcp_remote:
        names = ", ".join(sorted({f"{m['name']}→{m['host']}" for m in mcp_remote}))
        lines.append(f"│ remote MCP (allow-listed, recorded, NOT sandboxed): {names}")
    lines.append(f"│ exit    : {meta['exit'].get('code','?')}   duration: {meta['exit'].get('duration_s','?')}s")
    lines.append(f"│ log     : {Path(path).name}   records: {len(records)}")
    integrity = "OK intact (tamper-evident chain verified)" if ok else f"!! BROKEN - {verify_msg}"
    lines.append(f"│ integrity: {integrity}")
    lines.append("╰────────────────────────────────────────────────────────")
    lines.append("")

    header = f"NETWORK EGRESS  ({len(net_allow)} allowed, {len(net_block)} blocked"
    header += f", {len(net_warn)} warned)" if net_warn else ")"
    lines.append(header)
    if not net_allow and not net_block and not net_warn:
        lines.append("  (no network activity observed)")
    for t in _dedupe(net_allow):
        lines.append(f"  ✓ allow  {t}")
    for t in _dedupe(net_warn):
        lines.append(f"  ! WARN   {t}   ← not in allow-list, let through (monitor mode)")
    for t in _dedupe(net_block):
        lines.append(f"  ✗ BLOCK  {t}   ← denied: host not in allow-list")
    lines.append("")

    if deep_counts:
        label = {"proc.exec": "processes executed", "proc.fork": "forks",
                 "fs.open": "files opened", "fs.create": "files created",
                 "fs.write": "files written", "ipc.connect": "IPC connects"}
        summary = "  ".join(f"{label.get(k, k)}: {v}" for k, v in sorted(deep_counts.items()))
        lines.append(f"DEEP RECORDING (files & processes)")
        lines.append("  " + summary)
        for kind, detail in deep_events[:20]:
            lines.append(f"  · {kind:<12} {detail}")
        lines.append("")

    if degraded:
        if meta["exit"].get("not_started"):
            lines.append("⚠  Enforcement was unavailable; Warden failed closed and did not "
                         "start the child.")
        else:
            lines.append("⚠  Enforcement was unavailable; this session used explicit "
                         "proxy-only fallback.")
    if net_block:
        lines.append("⚠  Warden blocked "
                     f"{len(_dedupe(net_block))} undisclosed egress destination(s). "
                     "Review the blocked hosts above.")
    elif net_warn:
        lines.append(f"⚠  Monitor mode: {len(_dedupe(net_warn))} unlisted destination(s) were "
                     "let through and recorded. Switch on_violation to 'block+receipt' to block them.")
    elif not degraded or not meta["exit"].get("not_started"):
        lines.append("No undisclosed egress. All network activity was to allow-listed hosts.")

    return "\n".join(lines)


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out
