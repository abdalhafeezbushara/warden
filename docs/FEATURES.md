# Warden — feature map

What exists in the MVP, and what the tool can grow into. Grouped by how much
they move the needle, not by difficulty.

## Shipped (v0.1)

- **Multi-agent support** — one command runs any known tool under policy:
  `warden run claude`, `warden run codex`, `warden run cursor`, … Each agent
  has a least-privilege baseline (its provider hosts + the developer registries,
  secrets denied). `warden agents` lists them and shows which are installed.
- **OS-level enforcement** (macOS Seatbelt) — deny credential stores, deny named
  binaries, pin egress to the recording proxy.
- **Network flight recorder** — every egress host recorded, allowed or blocked,
  to a tamper-evident hash-chained log.
- **Local dashboard** — read-only loopback UI: overview (sessions, blocked
  egress, top hosts, tampered logs), session list, per-session detail with the
  egress verdict list. Auto-refreshes for live sessions.
- **Tamper-evident + signed receipts** — `warden verify` proves a log was not
  altered and was signed by the expected key (`warden key` / `--pubkey`).
- **Monitor mode** (`on_violation: warn`) — enforce the filesystem but let
  unlisted egress through *and record it*, so a team can adopt Warden and see
  what would be blocked before switching enforcement on.

## Shipped in v0.2

1. **Comprehensive recording (Endpoint Security)** ✅ — `warden run --deep`
   records every file open, process exec, and file create for the agent's
   process subtree via macOS eslogger (needs sudo + Full Disk Access).
2. **Skill profiling** ✅ — `warden profile` detonates a skill and generates a
   least-privilege policy from observed behavior, flagging unrecognized hosts.
3. **Signed receipts (Ed25519)** ✅ — third-party-verifiable via `warden key`
   and `warden verify --pubkey`.
4. **Live approvals** ✅ — `on_violation: ask` prompts allow-once/always/deny.
5. **Behavioral intelligence** ✅ — `warden risk` classifies hosts (incl. real
   exfil infrastructure) and scores sessions; per-agent baselines.
6. **CI gate + Linux backend + strict-fs + monitor mode** ✅.

## High-impact next

1. **MCP server firewalling.** Treat each MCP server as its own principal with
   its own egress and filesystem policy — the seam GitHub's own docs admit their
   agent firewall does not cover.
2. **Secrets brokering.** Instead of leaving long-lived tokens in env vars and
   dotfiles (how the 2025 s1ngularity attack worked), issue the agent
   short-lived, task-scoped credentials it can't exfiltrate.
3. **Community policy registry (`policies/skills/*.yaml`).** Reviewed
   least-privilege profiles for popular skills/MCP servers — the contribution
   surface that turns users into contributors.
4. **Hardened Linux network pin** — netns + AF_UNIX/socat bridge so egress is
   hard-pinned to the proxy (not just via HTTP_PROXY), matching macOS's
   loopback pin.
5. **Alerting & export** — desktop notification / webhook on a blocked exfil or
   tampered log; one-click signed receipt export for audit.

## Reach (later)

- **Team policies** — a shared org policy file so every developer's agents obey
  the same baseline, with local overrides.
- **Windows** — WFP egress + restricted tokens (the hardest lift; last).

## Deliberately out of scope (for the OSS core)

- TLS interception / payload DLP — Warden records *which host*, not contents, on
  purpose (no MITM, no cert games).
- Cloud SaaS backend — Warden stays local-first; nothing leaves the machine.
