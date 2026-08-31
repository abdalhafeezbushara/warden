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
- **Local security console** — read-only loopback UI with runtime posture,
  capability status, approved drift inbox, signed-baseline coverage, searchable
  sessions, network and file/process evidence, signed timeline, and JSON export.
- **Tamper-evident + signed receipts** — `warden verify` proves a log was not
  altered and was signed by the expected key (`warden key` / `--pubkey`).
- **Monitor mode** (`on_violation: warn`) — enforce the filesystem but let
  unlisted egress through *and record it*, so a team can adopt Warden and see
  what would be blocked before switching enforcement on.

## Shipped in v0.2

1. **Comprehensive recording (Endpoint Security)** ✅ — `warden run --deep`
   records every file open, process exec, and file create for the agent's
   process subtree via macOS eslogger (needs sudo + Full Disk Access).
2. **Skill profiling** ✅ — `warden profile` time-boxes a semi-trusted skill
   under strict host confinement and generates a least-privilege policy from
   observed behavior, flagging unrecognized hosts.
3. **Signed receipts (Ed25519)** ✅ — third-party-verifiable via `warden key`
   and `warden verify --pubkey`.
4. **Live approvals** ✅ — `on_violation: ask` prompts allow-once/always/deny.
5. **Behavioral intelligence** ✅ — `warden risk` classifies hosts (incl. real
   exfil infrastructure) and scores sessions; per-agent baselines.
6. **CI gate + Linux backend + strict-fs/strict-read + monitor mode** ✅.
7. **Approved behavioral integrity** ✅ — versioned behavior manifests,
   explicit signed baselines, explainable capability drift, executable/policy
   identity changes, and `warden gate --fail-on-new`. No auto-learning.
8. **Per-MCP-server firewalling** ✅ — local stdio servers launch through an
   authenticated parent broker as independent `mcp:<name>` principals, with
   strict filesystem defaults, configured env preservation, signed baselines,
   and definition/package drift. Remote URL/SSE confinement remains next.

## High-impact next

1. **Remote MCP gateway.** Extend the shipped stdio per-server identity and
   confinement to remote URL/SSE transports through a recorded egress gateway.
2. **Secrets brokering.** Instead of leaving long-lived tokens in env vars and
   dotfiles (how the 2025 s1ngularity attack worked), issue the agent
   short-lived, task-scoped credentials it can't exfiltrate.
3. **Community behavior + policy registry.** Reviewed least-privilege profiles
   and signed expected-behavior manifests for popular skills/MCP servers — the
   contribution surface that turns users into contributors.
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
