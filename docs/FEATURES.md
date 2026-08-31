# Driftward — feature map

What exists in the MVP, and what the tool can grow into. Grouped by how much
they move the needle, not by difficulty.

## Shipped (v0.1)

- **Multi-agent support** — one command runs any known tool under policy:
  `driftward run claude`, `driftward run codex`, `driftward run cursor`, … Each agent
  has a least-privilege baseline (its provider hosts + the developer registries,
  secrets denied). `driftward agents` lists them and shows which are installed.
- **OS-level enforcement** (macOS Seatbelt) — deny credential stores, deny named
  binaries, pin egress to the recording proxy.
- **Network flight recorder** — every egress host recorded, allowed or blocked,
  to a tamper-evident hash-chained log.
- **Local security console** — read-only loopback UI with runtime posture,
  capability status, approved drift inbox, signed-baseline coverage, searchable
  sessions, network and file/process evidence, signed timeline, and JSON export.
- **Tamper-evident + signed receipts** — `driftward verify` proves a log was not
  altered and was signed by the expected key (`driftward key` / `--pubkey`).
- **Monitor mode** (`on_violation: warn`) — enforce the filesystem but let
  unlisted egress through *and record it*, so a team can adopt Driftward and see
  what would be blocked before switching enforcement on.

## Shipped in v0.2

1. **Comprehensive recording (Endpoint Security)** ✅ — `driftward run --deep`
   records every file open, process exec, and file create for the agent's
   process subtree via macOS eslogger (needs sudo + Full Disk Access).
2. **Skill profiling** ✅ — `driftward profile` time-boxes a semi-trusted skill
   under strict host confinement and generates a least-privilege policy from
   observed behavior, flagging unrecognized hosts.
3. **Signed receipts (Ed25519)** ✅ — third-party-verifiable via `driftward key`
   and `driftward verify --pubkey`.
4. **Live approvals** ✅ — `on_violation: ask` prompts allow-once/always/deny.
5. **Behavioral intelligence** ✅ — `driftward risk` classifies hosts (incl. real
   exfil infrastructure) and scores sessions; per-agent baselines.
6. **CI gate + Linux backend + strict-fs/strict-read + monitor mode** ✅.
7. **Approved behavioral integrity** ✅ — versioned behavior manifests,
   explicit signed baselines, explainable capability drift, executable/policy
   identity changes, and `driftward gate --fail-on-new`. No auto-learning.
8. **Per-MCP-server firewalling** ✅ — local stdio servers launch through an
   authenticated parent broker as independent `mcp:<name>` principals, with
   strict filesystem defaults, configured env preservation, signed baselines,
   and definition/package drift.
9. **Remote MCP confinement** ✅ — remote (`url`) servers run through a sandboxed
   stdio↔HTTP bridge as their own principal with egress locked to the declared
   host, for both MCP transports (Streamable HTTP and legacy SSE).
10. **Signed community registry** ✅ — `driftward registry` shares/adopts reviewed,
    Ed25519-signed behavior baselines (and optional policies) with a deny-by-
    default trust store; adopting one drift-checks against it in any project.

## High-impact next

1. **Secrets brokering.** Instead of leaving long-lived tokens in env vars and
   dotfiles (how the 2025 s1ngularity attack worked), issue the agent
   short-lived, task-scoped credentials it can't exfiltrate.
2. **A curated public registry** — an independently-published maintainer key and
   reproducibly reviewed, version-pinned entries (the signing/trust/adopt
   primitive ships today; the seed registry under `registry/examples/` is a
   template, not production trust).
3. **Hardened Linux network pin** — netns + AF_UNIX/socat bridge so egress is
   hard-pinned to the proxy (not just via HTTP_PROXY), matching macOS's
   loopback pin.
5. **Alerting & export** — desktop notification / webhook on a blocked exfil or
   tampered log; one-click signed receipt export for audit.

## Reach (later)

- **Team policies** — a shared org policy file so every developer's agents obey
  the same baseline, with local overrides.
- **Windows** — WFP egress + restricted tokens (the hardest lift; last).

## Deliberately out of scope (for the OSS core)

- TLS interception / payload DLP — Driftward records *which host*, not contents, on
  purpose (no MITM, no cert games).
- Cloud SaaS backend — Driftward stays local-first; nothing leaves the machine.
