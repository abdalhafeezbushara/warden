# Warden roadmap: basic → advanced

A structured plan to move Warden from a solid egress-firewall + signed-logger
(v0.1) to an advanced behavioral-security platform for AI agents. Each phase
lists its goal, deliverables, how it is tested, and known constraints.

**Status: the v0.2 security core is shipped and covered by 149 tests.** Phases
1, 3, and the macOS portion of 4 are implemented; phases 2, 5, 6, and 7 have
useful shipped slices plus the explicitly listed work below. See
[FEATURES.md](FEATURES.md) for the prioritized backlog.

## Guiding constraints (honesty first)

- **Standard library only** in the core. Optional observability helpers may
  degrade clearly; a missing enforcement backend fails closed unless the user
  explicitly requests record-only fallback.
- **Never claim more than is tested.** A feature that can't be live-tested in a
  given environment ships behind an explicit flag and says so.
- **Two hard external prerequisites** discovered during build, documented so we
  don't pretend around them:
  - *Comprehensive filesystem/process recording* on macOS needs either
    `eslogger` (which requires the **terminal to have Full Disk Access** granted
    in System Settings — a one-time manual GUI step, not grantable from code) or
    a code-signed helper with the `com.apple.developer.endpoint-security.client`
    entitlement (Apple-gated). The recorder is built and unit-tested against
    captured/synthetic event data; the live capture path is thin and documented.
  - *Linux enforcement* uses `bubblewrap` (unprivileged user namespaces); where
    those are disabled by a hardened distro, enforced runs refuse to start.

## Phase 1 — Behavioral integrity  ✅ shipped

**Goal:** make Warden *understand* behavior, not just record it.
- Versioned behavior manifests normalize network, process, filesystem, IPC,
  and credential capabilities into portable, deterministic evidence.
- Explicit Ed25519-signed approved baselines, scoped by subject + workspace.
  Observed history never becomes approval automatically.
- Explainable drift with severity, runtime/policy identity changes, baseline
  signature verification, and anti-poisoning replacement via explicit `--force`.
- Egress reputation: classify each host (known-provider / developer-infra /
  unrecognized / suspicious-pattern) and score a session's risk.
**Tested:** pure logic, unit tests over synthetic sessions.

## Phase 2 — Enforcement depth  ◐ partially shipped

**Goal:** tighter, more expressive policies.
- Strict filesystem mode: allow-listed writes (deny-all-writes then re-allow the
  project tree) instead of only denying secrets.
- Per-agent process and credential scoping is shipped.
- Per-MCP-server sub-policies are shipped for local stdio servers: an
  authenticated parent broker launches each exact pre-registered definition as
  a strict, signed principal. **Pending:** a gateway for remote URL/SSE servers.
**Tested:** live `sandbox-exec` runs assert denied/allowed outcomes.

## Phase 3 — Live approvals (human-in-the-loop)  ✅ logic testable now

**Goal:** interactive containment.
- Decision engine: on unlisted egress, decide allow-once / allow-always / deny,
  via a pluggable "decider" (TTY prompt, or auto-policy).
- Policy learning: an approved host is appended to the effective allow-list.
**Tested:** decider is injectable; unit tests drive it without a TTY.

## Phase 4 — Comprehensive recorder (eslogger)  ⚙ build + synthetic test

**Goal:** record every file open, process exec, and socket — the true flight
recorder. Correlate ES events to the sandboxed child by pid subtree.
- `warden run --deep` streams `sudo eslogger --format json exec fork open ...`,
  filters to the child's process subtree, and records into the same signed log.
**Tested:** event parser + pid-correlation unit-tested against captured/synthetic
eslogger JSONL. **Live path requires Full Disk Access on the terminal** (doc'd).

## Phase 5 — Linux backend  ◐ filesystem shipped; hard egress pending

**Goal:** cross-platform enforcement via `bubblewrap`. Filesystem/read
confinement is generated and CI-tested; proxy environment wiring is shipped.
**Pending:** network-namespace pinning so non-proxy-aware Linux clients cannot
bypass recording. Missing bwrap fails closed by default.

## Phase 6 — Security console  ◐ behavior workspace shipped

**Goal:** surface the new depth.
- Shipped: runtime posture, capability detection, searchable/filterable
  sessions, risk/status/backend signals, file/process/network evidence, signed
  timeline, approved-drift inbox, baseline coverage/signature view, per-session
  behavior diffs, and JSON export.
- **Pending:** interactive approval with CSRF-safe local mutations, side-by-side
  raw session diff, and SSE streaming (the current UI polls locally).
**Tested:** session summary/API contracts plus live browser validation.

## Phase 7 — Distribution & trust  ◐ partially shipped

**Goal:** make it a platform.
- Shipped: GitHub Action and risk/blocked-egress/behavior-drift CI gate, plus
  portable signed behavior baseline JSON.
- **Pending:** signed community registry, signed export command, and team policy
  inheritance/composition.

## Continuous

Hardening (raw-IP egress, proxy edge cases, large logs), adversarial review by a
security agent after each phase, tests, and docs kept in lockstep with claims.
