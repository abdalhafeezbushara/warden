# Warden roadmap: basic → advanced

A structured plan to move Warden from a solid egress-firewall + signed-logger
(v0.1) to an advanced behavioral-security platform for AI agents. Each phase
lists its goal, deliverables, how it is tested, and known constraints.

**Status: Phases 1–7 all shipped in v0.2** (91 tests; adversarial-reviewed and
hardened — see the review-fix notes in CHANGELOG). Remaining work is in the
"High-impact next" section of [FEATURES.md](FEATURES.md).

## Guiding constraints (honesty first)

- **Standard library only** in the core. Optional platform helpers are allowed
  but must degrade gracefully when absent.
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
    those are disabled by a hardened distro, Warden degrades to record-only.

## Phase 1 — Intelligence layer  ✅ testable now

**Goal:** make Warden *understand* behavior, not just record it.
- Per-agent behavioral baseline (fingerprint of hosts, processes, fs scope).
- Anomaly detection: flag a session that deviates from its agent's baseline.
- Egress reputation: classify each host (known-provider / developer-infra /
  unrecognized / suspicious-pattern) and score a session's risk.
**Tested:** pure logic, unit tests over synthetic sessions.

## Phase 2 — Enforcement depth  ✅ testable now (Seatbelt)

**Goal:** tighter, more expressive policies.
- Strict filesystem mode: allow-listed writes (deny-all-writes then re-allow the
  project tree) instead of only denying secrets.
- Per-agent process scoping; per-MCP-server sub-policies (each server a principal).
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

## Phase 5 — Linux backend  ⚙ build; CI-tested

**Goal:** cross-platform enforcement via `bubblewrap` (bind-mounts to hide
secrets, network isolation to force the proxy). Policy model/recorder/signing
are already OS-agnostic.
**Tested:** GitHub Actions on ubuntu; graceful record-only fallback verified.

## Phase 6 — Dashboard v2  ✅ testable now

**Goal:** surface the new depth.
- Recorder views (files/processes), per-agent baseline view, session diff
  (rug-pull forensics), risk scores, live streaming (SSE) instead of polling.
**Tested:** JSON API endpoints + parsing.

## Phase 7 — Distribution & trust  ✅ mostly testable now

**Goal:** make it a platform.
- GitHub Action (run agents under Warden in CI; fail on undisclosed egress).
- Signed, reviewable community policies; `warden export` signed receipts.
- Team policy inheritance / composition.

## Continuous

Hardening (raw-IP egress, proxy edge cases, large logs), adversarial review by a
security agent after each phase, tests, and docs kept in lockstep with claims.
