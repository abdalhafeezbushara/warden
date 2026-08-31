# Changelog

All notable changes to Warden are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); Warden uses semantic versioning.

## [0.2.0] — unreleased

Advanced capabilities on top of v0.1.

### Added
- **Batch scan engine** (`warden scan`): point it at a corpus of skills / MCP
  servers and it reports what they actually do at scale — a static pass (network
  calls, credential-store access, prompt-injection patterns) combined with a safe
  detonation of each under containment, aggregated into a shareable HTML/JSON
  finding. `--static-only` never executes anything (safe on large untrusted
  corpora). Static analysis is tuned for PRECISION against real-world code:
  hostnames are validated (template-literal junk rejected), credential detection
  is limited to actual credential-store paths (not generic `process.env`),
  injection detection keeps only high-precision patterns (Trojan-Source bidi
  chars, "ignore previous instructions", "do not tell the user") and skips
  test/dist/minified files — verified against 30 real npm MCP servers with zero
  false positives. Ships `scripts/warden-launch.sh` (fetch real MCP servers →
  scan) and an example corpus under `examples/skill-corpus/`.
- **Behavioral intelligence** (`warden risk`): host classification with real
  exfiltration-infrastructure detection (tunnels, webhook catchers, OOB domains,
  raw IPs, punycode, DGA-like subdomains), a 0-100 session risk score, and
  per-agent behavioral baselines / anomaly detection.
- **CI gate** (`warden gate`) + a composite GitHub Action: fail a build on high
  risk or undisclosed egress.
- **Comprehensive recording** (`warden run --deep`): macOS Endpoint Security
  (eslogger) capture of the agent's process subtree — file opens, process execs,
  file creates — correlated by pid. Best-effort; needs sudo + Full Disk Access.
- **Linux enforcement backend** (bubblewrap), behind a platform-agnostic backend
  abstraction; `warden doctor` runs a live enforcement test on both platforms.
- **Strict filesystem mode** (`--strict` / `strict_fs`): deny all writes outside
  the allow-list.
- **Live approvals** (`on_violation: ask`): interactive allow-once / allow-always
  / deny for unlisted hosts, with per-session learning.
- Dashboard v2: risk scores and levels, host classification, deep-recording
  (files/processes) view, event timeline.
- Clean CLI error handling for malformed policies; bare session-id resolution for
  `report`/`verify`/`risk`/`gate`.

### Dynamic detonation harness
- `detonate/` — run untrusted MCP servers for real inside disposable Docker
  containers (unprivileged, no host mounts), capturing egress via DNS (tcpdump,
  app-agnostic so it catches Node `fetch` that ignores HTTP_PROXY) and Warden's
  proxy, across the whole container lifetime (so `npm postinstall` beacons are
  caught). Validated to flag a simulated exfil beacon; reputable servers read
  clean. See `detonate/README.md`.
- Fixed a Python 3.11 incompatibility in `scan_report.py` (a backslash inside an
  f-string expression — valid only on 3.12+, so the module failed to import on
  the 3.11 the project claims to support; tests had only run on 3.13).

### Security fixes (from adversarial review)
- Deep recorder now keys the process subtree on `(pid, pidversion)` with exit
  pruning, so a later process that reuses a pid is never mis-attributed to the
  agent.
- macOS: `**/.env.*` deny rules now match `.env.local` / `.env.production`
  (previously readable). Linux: `**/.env` is masked in the project tree instead
  of emitting a bogus glob path bwrap ignored; glob PATH entries are skipped.
- Proxy plain-HTTP relaying fixed (wrote to a raw socket). Seatbelt temp-file fd
  leak closed. Host classification: chat-webhook exfil hosts flagged, CDN
  content-hash hosts no longer false-positived, non-dotted IP encodings detected.

## [0.1.0] — unreleased

First working release. macOS.

### Added
- `warden run <agent|-- cmd>` — run an AI coding agent or any command under an
  OS-enforced least-privilege policy (macOS Seatbelt), with full egress recording.
- `warden record` — observe-only mode (no fs/process sandbox; egress still
  contained) for safely seeing what a skill does.
- `warden profile` — detonate a skill and generate a least-privilege policy from
  its observed egress, flagging unrecognized hosts for review.
- `warden dashboard` — read-only, loopback-only web dashboard: overview,
  sessions, per-session detail with egress verdicts and timeline, and behavioral
  drift ("rug-pull") detection.
- `warden doctor` — live self-test that proves enforcement actually works on the
  current machine, plus a signing round-trip and environment checks.
- `warden verify` — check a session's tamper-evident hash chain and Ed25519 seal
  signature (optionally against an expected public key).
- `warden report` — human-readable session receipt.
- `warden init` — scaffold a project `.warden.yaml`; auto-discovered by `run`.
- `warden agents` — list supported tools and which are installed.
- First-class agent baselines: claude, codex, cursor, copilot, gemini, aider, q,
  opencode, goose.
- Ed25519-signed, hash-chained session receipts (pure standard library;
  validated against RFC 8032 test vectors).
- Minimal-YAML/JSON policy format with deny-wins semantics and path
  canonicalization (resolves the macOS `/tmp`→`/private/tmp` alias trap).

### Known gaps
- Filesystem/process recording is denial-only (comprehensive capture needs the
  Endpoint Security framework). macOS only. See docs/LIMITATIONS.md.
