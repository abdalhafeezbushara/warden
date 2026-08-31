# Changelog

All notable changes to Warden are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); Warden uses semantic versioning.

## [0.2.0] — unreleased

Advanced capabilities on top of v0.1.

### Enforcement enhancements (turning documented limits into features)
- **Read confinement** (`--strict-read` / `strict_read`): deny the user's home
  except the read allow-list (project + agent config), keeping system paths
  readable. Verified live on Seatbelt — the agent runs but `~/Documents`, other
  repos, and browser data are blocked. Makes `filesystem.read` actually enforce.
- **Deep-recording startup race fixed:** `eslogger` now starts *before* the child
  with a readiness grace, buffering events until the child pid is known — so a
  short command's first fork/exec are captured, not lost to eslogger's ~1s
  startup.
- **Linux backend verified live** (privileged container): bubblewrap genuinely
  blocks a denied secret. `warden doctor` had a **false-pass bug** — it couldn't
  tell "enforcement blocked the read" from "the sandbox failed to start" (bwrap
  can't create namespaces on default Docker / hardened distros); now a canary
  proves the sandbox actually ran. When user namespaces are unavailable, `warden
  run` now fails closed with a clear, actionable message instead of silently
  running record-only. `--allow-record-fallback` is the explicit opt-in.

### Security hardening (from an independent audit)
- **Control-plane isolation:** the agent can no longer read Warden's signing key
  or session logs, nor write into `~/.warden` — that directory is denied in every
  policy and locked to `0700`. This restores the receipt trust boundary (a
  compromised agent previously could steal the key and forge/alter its receipts).
- **Environment scrubbing:** the child now gets only a safe env allow-list
  (system vars + the selected agent's registered provider keys +
  `policy.env_allow`). Arbitrary commands receive no provider credentials.
- **Network tightened:** egress is pinned to the recording proxy's single loopback
  port (not a blanket `localhost:*`), and Unix-domain sockets are denied — closing
  access to other local services, the SSH agent, and the Docker socket.
- **Proxy SSRF/rebinding defense:** destinations are resolved once; private,
  loopback, link-local, multicast, and reserved addresses are rejected and only
  the validated socket address is dialed. `network.allow_private` is an explicit
  escape hatch for intranet workflows.
- **`warden profile` confined:** now runs with `strict_fs` (writes limited to the
  work/tmp trees), `strict_read`, blocked-by-default egress, and a 60s timeout.
  Batch dynamic scans use the same posture. Fully untrusted skills should use
  the container detonation harness (`detonate/`).
- **Policy serialization fixed:** `strict_read`, `env_allow`, and
  `network.allow_private` now survive YAML round-trips.
- **GitHub Action** no longer masks the command's exit code with `|| true`.
- **`warden profile ./skill.sh`** now works (was parsed as an agent name).
- Docs corrected: honest "what it does/doesn't guarantee" section; fixed the
  inaccurate "egress still contained" record-mode wording; real repo URLs;
  reconciled test counts.

### Real-agent dogfooding (found and fixed by running the actual agents)
- **cursor-agent keychain auth:** `cursor-agent` stores its login session in the
  macOS Keychain, which Warden denied by default — so a logged-in user still got
  "Authentication required" under `warden run cursor` (and the failure was
  *opaque*, giving no hint Warden was the cause). Agents can now declare
  `keychain_auth`; cursor's baseline opens *exactly* `~/Library/Keychains/**`
  (every other secret — `~/.ssh`, `~/.aws`, `.env`, … — stays denied) and works
  under `--strict-read`/`--strict-fs`. New `warden run --deny-keychain` re-seals
  it (pair with `CURSOR_API_KEY`); `--allow-keychain` opens it for any run. The
  keychain state is now printed at launch and shown in `warden report`, so the
  grant is never invisible. Verified live: cursor authenticates and completes a
  task under full enforcement.
- **cursor dynamic egress:** cursor fans out across dynamic shards
  (`agentn.global.api5.cursor.sh` for agent inference, observed via the flight
  recorder) that the static allow-list missed and blocked. The baseline now
  allows its own domain by wildcard (`*.cursor.sh`) — still vendor-scoped. A task
  now runs clean end-to-end; cursor's optional `http://localhost/getRepositoryInfo`
  sidecar stays blocked by the private-address guard and the agent degrades
  gracefully — least privilege held, task succeeded.

### Added
- **Approved behavioral integrity:** versioned `warden.behavior/v1` manifests
  normalize network, process, filesystem, IPC, and credential capabilities;
  `warden baseline approve` creates an explicit Ed25519-signed trust point;
  `warden diff` reports explainable new/removed capabilities and identity or
  policy changes. First-run observations are never auto-learned, replacement
  requires `--force`, and tampered receipts/baselines are rejected. `warden diff`
  also refuses to certify a *non-intact observation*: a "stable" verdict read
  from a tampered session log is flagged and fails `--exit-code`, closing the
  anti-poisoning gap symmetric to approve-time receipt checking. Network
  capabilities collapse the port-bearing and port-less form of one destination,
  so a single host is never double-counted as drift.
- **Per-MCP-server identity** (`warden mcp`): each MCP server runs as its own
  confined principal (`mcp:<name>`) with its own least-privilege policy and its
  own signed behavioral baseline — so a rug-pull in one server is caught against
  *that server's* history instead of vanishing into the launching agent's noise.
  `warden mcp list` discovers servers across `.mcp.json`, `~/.claude.json`,
  `~/.cursor/mcp.json`, and VS Code configs; `warden mcp run <name>` runs one
  under its principal; `warden mcp wrap --config <file>` rewrites a config so the
  agent launches every stdio server through an **authenticated parent broker**
  (`--write` keeps a `.bak`, `unwrap` reverts). The broker snapshots exact server
  definitions before the agent starts and accepts only those — it cannot become a
  general process-launch escape — so there is no nested Warden inside the agent
  sandbox. A package/argument swap changes the definition digest, which both
  fails the launch closed and shows as high-severity identity drift. The
  underlying primitive is `warden run --subject <kind:name>`, so any process can
  be given its own behavioral principal.
  **Remote (`url`) servers are confined too.** `warden mcp run <name>` (and a
  wrapped remote server) runs a sandboxed stdio↔HTTP **bridge** as the
  `mcp:<name>` principal with egress locked to *only* the declared host — so a
  remote server's traffic is recorded under its own identity and a rug-pulled URL
  is blocked, not merely logged. The bridge speaks MCP Streamable HTTP (session
  header, JSON and SSE responses) **and** legacy two-endpoint HTTP+SSE
  (`transport: sse`); resolved auth headers are passed by value through a private
  env var, never argv or the log. An un-wrapped remote endpoint the agent calls
  directly is still allow-listed and recorded so it works under default-deny egress.
- **Signed community registry** (`warden registry`): share and adopt reviewed
  behavior baselines for popular MCP servers and skills as Ed25519-signed,
  offline-verifiable JSON entries — no network, no cloud. `warden registry
  publish <baseline>` signs a reviewed baseline as a shareable entry; `warden
  registry trust <key>` adds a publisher key to a deny-by-default trust store;
  `warden registry verify`/`list` check signatures and trust status; `warden
  registry install <name> --from <dir>` adopts a *trusted* entry, re-signing it
  as a local baseline (with provenance recording the original signer). A
  registry baseline is workspace-independent, so a community MCP-server profile
  drift-checks in any project. Trust is explicit: an unsigned or untrusted entry
  is never installed. Entries may also carry a reviewed least-privilege **policy**
  (`publish --policy`, `install --policy-out`). The repo ships a starter registry
  under [`registry/`](registry/) with a schema, contribution guide, trust-key
  doc, and signed seed entries.
- **Behavior-aware CI:** `warden gate --fail-on-new` can fail on all capability
  drift or selected categories (`network,process,filesystem,ipc,credential`).
- **Behavior dashboard:** a dedicated local view shows baseline coverage, an
  approved drift inbox, unapproved subjects, signature state, and per-session
  behavior evidence. The dashboard remains read-only and loopback-only.
- **Batch scan engine** (`warden scan`): point it at a corpus of skills / MCP
  servers and it reports what they actually do at scale — a static pass (network
  calls, credential-store access, prompt-injection patterns) combined with a
  time-boxed, blocked-egress run for semi-trusted code, aggregated into a shareable HTML/JSON
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
  per-agent observed-history fingerprints / anomaly hints. Explicit trusted
  baselines are now provided by the signed behavioral-integrity layer above.
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
- Dashboard security-console redesign: capability/posture summary, operational
  status metrics, searchable mode/risk filters, backend and environment evidence,
  deep/network event views, signed timeline, accessible responsive UI, and JSON
  export.
- Dashboard HTTP hardening: strict CSP/security headers and exact loopback Host
  validation prevent framing and browser DNS-rebinding access to local receipts.
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
  OS-enforced least-privilege policy (macOS Seatbelt), with proxy-observed egress.
- `warden record` — observe-only mode (no fs/process sandbox); records only
  proxy-honoring egress.
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
