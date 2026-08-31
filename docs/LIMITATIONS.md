# Limitations & roadmap

Warden is honest about what is enforced vs. recorded, and what is not yet built.
Overselling is the fastest way to lose the trust the tool exists to create.

## What works today (macOS, tested)

- **Filesystem enforcement** — denied paths (credentials, `.env`, keychains) are
  unreadable/unwritable under `warden run`, enforced by macOS Seatbelt.
- **Process enforcement** — denied binaries (`ssh`, `aws`, …) cannot be exec'd.
- **Network recording + enforcement** — every egress host is recorded; unlisted
  hosts are blocked (default-deny). HTTPS is tunneled, not decrypted.
- **Tamper-evident + signed receipts** — SHA-256 hash chain, sealed with an
  Ed25519 signature (`warden verify` checks both; validated against RFC 8032).
- **Skill profiling** — `warden profile` time-boxes a semi-trusted skill with
  strict read/write confinement and blocked-by-default egress, then generates a
  least-privilege policy from observed attempts. Unknown code belongs in
  `detonate/`, the disposable container harness.
- **Approved behavioral integrity** — versioned manifests normalize network,
  process, filesystem, IPC, and credential capabilities. Explicitly approved
  baselines are Ed25519-signed; diffs and CI gates reject unexplained additions.
- **Multi-agent** — first-class baselines for claude, codex, cursor, copilot,
  gemini, aider, q, opencode, goose; project `.warden.yaml` discovery.
- **Per-MCP-server principals** — `warden mcp run <name>` runs each MCP server as
  its own confined identity (`mcp:<name>`) with its own signed baseline and
  drift; `warden mcp wrap` routes an agent's whole MCP config through an
  authenticated parent broker. The broker snapshots exact definitions before
  the agent starts, so it cannot become a general sandbox escape. Configured env
  values are preserved without being logged, package/argument changes alter the
  behavioral identity, and MCP filesystem reads/writes are strict by default.
  Stdio servers are fully confined. A **remote (`url`) server is confined too**:
  a wrapped remote server (or `warden mcp run <name>`) runs a sandboxed stdio↔HTTP
  bridge as the `mcp:<name>` principal with **egress locked to only its declared
  host**, so its traffic is recorded under its own identity and a rug-pulled URL
  is *blocked*, not merely logged. The bridge speaks both MCP remote transports —
  Streamable HTTP (default) and legacy two-endpoint HTTP+SSE (`transport: sse` in
  the config). An *un*wrapped remote endpoint the agent calls
  directly is still allow-listed and recorded (not bridged), so it works under
  default-deny egress without silently reaching out.
- **Signed community registry** — `warden registry` shares and adopts reviewed
  behavior baselines for popular MCP servers/skills as Ed25519-signed, offline-
  verifiable JSON entries. Trust is deny-by-default: an entry is adopted only
  after its signer is in your trust store (`warden registry trust <key>`), and
  adopting re-signs a local baseline (with provenance) so drift and CI gates run
  against the community profile — across any workspace. No network, no cloud.
- **Self-test** — `warden doctor` performs a live enforcement test on the
  machine, so you can confirm the guarantees hold here.
- **Credential scoping** — named agents inherit only their registered provider
  variables; arbitrary commands get no provider credentials unless `env_allow`
  opts in.
- **Keychain-authenticated agents** — the macOS Keychain is denied by default
  (it holds every app's saved secrets). An agent that keeps its *own* login
  session there (`cursor-agent`) declares `keychain_auth`, and its baseline opens
  exactly `~/Library/Keychains/**` and nothing else — `~/.ssh`, `~/.aws`,
  `.env`, `.git-credentials`, etc. stay denied, egress stays allow-listed, and
  the env stays scrubbed, so the agent is still far below its unsandboxed
  privilege. The grant is printed at launch and shown in `warden report`. To keep
  the keychain sealed, authenticate with an API key (`CURSOR_API_KEY`) and pass
  `warden run --deny-keychain`.

## Known gaps (honest list)

0. **Filesystem reads are allow-by-default *unless* you pass `--strict-read`.**
   By default, reads are allowed except the credential deny-list and Warden's
   home (agent-compatibility default). Pass `--strict-read` (or `strict_read:
   true`) to confine reads to the `read` allow-list — the project, the agent's
   config/cache dirs, and system paths — denying the user's other data
   (`~/Documents`, other repos, browser profiles). Verified live on Seatbelt: the
   agent still runs, but private home data is blocked. **This is an advanced,
   opt-in mode that needs per-agent read tuning** — real agents installed under
   `$HOME` (npm global, node scripts) and their config/cache paths must be in the
   `read` list or the agent won't launch. The runner auto-allows the agent's own
   binary + package tree; a complex agent may still stat other paths. Dogfood the
   specific agent under `--strict-read` and add what it needs. The default
   (non-strict) mode is the recommended posture for real-agent use.

1. **Deep recording needs Full Disk Access (and sudo).** `warden run --deep`
   captures comprehensive file/process activity via macOS `eslogger`, which
   requires the **terminal to have Full Disk Access** (a one-time System Settings
   grant — TCC will not let code grant it) and `sudo`. When those aren't present,
   `--deep` degrades to no deep events with a clear message; normal egress
   recording and enforcement are unaffected. The parser and pid-correlation are
   unit-tested against the real ES schema; the live capture path is thin.
2. **eslogger has no network events.** Endpoint Security exposes only UNIX-socket
   connects, not IP/DNS — so network recording is (and must be) the egress
   proxy's job. The two are complementary by design.
3. **Egress recording assumes proxy-honoring clients.** On macOS, Seatbelt pins
   egress to loopback so direct sockets fail closed. On Linux, v0.2 uses
   `HTTP_PROXY` (proxy reachable); a hard netns+socat pin is the documented next
   step. A client that neither honors the proxy nor errors could be
   under-recorded on Linux until then.
4. **Linux enforcement needs bubblewrap + user namespaces.** Where a hardened
   distro disables unprivileged userns (e.g. Ubuntu's AppArmor restriction),
   bwrap fails. `warden run` now refuses to start the child; use
   `--allow-record-fallback` only when an explicit proxy-only fallback is
   acceptable.
5. **No TLS interior.** Warden records *which host*, not payloads — a deliberate
   no-MITM choice. Content DLP is out of scope for the OSS core.
6. **Signing key is per-machine and local.** Good for local integrity and
   single-owner attribution; a shared-team trust root is future work.
7. **Deep recording is optional observability, not enforcement.** Capture now
   starts before the child and buffers until its pid is attached, closing the
   earlier startup race. It still depends on `eslogger`/TCC availability and can
   produce high-volume logs when every file open is requested.
8. **Linux binary-deny is best-effort.** Denied binaries are masked at their PATH
   locations; a copy dropped into the project tree or reached by an absolute path
   outside PATH is not masked (the macOS Seatbelt backend denies by basename
   regardless of location). Egress from any such binary is still proxy-recorded,
   and strict-fs limits where it can be written.
9. **Private destinations are denied by default.** The proxy resolves a host
   once, rejects non-public addresses, and dials only a validated address. Tools
   that intentionally call an intranet or local service must opt in with
   `network.allow_private: true`; doing so expands the SSRF/local-service risk.
10. **Behavior coverage depends on available telemetry.** Network attempts are
    hard-pinned to the proxy on macOS but best-effort on the current Linux
    backend. Filesystem/process drift requires `--deep`; without it, the
    manifest marks deep coverage false rather than claiming that no such
    activity occurred. Baselines are scoped to subject + workspace to avoid one
    repository teaching capabilities to another.
11. **The MCP broker must know custom config paths before launch.** Project and
    standard Claude/Cursor/VS Code/Windsurf locations are discovered
    automatically. For any other wrapped config, pass repeatable
    `warden run --mcp-config path/to/mcp.json ...`; an unregistered definition
    fails closed. MCP config backups retain the source file's permissions.

## Roadmap

- Harden Linux egress with a network-namespace proxy pin.
- Handle unsolicited server-initiated GET streams in the remote MCP bridge (both
  Streamable HTTP and legacy HTTP+SSE request/response are confined today).
- Grow the reviewed-baseline registry format into a curated public registry repo,
  and add policy entries alongside behavior baselines (the signing/trust/adopt
  machinery ships today via `warden registry`).
- Add team policy inheritance and shared organizational trust roots.
- Add Windows enforcement and shared organizational trust roots.
