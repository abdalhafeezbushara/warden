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
- **Skill profiling** — `warden profile` detonates a skill safely and generates
  a least-privilege policy from observed egress, flagging unrecognized hosts.
- **Behavioral drift detection** — the dashboard flags a skill that contacts a
  host in a later run it never contacted before (rug-pull detection).
- **Multi-agent** — first-class baselines for claude, codex, cursor, copilot,
  gemini, aider, q, opencode, goose; project `.warden.yaml` discovery.
- **Self-test** — `warden doctor` performs a live enforcement test on the
  machine, so you can confirm the guarantees hold here.

## Known gaps (honest list)

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
   bwrap fails and Warden degrades to record-only with a clear message rather
   than a false sense of enforcement.
5. **No TLS interior.** Warden records *which host*, not payloads — a deliberate
   no-MITM choice. Content DLP is out of scope for the OSS core.
6. **Signing key is per-machine and local.** Good for local integrity and
   single-owner attribution; a shared-team trust root is future work.
7. **Deep recording has a startup window.** `eslogger` capture starts just after
   the child launches (and has sudo/ES setup latency), so a fork/exec the agent
   does in the very first moments may be missed. The root process and everything
   after the window are tracked precisely (by pid+pidversion, with exit pruning
   so a reused pid is never mis-attributed).
8. **Linux binary-deny is best-effort.** Denied binaries are masked at their PATH
   locations; a copy dropped into the project tree or reached by an absolute path
   outside PATH is not masked (the macOS Seatbelt backend denies by basename
   regardless of location). Egress from any such binary is still proxy-recorded,
   and strict-fs limits where it can be written.

## Roadmap

- **v0.2** — Endpoint Security recorder (full fs/process/socket capture).
- **v0.3** — Linux enforcement backend; GitHub Action; pre-commit hook.
- **v0.4** — community policy registry (`policies/skills/*.yaml`) for popular
  skills and MCP servers; live human-in-the-loop approvals.
- **v1.0** — org-level policy distribution, shared trust roots, marquee-adopter
  trophy case.
