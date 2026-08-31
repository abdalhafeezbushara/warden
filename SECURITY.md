# Security Policy

## Reporting a vulnerability

Driftward is a security tool, so its own security matters. If you find a
vulnerability, please report it privately rather than opening a public issue.

- **GitHub private vulnerability reporting** — "Report a vulnerability" under the
  repository's **Security** tab. (Maintainers: enable this in Settings → Code
  security → Private vulnerability reporting.)

Please include a description, reproduction steps, and the impact. We aim to
acknowledge within a few days. This is a pre-1.0 project — if the private
advisory form is unavailable, open a minimal public issue that says only "security
report — please open a private channel" (no details), and a maintainer will
follow up privately.

## Scope and threat model

The full analysis — trust boundaries, adversary model, threat-by-threat
mitigations, and a residual-risk register — is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In brief, Driftward's job is to
contain and record an AI coding agent running on a developer machine. In scope:

- **Enforcement bypass** — any way a process under `driftward run` reads a denied
  path, execs a denied binary, or reaches the network off the recorded path.
- **Recording evasion** — egress that leaves the machine without a log entry.
- **Log forgery** — altering a session log without `driftward verify` detecting it,
  or forging a valid Ed25519 seal.
- **Dashboard** — anything that lets the read-only dashboard mutate state, read
  outside its asset directory, or reach the network.

Known and documented limits (not vulnerabilities) live in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md): filesystem *recording* is currently
denial-only, egress recording assumes proxy-honoring clients, and Driftward does
not inspect TLS payloads by design.

## What Driftward itself does

Driftward sends no telemetry and makes no Driftward-controlled outbound connections
(the remote-MCP bridge connects only to the endpoint you configure, on your
behalf). It has no runtime dependencies, and
stores everything locally under `~/.driftward`. The signing key at
`~/.driftward/signing.key` is created 0600 and never leaves the machine.
