# Security Policy

## Reporting a vulnerability

Warden is a security tool, so its own security matters. If you find a
vulnerability, please report it privately rather than opening a public issue.

- Use GitHub's private vulnerability reporting ("Report a vulnerability" under
  the Security tab), or
- email the maintainer listed in the repository.

Please include a description, reproduction steps, and the impact. We aim to
acknowledge within a few days.

## Scope and threat model

Warden's job is to contain and record an AI coding agent running on a developer
machine. In scope:

- **Enforcement bypass** — any way a process under `warden run` reads a denied
  path, execs a denied binary, or reaches the network off the recorded path.
- **Recording evasion** — egress that leaves the machine without a log entry.
- **Log forgery** — altering a session log without `warden verify` detecting it,
  or forging a valid Ed25519 seal.
- **Dashboard** — anything that lets the read-only dashboard mutate state, read
  outside its asset directory, or reach the network.

Known and documented limits (not vulnerabilities) live in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md): filesystem *recording* is currently
denial-only, egress recording assumes proxy-honoring clients, and Warden does
not inspect TLS payloads by design.

## What Warden itself does

Warden makes no outbound network connections, has no runtime dependencies, and
stores everything locally under `~/.warden`. The signing key at
`~/.warden/signing.key` is created 0600 and never leaves the machine.
