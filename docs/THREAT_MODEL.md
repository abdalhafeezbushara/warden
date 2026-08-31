# Driftward threat model

This document states precisely what Driftward defends, against whom, and where the
defense ends. It is written to be falsifiable: every guarantee names the
mechanism that enforces it and the residual risk it leaves. If you find a gap
that is not listed here, that is a bug — see [SECURITY.md](../SECURITY.md).

Driftward's one-line claim is deliberately modest: **a transparent local wrapper
that contains and records an AI coding agent.** It is a strong guardrail and an
honest flight recorder for a *trusted-to-semi-trusted* agent — not a hardened
sandbox for arbitrary malware. This model exists to make that boundary exact.

---

## 1. System overview

Driftward runs an AI coding agent as a **child process** under an OS-enforced
policy, mediates its network through a **loopback recording proxy**, and writes
a **signed, tamper-evident log**. Nothing leaves the machine.

For wrapped local MCP servers, the trusted parent also owns an authenticated
loopback broker. It snapshots exact definitions before the agent starts and
launches approved servers as sibling Driftward sessions, not descendants of the
agent sandbox. The agent receives a per-run token but cannot ask the broker to
launch an unregistered command, argument list, or config source. Each server is
therefore confined and recorded under its own `mcp:<name>` principal while the
agent remains unable to read `~/.driftward`.

```
        ┌──────────────────────────── developer machine (single owner) ────────────────────────────┐
        │                                                                                            │
        │   user (trusted)                                                                           │
        │        │ invokes                                                                           │
        │        ▼                                                                                   │
        │   ┌──────────┐    compiles policy    ┌───────────────────┐                                 │
        │   │  driftward  │──────────────────────▶│ Seatbelt / bwrap  │                                 │
        │   │ (parent) │                        │  OS sandbox       │                                 │
        │   └────┬─────┘                        └─────────┬─────────┘                                 │
        │        │ spawns child in sandbox                │ confines                                  │
        │        │ scrubbed env + HTTP(S)_PROXY           ▼                                           │
        │        │                            ╔═══════════════════════╗   file reads/writes          │
        │        │                            ║  AGENT  (semi-trusted, ║──────────────┐               │
        │        │                            ║  may be prompt-        ║              ▼               │
        │        │                            ║  injected)            ║   ┌────────────────────────┐  │
        │        │                            ╚═══════╤═══════════════╝   │ filesystem              │  │
        │        │                                    │ all egress        │  deny: secrets, ~/.driftward│ │
        │        │              ┌─────────────────────┘ (loopback pin)    │  (strict-read optional) │  │
        │        ▼              ▼                                         └────────────────────────┘  │
        │   ┌─────────────────────────┐  allow-list + SSRF guard    ══════════════▶ internet         │
        │   │  recording proxy        │─────────────────────────────────────────▶ (allow-listed      │
        │   │  (127.0.0.1:PORT)       │  resolve-once, reject private              hosts only)        │
        │   └───────────┬─────────────┘                                                              │
        │               │ every request/verdict                                                      │
        │               ▼                                                                            │
        │   ┌─────────────────────────┐   Ed25519 seal over SHA-256 hash chain                       │
        │   │ ~/.driftward (0700)        │◀── signing key (0600) ── DENIED to the agent                 │
        │   │  session logs, key      │                                                              │
        │   └─────────────────────────┘                                                              │
        └────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Double lines** mark the primary trust boundary: everything the agent does
crosses an enforcement point (the OS sandbox for filesystem/process/socket, the
proxy for egress) before it reaches an asset.

### Components (principals)

| Principal | Trust | Notes |
|---|---|---|
| **User** | Trusted | Owns the machine, writes the policy, invokes Driftward. |
| **Driftward parent** (`driftward run`) | Trusted (TCB) | Compiles the policy, owns the signing key and logs. |
| **OS sandbox** (Seatbelt / bubblewrap) | Trusted (relied upon) | The kernel-level enforcement primitive. |
| **Recording proxy** | Trusted (TCB) | In-process; sees plaintext HTTP metadata, tunnels HTTPS. |
| **MCP launch broker** | Trusted (TCB) | Parent-owned; exact pre-launch allow-list, token-authenticated, stdio only. |
| **Agent** (Claude Code, cursor-agent, …) | **Semi-trusted** | Assumed possibly prompt-injected or misbehaving; the thing being contained. |
| **Reviewed MCP server** | **Semi-trusted** | Runs in a separate strict Driftward session; genuinely unknown code still belongs in `detonate/`. |
| **Unknown skill / MCP server** | **Untrusted** | Arbitrary third-party code; belongs in `detonate/`, not a host run. |
| **Remote model/provider API** | External | Reached only through the allow-listed, recorded proxy path. |

---

## 2. Assets

What Driftward exists to protect, roughly in priority order:

1. **On-disk credentials** — `~/.ssh`, `~/.aws`, `~/.gnupg`, cloud/kube configs,
   `.env` files, `.git-credentials`, `.npmrc`, and the macOS Keychain.
2. **Shell-environment secrets** — `AWS_*`, `GITHUB_TOKEN`, database URLs, and
   any other credential exported in the invoking shell.
3. **The network as an exfiltration channel** — the agent should reach only
   declared hosts, and every destination it reaches should be recorded.
4. **Driftward's integrity root** — the Ed25519 signing key and the session logs.
   If these fall, the receipts mean nothing.
5. **The user's other data** — `~/Documents`, unrelated repositories, browser
   profiles (protected only under the opt-in `--strict-read`).

---

## 3. Adversary model

### In scope

- **A1 — A prompt-injected or misaligned agent.** The primary adversary. It can
  run arbitrary code *with the user's own UID* inside the sandbox, and will try
  to read secrets, exfiltrate data, exec forbidden tools, or tamper with its own
  audit trail. It is **not** assumed to have a kernel or sandbox 0-day.
- **A2 — A malicious skill / MCP server the agent executes.** A wrapped stdio
  MCP server gets a separate strict host sandbox and identity, rather than the
  agent's privileges. Driftward's answer for *genuinely* untrusted code remains the
  container harness (§7, F1), not a host run; remote MCP transport confinement
  is not yet implemented.
- **A3 — A network adversary** (passive or active MITM) on the path to the
  provider. Driftward relies on TLS for confidentiality/integrity and records the
  *destination*, not the payload.

### Out of scope (assumptions)

- **Root / kernel-level attacker.** Anyone who is already root, can load kernel
  code, or has a Seatbelt/bubblewrap escape is out of scope — the enforcement
  primitive is part of the TCB (§8).
- **A malicious Driftward build or its (zero) dependencies.** Supply-chain
  integrity of Driftward itself is assumed; Driftward has no runtime dependencies to
  reduce this surface, but the assumption stands.
- **A hostile local co-tenant.** Driftward is a single-owner tool. File permissions
  (`~/.driftward` 0700, key 0600) are the only barrier; a second interactive user
  with equal privileges, or another process running as the same UID *outside*
  `driftward run`, is not contained (§6, C3).
- **Physical access, side channels, speculative execution, TLS-breaking
  adversaries.**

---

## 4. Threats and mitigations

Organized by Driftward's four in-scope categories (per SECURITY.md) plus
control-plane/credential threats. Each entry: **vector → mitigation → residual
risk.**

### A. Enforcement bypass — the agent reaches a denied resource

- **A1. Read a credential store** (`cat ~/.ssh/id_rsa`).
  *Mitigation:* Seatbelt emits `(deny file-read* file-write* …)` for every
  secret path, **canonicalized with `realpath`** first so the `/tmp→/private/tmp`,
  `/etc→/private/etc`, `/var→/private/var` symlink aliases can't be used to slip
  past a rule. Deny always wins over allow.
  *Residual:* outside the deny-list, reads are **allow-by-default** (agent
  compatibility) unless the user opts into `--strict-read`, which denies the
  whole home and re-allows only the read-list. Documented in LIMITATIONS §0.

- **A2. Exec a forbidden binary** (`ssh`, `aws`, `kubectl`).
  *Mitigation:* macOS denies `process-exec*` by **basename anywhere** via regex,
  so a copy or an absolute path outside `PATH` is still denied.
  *Residual:* the Linux backend masks denied binaries at their `PATH` locations
  only; a binary copied into the project tree or reached by an absolute path off
  `PATH` is not masked (LIMITATIONS §8). Egress from any such binary is still
  proxy-recorded.

- **A3. Open a direct socket, bypassing the proxy.**
  *Mitigation:* on macOS the profile is `(deny network-outbound)` with a single
  re-allow of `localhost:PORT` — the proxy's port and nothing else. A direct
  socket to an external IP **fails closed**; it cannot leave unrecorded because
  it cannot leave at all.
  *Residual:* on **Linux**, v0.2 pins egress via `HTTP_PROXY`, not a network
  namespace. A client that neither honors the proxy nor errors could reach the
  network directly there (LIMITATIONS §3; roadmap: netns pin). This is the single
  most important open gap.

- **A4. Reach another local service** (a Postgres on 5432, the Docker socket, the
  SSH agent's Unix socket).
  *Mitigation:* the loopback re-allow is pinned to the proxy port, **not** a
  blanket `localhost:*`, and **Unix-domain sockets are denied outright**. Other
  local services are unreachable.
  *Residual:* if the user sets `network.allow_private: true` for an intranet
  workflow, this protection is relaxed by their explicit choice.

- **A5. Escape confinement via a child/helper process.**
  *Mitigation:* the Seatbelt/bwrap policy applies to the whole process subtree;
  children inherit it. Deep recording tracks the subtree by `(pid, pidversion)`
  to survive PID reuse.
  *Residual:* none within the sandbox model; a kernel-level escape is out of
  scope (§3).

### B. Recording evasion — egress leaves without a log entry

- **B1. Use an HTTP client that ignores `HTTP(S)_PROXY`** (e.g. Node's default
  agent).
  *Mitigation:* on macOS the Seatbelt loopback pin (A3) means such a client's
  direct socket **fails** rather than leaking — the attempt is a blocked
  connection, not a silent exfil. Recording is therefore complete *because*
  non-proxy egress is impossible.
  *Residual:* on Linux, per A3, a non-cooperating client can currently bypass
  both the proxy and the record. **This is the headline honest limitation** and
  is stated wherever Linux is discussed.

- **B2. Exfiltrate over DNS** (encode data in lookups to an attacker resolver).
  *Mitigation:* the proxy performs name resolution for the agent; the agent's own
  outbound UDP/TCP to an arbitrary resolver is denied by the macOS loopback pin.
  *Residual:* DNS to the system resolver for allow-listed hostnames is normal and
  not payload-inspected; low-bandwidth covert channels are out of scope (B3).

- **B3. Covert / timing channels, payload steganography.**
  *Mitigation:* none attempted — Driftward records *which host*, not payloads, by
  design (no TLS MITM).
  *Residual:* accepted. Content DLP is explicitly out of scope for the OSS core.

### C. Log forgery / tamper — break the receipt

- **C1. Alter or delete a past log entry.**
  *Mitigation:* each record is chained by SHA-256 over the previous; `driftward
  verify` recomputes the chain and detects any edit, insertion, or truncation
  before the seal.
  *Residual:* none for detection; Driftward proves *that* tampering occurred, not
  who did it.

- **C2. Forge a valid seal on a doctored log.**
  *Mitigation:* the log is sealed with an Ed25519 signature over the chain head
  (implementation RFC 8032-validated). Forging it requires the private key.
  *Residual:* reduces to key custody (C3).

- **C3. Steal the signing key to sign forgeries.**
  *Mitigation:* the key lives in `~/.driftward` (chmod **0700** dir, **0600** key)
  and that directory is injected into the **deny-list of every policy**, so the
  agent under `driftward run` cannot read it — closing the loop where a contained
  agent could forge its own receipts.
  *Residual:* a process running as the same user **outside** `driftward run` can
  read the key. Driftward protects what runs *under* it; whole-machine compromise or
  a hostile co-tenant is out of scope (§3). Per-machine key; a shared-team trust
  root is future work (LIMITATIONS §6).

- **C4. Suppress the recorder — kill Driftward mid-session.**
  *Mitigation:* the agent is a child of the Driftward parent; killing the parent
  ends the agent's session. An interrupted session is sealed as `interrupted`
  and still verifies up to its last record; a session that never sealed is
  visibly unsealed.
  *Residual:* an attacker who is already root can of course stop any process;
  that is out of scope.

### D. Control-plane and credential threats

- **D1. Harvest shell-environment secrets** (`AWS_SECRET_ACCESS_KEY`,
  `GITHUB_TOKEN`, DB URLs exported in the invoking shell).
  *Mitigation:* the child environment is **scrubbed to an allow-list** — a safe
  base set, plus *only the selected agent's* registered provider keys, plus
  `policy.env_allow`. Arbitrary commands get no provider credentials. `DRIFTWARD_*`
  control variables never pass to the child. Scrubbed names are recorded.
  *Residual:* a key the user deliberately allow-lists (`env_allow`) is, by
  definition, passed through.

- **D2. Over-read the macOS Keychain via a keychain-authenticated agent.**
  *Context:* `cursor-agent` stores its own login session in the Keychain, so its
  baseline opens exactly `~/Library/Keychains/**` (all other secret paths stay
  denied) — otherwise the agent cannot authenticate at all.
  *Mitigation:* keychain access is **off by default**, opened only for an agent
  that declares `keychain_auth`, surfaced at launch and in `driftward report`, and
  re-sealable with `--deny-keychain` (pair with an API key). Even opened, the
  agent is far below its unsandboxed privilege (egress allow-listed, other
  secrets denied, env scrubbed).
  *Residual:* an opened keychain lets that agent read login-keychain items whose
  ACL is "allow all applications." Signature-bound items belonging to other apps
  remain gated by `securityd`. Users wanting zero keychain exposure use
  `CURSOR_API_KEY` + `--deny-keychain`.

- **D3. SSRF / DNS-rebinding through the proxy** (allow-list a public host, then
  resolve it to `169.254.169.254` or `127.0.0.1` to hit cloud metadata or a
  local service).
  *Mitigation:* the proxy **resolves once**, rejects loopback/private/link-local/
  reserved/multicast/`::1` addresses, and dials **only the validated address** —
  so a name that resolves public-then-private cannot be re-pointed after the
  check.
  *Residual:* relaxed only by the explicit `network.allow_private` opt-in.

- **D4. Policy confusion — a user policy that is accidentally over-permissive.**
  *Mitigation:* deny-wins semantics; secret paths are denied in every default
  policy; the agent's own provider egress is unioned in so a strict project file
  can't silently break (and thereby tempt the user to disable) the agent.
  *Residual:* a user can always write a deliberately loose policy; Driftward makes
  the effective policy inspectable with `driftward policy show|sbpl`.

### E. Dashboard and ancillary surfaces

- **E1. The local dashboard mutates state, reads outside its assets, or reaches
  the network.**
  *Mitigation:* the dashboard is read-only, serves from a fixed asset directory,
  and makes no outbound connections.
  *Residual:* it renders recorded session data; treat it as you would any local
  viewer of untrusted strings (hosts, argv) — rendering is escaped.

---

## 5. Security guarantees vs non-guarantees

**Driftward guarantees (under `driftward run`, macOS Seatbelt):**

- Credential stores in the deny-list, and Driftward's own key/logs, are unreadable
  by the agent.
- Egress is pinned to the recording proxy — a direct socket to the outside fails
  closed, so recorded egress is complete on this platform.
- Denied binaries cannot exec (by basename, anywhere).
- Environment credentials are scoped to the selected agent.
- Any post-hoc edit to a session log is detected; a valid seal requires the local
  private key, which the contained agent cannot read.

**Driftward does *not* guarantee:**

- Confinement of filesystem **reads** outside the deny-list, unless
  `--strict-read` is set.
- Complete egress **recording on Linux** against a client that ignores the proxy
  (macOS is complete via the socket pin; Linux is the open gap).
- Any protection in `driftward record` mode — that mode records proxy-honoring
  clients and does **not** sandbox.
- Containment of **genuinely untrusted code** on the host — use `detonate/`.
- Payload-level DLP, or defense against a kernel/root-level adversary.

---

## 6. Platform notes

- **macOS (Seatbelt / `sandbox-exec`)** is the reference backend: allow-default,
  deny-the-dangerous, with realpath canonicalization and a hard loopback egress
  pin. This is where the guarantees above hold and are covered by the live
  `driftward doctor` self-test.
- **Linux (bubblewrap)** enforces filesystem/process confinement when
  unprivileged user namespaces are available; when they are not (default Docker,
  some hardened distros), `driftward run` **fails closed** with actionable guidance
  rather than silently running unprotected. Egress is proxy-pinned via env, not a
  netns — the documented gap of §A3/B1. `driftward doctor` uses a canary write to
  prove the sandbox actually ran (not a false pass on a namespace failure).

---

## 7. Untrusted-code detonation (`detonate/`)

For code you do **not** trust at all — an unknown skill, an unvetted MCP server —
host `driftward run`/`driftward profile` is the wrong tool. Use the container harness:

- **F1. Container escape.** The harness runs the code in an **unprivileged
  container with no host mounts**, capturing egress via both the proxy and
  tcpdump/DNS (app-agnostic, so it catches a Node client that ignores the proxy,
  and `postinstall` beacons across the whole container lifetime).
  *Residual:* a single container boundary is strong but not absolute; a container
  0-day is out of scope, and the harness is for *analysis*, not for safely
  running hostile code in production.

---

## 8. Trusted computing base and assumptions

Driftward's correctness depends on:

- The **OS sandbox primitive** (Seatbelt on macOS, bubblewrap + user namespaces
  on Linux) enforcing the compiled profile faithfully.
- The **kernel and `securityd`** not being already compromised.
- **TLS** providing confidentiality and integrity to allow-listed endpoints
  (Driftward does not MITM).
- **Standard filesystem permissions** protecting `~/.driftward` from other local
  users, and no other process running as the same UID outside `driftward run` being
  hostile.
- The **Python standard library and the `driftward` code itself** being intact
  (no runtime third-party dependencies by design).

If any of these assumptions is false, the corresponding guarantees do not hold.

---

## 9. Residual-risk register

| ID | Risk | Severity | Status |
|----|------|----------|--------|
| A1r | Reads outside the deny-list allowed unless `--strict-read` | Medium | By design; opt-in confinement shipped |
| A3r/B1r | Linux egress bypass by a non-proxy client (no netns pin) | **High** | Open — roadmap: network-namespace pin |
| A2r | Denied-binary masking is PATH-only on Linux | Low | Documented; macOS denies by basename |
| C3r | Signing key readable by same-UID processes outside `driftward run` | Medium | Single-owner assumption; team trust root is future work |
| D2r | Keychain-auth agent can read "allow-all-ACL" login items | Low–Medium | Off by default; `--deny-keychain` + API key seals it |
| B3r | Covert/timing channels, payload steganography | Low | Out of scope (no payload inspection) |
| F1r | Container detonation is one boundary, not absolute | Medium | Use for analysis, not production isolation |

---

*Report a suspected bypass privately — see [SECURITY.md](../SECURITY.md). Known,
documented limits live in [docs/LIMITATIONS.md](LIMITATIONS.md); this model and
that list are kept in sync.*
