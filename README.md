# Driftward

> Behavioral integrity, least privilege, and a flight recorder for AI coding agents.

Your AI coding agent runs with **your** account. It can read `~/.ssh`, your
cloud credentials, and every `.env` on disk — and any skill, MCP server, or
tool it loads inherits that reach. In 2025–2026 that stopped being theoretical:
agents have deleted production databases, and poisoned skills and packages have
turned developers' own agents into credential-exfiltration tools.

Driftward puts a boundary around the agent:

- **Record** everything it does to the network — to a tamper-evident log.
- **Enforce** what it may touch — real OS-level sandboxing, not a prompt asking nicely.
- **Prove** what happened — an integrity-checked receipt for incident response and review.
- **Diff** what changed — compare capabilities with an explicitly approved,
  signed baseline; observations never become trusted automatically.

It is local-first and dependency-free (Python standard library only). Driftward
sends no telemetry of its own; wrapped processes can connect only to destinations
allowed by their policy, including configured remote MCP endpoints.

> **Status: v0.2 (hardening release).** Enforcement (macOS Seatbelt / Linux
> bubblewrap), proxy-observed egress, Ed25519-signed receipts, behavioral risk
> scoring, skill profiling, live approvals, and comprehensive file/process
> recording (macOS eslogger) work today and are covered by the test suite.

## What Driftward does — and doesn't — guarantee

Driftward is a **transparent local wrapper that contains and records** an AI coding
agent. Be clear-eyed about the boundary:

- **Enforced under `driftward run` (macOS Seatbelt):** credential stores and Driftward's
  own key/logs are unreadable; egress is pinned to the recording proxy (a single
  loopback port — other local services and Unix sockets are closed); denied
  binaries can't exec; environment credentials are scoped to the selected agent
  (arbitrary commands receive no provider keys unless policy explicitly opts in).
- **Best-effort / not yet contained:** filesystem *reads* are allow-by-default
  minus the deny-list (not a read allow-list), matching how agent sandboxes stay
  compatible; `driftward record` (no `--run`) does **not** sandbox — it records only
  proxy-honoring clients; the Linux backend pins egress via `HTTP_PROXY`, not a
  network namespace, so a non-cooperating client can bypass it there.
- **For genuinely untrusted skills, use the container detonation harness**
  (`detonate/`), not host-based `driftward run`/`driftward profile`. A single container
  boundary is strong but not absolute.

In short: a solid guardrail for trusted-to-semi-trusted agents and a real
recording/receipt layer — **not** a hardened sandbox for arbitrary malware. See
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full list and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the trust boundaries, adversary
model, and residual-risk register.

---

## Install

```bash
pip install .        # from a clone; PyPI/Homebrew to follow
driftward doctor        # proves enforcement actually works on your machine
```

No dependencies — just Python 3.11+. During development, `python3 -m driftward …`
works without installing.

## Quickstart

Driftward knows the major AI coding tools by name and gives each a least-privilege
baseline (its provider hosts + common developer registries, credential paths
denied, and only that agent's provider environment variables inherited):

```bash
driftward agents              # list supported tools, show which are installed
driftward run claude          # run Claude Code, enforced + recorded
driftward record cursor       # observe only — records proxy-honoring egress; NO OS sandbox
driftward report              # what did the last session do?
driftward verify              # is the receipt intact and correctly signed?
driftward behavior            # portable capability manifest for the last run
driftward baseline approve    # explicitly sign that behavior as trusted
driftward diff                # show new capabilities since approval
driftward mcp list            # discover MCP servers; run each as its own principal
driftward dashboard           # open the local session dashboard
```

Each MCP server can be run as its **own** confined, baselined principal — so a
rug-pull in one server is caught against that server's history, not lost in the
agent's:

```bash
driftward mcp list                       # discover configured servers
driftward mcp run github                 # run one as principal mcp:github
driftward mcp wrap --config .mcp.json --write  # route every local server through Driftward
driftward run claude                     # standard wrapped configs are registered automatically
# custom config outside the standard locations:
driftward run --mcp-config path/mcp.json claude
```

Remote (`url`) servers are confined too: Driftward runs a sandboxed stdio↔HTTP
bridge as the server's principal with egress locked to *only* its declared host,
so a rug-pulled URL is blocked, not merely logged (MCP Streamable HTTP transport).

Wrapped servers use an authenticated, parent-owned broker rather than nesting
Driftward inside the agent sandbox. Before the agent starts, the broker snapshots
each exact command, argument list, and environment-variable name. The agent can
launch only those registered definitions; each launch gets strict read/write
confinement, configured environment values, an independent signed session, and
a definition digest that flags package or argument swaps as identity drift.
Remote (`url`) servers are confined through a sandboxed, egress-locked bridge
(both MCP remote transports: Streamable HTTP and legacy two-endpoint SSE).

Supported today: **claude, codex, cursor, copilot, gemini, aider, q, opencode,
goose** — plus any command via `driftward run -- <command>`.

## Share reviewed baselines (signed community registry)

Approving a baseline is per-machine work, but everyone runs the same popular
servers. `driftward registry` shares that review — verifiably. Entries are
Ed25519-signed JSON; trust is deny-by-default.

```bash
driftward registry publish mcp:github --out github.json --reviewer you   # sign your reviewed baseline
driftward registry trust <publisher-key>                                 # trust a reviewer you vetted
driftward registry verify ./community-registry/                          # check signatures + trust
driftward registry install github --from ./community-registry/           # adopt a trusted entry
```

Installing re-signs a local baseline (with provenance), so drift and CI gates run
against the community profile in **any** project. No network, no cloud — a
registry is just a directory of signed files you obtain however you like.

Pass agent flags after `--`, or override the baseline with a policy:

```bash
driftward run claude -- --resume
driftward run --policy team.yaml codex
driftward init claude         # scaffold a project .driftward.yaml (auto-discovered by run)
```

## Scan a whole corpus of skills

Point Driftward at a directory of skills / MCP servers and it reports what they
*actually do*, at scale — combining a static pass (network calls, credential
access, prompt-injection patterns in `SKILL.md`) with a time-boxed host-based run
using strict read/write confinement and blocked-by-default egress:

```bash
driftward scan examples/skill-corpus --html finding.html
```

```
DRIFTWARD SCAN — 3 skills
   33.3%  contacted an UNDISCLOSED host
   33.3%  contain injection patterns (static)
  Highest-risk skills:
     36 medium   sneaky-tracker  beacon.undisclosed-analytics.example
      0 none     poisoned-helper  override-instructions, hide-from-user
```

`--html` writes a shareable finding page. This is the honest answer to the
supply-chain problem static scanners can't solve alone: watch what a skill *does*,
then compare it to what it *declared*.

Dynamic scanning is intended for semi-trusted code; use `--static-only` or the
disposable `detonate/` container harness for unknown code. `--allow-egress` is an
explicit opt-in that permits real outbound connections for a fuller run.

## Vet a single unknown skill before you trust it

```bash
driftward profile ./some-skill.sh
```

Driftward runs the skill once with strict read/write confinement and egress blocked
by default, records every host it *tries* to reach, flags the ones it doesn't
recognize, and prints a least-privilege policy for you to review. This remains a
host sandbox for semi-trusted code; use `detonate/` for unknown code.

```
PROFILE REVIEW — hosts this skill contacted
UNRECOGNIZED — review before trusting:
  ??   evil-collector.example-attacker.com   <-- not a known host; remove if unexpected
```

## See it catch a malicious skill

The repo ships a stand-in "malicious skill" that does a little real work, then
tries to steal a credential and phone home:

```bash
# 1. set up a fake secret + project
mkdir -p /private/tmp/driftward-demo/secrets /private/tmp/driftward-demo/project
echo 'sk-live-DEADBEEF-secret' > /private/tmp/driftward-demo/secrets/api_key.txt

# 2. run it under Driftward
python3 -m driftward run --policy examples/demo.policy.yaml -- sh examples/malicious-skill.sh

# 3. read the receipt
python3 -m driftward report
```

```
╭─ Driftward flight report ─────────────────────────────────
│ command : sh examples/malicious-skill.sh
│ policy  : demo   mode: ENFORCE (filesystem + process + egress contained)
│ exit    : 0   duration: 0.50s
│ integrity: OK intact (tamper-evident chain verified)
╰────────────────────────────────────────────────────────

NETWORK EGRESS  (1 allowed, 1 blocked)
  ✓ allow  example.com
  ✗ BLOCK  evil-collector.example-attacker.com   ← denied: host not in allow-list

⚠  Driftward blocked 1 undisclosed egress destination(s).
```

The credential read is blocked by the OS sandbox; the exfiltration host is
blocked **and recorded**; the one legitimate host still works.

## Policies

A policy is a small declarative file (a minimal YAML subset, or JSON — no
dependencies). Deny always wins; unlisted hosts are denied by default.

```yaml
name: my-project
filesystem:
  read:  ["./", "~/.gitconfig"]
  write: ["./", "/tmp/**"]
  deny:  ["~/.ssh/**", "~/.aws/**", "**/.env"]
network:
  allow: ["api.anthropic.com", "github.com", "registry.npmjs.org"]
  allow_private: false
  deny_all_other: true
process:
  deny:  ["ssh", "aws", "kubectl"]
on_violation: block+receipt
```

The default policy (no `--policy` flag) already denies the common credential
stores and allow-lists the hosts a coding agent normally needs. Inspect what
will be enforced:

```bash
python3 -m driftward policy show     # the effective policy, as JSON
python3 -m driftward policy sbpl     # the compiled macOS sandbox profile
```

## How it works

```
                 ┌─────────────────────────────────────────┐
   your policy → │ Driftward                                   │
                 │  • compiles a macOS Seatbelt profile     │  OS-enforced:
   driftward run  → │  • starts a loopback egress proxy        │  fs + process
                 │  • runs the agent as a child             │
                 └───────────────┬─────────────────────────┘
                                 │ HTTP(S)_PROXY, sandbox-exec
                    ┌────────────▼───────────┐
                    │  agent / skill / MCP   │ egress pinned to the proxy;
                    │  (Claude Code, etc.)   │ direct sockets fail closed
                    └────────────┬───────────┘
                                 │ every host recorded, allowed or denied
                    ┌────────────▼───────────┐
                    │ tamper-evident log     │ → driftward report / verify
                    └────────────────────────┘
```

- **Enforcement** uses macOS Seatbelt (`sandbox-exec`) — `allow default` with
  targeted denials, so real agent workloads keep working while credentials,
  denied binaries, and un-proxied egress fail closed. All paths are
  canonicalized (macOS aliases `/tmp`→`/private/tmp`; a rule against the alias
  silently matches nothing).
- **Recording** routes egress through a loopback proxy that logs every host and
  allows or refuses it by policy. Resolved private, loopback, link-local, and
  reserved addresses are rejected unless `allow_private: true` is explicit.
  HTTPS is tunneled, not decrypted — no MITM.
- **Integrity** comes from a SHA-256 hash chain sealed with an **Ed25519
  signature** (pure standard library, validated against the RFC 8032 test
  vectors). `driftward verify` detects any edit, reorder, or deletion, and confirms
  the seal was signed by the expected key — so a session log becomes portable
  evidence, not just a local file.
- **Behavioral integrity** compares runtime capabilities with an explicitly
  approved, signed baseline—catching a "rug pull" without treating every earlier
  observation as trusted.

## Why this exists

The independent tools that might have solved agent runtime security were all
acquired into platform suites in 2025–2026, and every deployed defense for the
skill/plugin supply chain is static analysis — which a 2026 result showed
malicious skills evade over 90% of the time by decoding their payload at
runtime. The missing primitive is **observe → enforce → prove** at the OS level,
portable across agents and owned by no single vendor. Driftward is that primitive.

## Advanced

- **Behavioral risk scoring** — `driftward risk` classifies every egress host
  (provider / dev-infra / cloud / unrecognized / **suspicious**) and scores the
  session 0-100. It recognizes real exfiltration infrastructure — tunnels
  (ngrok, trycloudflare), webhook catchers (webhook.site, requestbin), OOB
  domains (oast.fun, interact.sh), paste sites, raw IPs, punycode homographs,
  and DGA-like subdomains.
- **CI gate** — `driftward gate --max-risk 40 --fail-on-blocked` exits non-zero so
  a build fails if an agent step phones home. Ships as a GitHub Action
  ([action.yml](action.yml)).
- **Comprehensive recording** — `driftward run --deep` streams macOS Endpoint
  Security events for the agent's process subtree (every file open, process
  exec, file create), correlated by pid. Needs `sudo` + Full Disk Access on the
  terminal; best-effort and never breaks the run.
- **Strict filesystem** — `driftward run --strict` denies *all* writes outside the
  project tree, not just credential paths.
- **Live approvals** — `on_violation: ask` pauses on an unlisted host and asks
  (allow once / allow always / deny); "allow always" is learned for the session.
- **Monitor mode** — `on_violation: warn` enforces the filesystem but lets egress
  through *and records it*, for adopting Driftward before tightening the list.
- **Approved behavioral drift** — Driftward normalizes network, process,
  filesystem, IPC, and credential capabilities. A first run is only an
  observation. `driftward baseline approve` creates an Ed25519-signed trust point;
  `driftward diff` explains every new capability and its severity.

## Behavioral integrity

Driftward behaves like `git diff` for an agent's runtime capabilities:

```bash
# 1. Observe and inspect a known-good run.
driftward run --deep claude
driftward behavior

# 2. Explicitly approve it. This writes a signed local baseline scoped to the
#    agent/command and workspace; it never happens automatically.
driftward baseline approve
driftward baseline verify claude@my-project

# 3. Future runs compare against that approval.
driftward diff --exit-code
driftward gate --fail-on-new network,process,credential
```

The manifest format is versioned JSON (`driftward.behavior/v1`). Approved
baselines are portable JSON signed by the same local Ed25519 identity used for
session receipts. Driftward refuses a tampered baseline and refuses to approve a
session whose receipt integrity has failed. A replacement requires an explicit
`--force`, preventing gradual observations from laundering themselves into
trusted behavior.

Filesystem events are normalized into low-noise scopes such as `project/**`,
`temp/**`, and `home/.ssh/**`; process executions become executable
capabilities; network behavior is reduced to host/port. `--deep` provides the
filesystem/process evidence on supported systems. Without it, the manifest is
honest about partial coverage.

## Dashboard

`driftward dashboard` serves a read-only, loopback-only UI (127.0.0.1, fresh port,
no remote requests) over your recorded sessions:

- **Posture overview** — enforcement capabilities, high-risk/degraded/timed-out
  runs, top destinations, approved behavioral drift, and recent sessions.
- **Behavior workspace** — baseline coverage, drift inbox, unapproved subjects,
  signed-baseline verification, and direct links to the evidence session.
- **Evidence explorer** — search and filter sessions by mode and risk, with
  status, backend, egress, and receipt integrity visible at a glance.
- **Session detail** — sandbox/network/environment/deep-trace evidence, signed
  timeline, filesystem/process events, copy-command, and JSON export.

It auto-refreshes while a session is live.

## Command reference

| Command | Does |
| --- | --- |
| `driftward run <agent\|-- cmd>` | Enforce + record (`--strict`, `--strict-read`, `--deep`) |
| `driftward record <agent\|-- cmd>` | Observe only; no sandbox and only proxy-honoring egress is seen |
| `driftward profile <skill>` | Time-box and profile a semi-trusted skill; generate a policy |
| `driftward scan <corpus>` | Batch-scan a directory of skills; produce a shareable finding |
| `driftward risk [log]` | Score a session's risk and classify its hosts |
| `driftward behavior [log]` | Emit a versioned normalized capability manifest |
| `driftward baseline approve\|list\|show\|verify` | Manage explicit Ed25519-signed approvals |
| `driftward diff [log]` | Explain new/removed capabilities against approval |
| `driftward gate [log]` | CI gate: risk, blocked egress, or `--fail-on-new` behavior |
| `driftward mcp list\|run\|wrap\|unwrap` | Discover and confine local + remote MCP servers as separate principals |
| `driftward registry publish\|trust\|verify\|list\|install` | Share/adopt signed, reviewed behavior baselines |
| `driftward agents` | List supported AI tools and which are installed |
| `driftward init [agent]` | Scaffold a project `.driftward.yaml` |
| `driftward dashboard` | Open the local, read-only session dashboard |
| `driftward doctor` | Prove enforcement works on this machine |
| `driftward sessions` | List recorded sessions |
| `driftward report [log]` | Human-readable session receipt |
| `driftward verify [log] [--pubkey HEX]` | Check the tamper-evident chain + signature |
| `driftward key` | Print this machine's public key (share it to let others verify) |
| `driftward policy show\|sbpl [agent]` | Inspect the effective policy / compiled profile |

## Repository map

```text
driftward/              CLI, policy model, Seatbelt compiler, egress proxy,
                     recorder, Ed25519 signing, profiler, doctor, dashboard
policies/            reference agent policies + reviewed skill policies
examples/            demo policy + stand-in malicious skill
tests/               unit + live-enforcement integration tests
docs/                architecture, limitations, feature map
```

## Feature map

See [docs/FEATURES.md](docs/FEATURES.md) for what's shipped and where this goes
next (complete behavioral recording via Endpoint Security, MCP firewalling,
Linux support, a community policy registry).

## Tests

```bash
python3 -m unittest discover -s tests -v   # the full test suite
driftward doctor                              # live enforcement self-test
```

## License

MIT.
