# Warden

> Least privilege and a flight recorder for AI coding agents.

Your AI coding agent runs with **your** account. It can read `~/.ssh`, your
cloud credentials, and every `.env` on disk — and any skill, MCP server, or
tool it loads inherits that reach. In 2025–2026 that stopped being theoretical:
agents have deleted production databases, and poisoned skills and packages have
turned developers' own agents into credential-exfiltration tools.

Warden puts a boundary around the agent:

- **Record** everything it does to the network — to a tamper-evident log.
- **Enforce** what it may touch — real OS-level sandboxing, not a prompt asking nicely.
- **Prove** what happened — an integrity-checked receipt for incident response and review.

It is local-first, dependency-free (Python standard library only), and sends
nothing anywhere.

> **Status: v0.2.** Enforcement (macOS Seatbelt / Linux bubblewrap), full egress
> recording, Ed25519-signed receipts, behavioral risk scoring, skill profiling,
> live approvals, and comprehensive file/process recording (macOS eslogger) all
> work today and are covered by 76 tests. See [Limitations](docs/LIMITATIONS.md)
> and the [roadmap](docs/ROADMAP.md).

---

## Install

```bash
pip install .        # from a clone; PyPI/Homebrew to follow
warden doctor        # proves enforcement actually works on your machine
```

No dependencies — just Python 3.11+. During development, `python3 -m warden …`
works without installing.

## Quickstart

Warden knows the major AI coding tools by name and gives each a least-privilege
baseline (its provider hosts + the common developer registries, credentials
denied):

```bash
warden agents              # list supported tools, show which are installed
warden run claude          # run Claude Code, enforced + recorded
warden record cursor       # observe Cursor first (no sandbox; egress still contained)
warden report              # what did the last session do?
warden verify              # is the receipt intact and correctly signed?
warden dashboard           # open the local session dashboard
```

Supported today: **claude, codex, cursor, copilot, gemini, aider, q, opencode,
goose** — plus any command via `warden run -- <command>`.

Pass agent flags after `--`, or override the baseline with a policy:

```bash
warden run claude -- --resume
warden run --policy team.yaml codex
warden init claude         # scaffold a project .warden.yaml (auto-discovered by run)
```

## Scan a whole corpus of skills

Point Warden at a directory of skills / MCP servers and it reports what they
*actually do*, at scale — combining a static pass (network calls, credential
access, prompt-injection patterns in `SKILL.md`) with a **safe detonation** of
each one under containment (filesystem protected, egress recorded and contained):

```bash
warden scan examples/skill-corpus --html finding.html
```

```
WARDEN SCAN — 3 skills
   33.3%  contacted an UNDISCLOSED host
   33.3%  contain injection patterns (static)
  Highest-risk skills:
     36 medium   sneaky-tracker  beacon.undisclosed-analytics.example
      0 none     poisoned-helper  override-instructions, hide-from-user
```

`--html` writes a shareable finding page. This is the honest answer to the
supply-chain problem static scanners can't solve alone: watch what a skill *does*,
then compare it to what it *declared*.

## Vet a single unknown skill before you trust it

```bash
warden profile ./some-skill.sh
```

Warden runs the skill once with the filesystem protected and egress contained
(nothing actually leaves), records every host it *tries* to reach, flags the
ones it doesn't recognize, and prints a least-privilege policy for you to review:

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
mkdir -p /private/tmp/warden-demo/secrets /private/tmp/warden-demo/project
echo 'sk-live-DEADBEEF-secret' > /private/tmp/warden-demo/secrets/api_key.txt

# 2. run it under Warden
python3 -m warden run --policy examples/demo.policy.yaml -- sh examples/malicious-skill.sh

# 3. read the receipt
python3 -m warden report
```

```
╭─ Warden flight report ─────────────────────────────────
│ command : sh examples/malicious-skill.sh
│ policy  : demo   mode: ENFORCE (filesystem + process + egress contained)
│ exit    : 0   duration: 0.50s
│ integrity: OK intact (tamper-evident chain verified)
╰────────────────────────────────────────────────────────

NETWORK EGRESS  (1 allowed, 1 blocked)
  ✓ allow  example.com
  ✗ BLOCK  evil-collector.example-attacker.com   ← denied: host not in allow-list

⚠  Warden blocked 1 undisclosed egress destination(s).
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
  deny_all_other: true
process:
  deny:  ["ssh", "aws", "kubectl"]
on_violation: block+receipt
```

The default policy (no `--policy` flag) already denies the common credential
stores and allow-lists the hosts a coding agent normally needs. Inspect what
will be enforced:

```bash
python3 -m warden policy show     # the effective policy, as JSON
python3 -m warden policy sbpl     # the compiled macOS sandbox profile
```

## How it works

```
                 ┌─────────────────────────────────────────┐
   your policy → │ Warden                                   │
                 │  • compiles a macOS Seatbelt profile     │  OS-enforced:
   warden run  → │  • starts a loopback egress proxy        │  fs + process
                 │  • runs the agent as a child             │
                 └───────────────┬─────────────────────────┘
                                 │ HTTP(S)_PROXY, sandbox-exec
                    ┌────────────▼───────────┐
                    │  agent / skill / MCP   │ egress pinned to the proxy;
                    │  (Claude Code, etc.)   │ direct sockets fail closed
                    └────────────┬───────────┘
                                 │ every host recorded, allowed or denied
                    ┌────────────▼───────────┐
                    │ tamper-evident log     │ → warden report / verify
                    └────────────────────────┘
```

- **Enforcement** uses macOS Seatbelt (`sandbox-exec`) — `allow default` with
  targeted denials, so real agent workloads keep working while credentials,
  denied binaries, and un-proxied egress fail closed. All paths are
  canonicalized (macOS aliases `/tmp`→`/private/tmp`; a rule against the alias
  silently matches nothing).
- **Recording** routes egress through a loopback proxy that logs every host and
  allows or refuses it by policy. HTTPS is tunneled, not decrypted — no MITM.
- **Integrity** comes from a SHA-256 hash chain sealed with an **Ed25519
  signature** (pure standard library, validated against the RFC 8032 test
  vectors). `warden verify` detects any edit, reorder, or deletion, and confirms
  the seal was signed by the expected key — so a session log becomes portable
  evidence, not just a local file.
- **Drift detection** on the dashboard flags a skill that contacts a host in a
  later run it never contacted before — catching a "rug pull" where a skill that
  was clean last week starts phoning home this week.

## Why this exists

The independent tools that might have solved agent runtime security were all
acquired into platform suites in 2025–2026, and every deployed defense for the
skill/plugin supply chain is static analysis — which a 2026 result showed
malicious skills evade over 90% of the time by decoding their payload at
runtime. The missing primitive is **observe → enforce → prove** at the OS level,
portable across agents and owned by no single vendor. Warden is that primitive.

## Advanced

- **Behavioral risk scoring** — `warden risk` classifies every egress host
  (provider / dev-infra / cloud / unrecognized / **suspicious**) and scores the
  session 0-100. It recognizes real exfiltration infrastructure — tunnels
  (ngrok, trycloudflare), webhook catchers (webhook.site, requestbin), OOB
  domains (oast.fun, interact.sh), paste sites, raw IPs, punycode homographs,
  and DGA-like subdomains.
- **CI gate** — `warden gate --max-risk 40 --fail-on-blocked` exits non-zero so
  a build fails if an agent step phones home. Ships as a GitHub Action
  ([action.yml](action.yml)).
- **Comprehensive recording** — `warden run --deep` streams macOS Endpoint
  Security events for the agent's process subtree (every file open, process
  exec, file create), correlated by pid. Needs `sudo` + Full Disk Access on the
  terminal; best-effort and never breaks the run.
- **Strict filesystem** — `warden run --strict` denies *all* writes outside the
  project tree, not just credential paths.
- **Live approvals** — `on_violation: ask` pauses on an unlisted host and asks
  (allow once / allow always / deny); "allow always" is learned for the session.
- **Monitor mode** — `on_violation: warn` enforces the filesystem but lets egress
  through *and records it*, for adopting Warden before tightening the list.
- **Drift detection** — the dashboard flags a skill that reaches a host in a
  later run it never used before (rug-pull forensics).

## Dashboard

`warden dashboard` serves a read-only, loopback-only UI (127.0.0.1, fresh port,
no remote requests) over your recorded sessions:

- **Overview** — sessions recorded, egress blocked, agents seen, tampered logs;
  top blocked destinations and most-contacted allowed hosts.
- **Sessions** — every run with its mode, allowed/blocked counts, integrity, exit.
- **Detail** — per-session egress verdict list, policy, and integrity receipt,
  with blocked exfiltration flagged.

It auto-refreshes while a session is live.

## Command reference

| Command | Does |
| --- | --- |
| `warden run <agent\|-- cmd>` | Enforce a policy + record egress (`--strict`, `--deep`) |
| `warden record <agent\|-- cmd>` | Observe only (no fs/process sandbox; egress contained) |
| `warden profile <skill>` | Detonate a skill; generate a least-privilege policy |
| `warden scan <corpus>` | Batch-scan a directory of skills; produce a shareable finding |
| `warden risk [log]` | Score a session's risk and classify its hosts |
| `warden gate [log]` | CI gate: fail on high risk / undisclosed egress |
| `warden agents` | List supported AI tools and which are installed |
| `warden init [agent]` | Scaffold a project `.warden.yaml` |
| `warden dashboard` | Open the local, read-only session dashboard |
| `warden doctor` | Prove enforcement works on this machine |
| `warden sessions` | List recorded sessions |
| `warden report [log]` | Human-readable session receipt |
| `warden verify [log] [--pubkey HEX]` | Check the tamper-evident chain + signature |
| `warden key` | Print this machine's public key (share it to let others verify) |
| `warden policy show\|sbpl [agent]` | Inspect the effective policy / compiled profile |

## Repository map

```text
warden/              CLI, policy model, Seatbelt compiler, egress proxy,
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
python3 -m unittest discover -s tests -v   # 32 tests
warden doctor                              # live enforcement self-test
```

## License

MIT.
