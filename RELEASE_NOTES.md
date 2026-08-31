# Driftward v0.2.0-alpha.2

**An open-source, local behavioral firewall for AI coding agents and MCP servers**
— giving every server a confined identity, a signed behavioral baseline, and
explainable drift.

This is an **early alpha**. It is a solid guardrail and a real evidence layer for
trusted-to-semi-trusted agents — **not** a hardened sandbox for arbitrary malware.
I'm releasing it to find **security reviewers and MCP contributors**. Please try to
break it.

---

## Why

Your AI coding agent runs with **your** account — it can read `~/.ssh`, your cloud
credentials, and every `.env` on disk, and any skill or MCP server it loads
inherits that reach. You can't secure that supply chain by reading code alone:
packages can ship opaque bundles, static review can miss malicious behavior, and
a later update can change runtime behavior after it was reviewed. The answer is
to watch what agents *do*, and notice when it changes.

## What's in this release

- **Contain · Record · Prove · Detect drift.** Run an agent under an OS sandbox
  (macOS Seatbelt / Linux bubblewrap), pin all egress through a recording proxy,
  and write an Ed25519-signed, hash-chained receipt. `driftward diff` compares a
  run against an explicitly approved baseline — a first run is *evidence, not
  trust*.
- **Per-MCP-server identity (the core).** Each MCP server runs as its own confined
  principal (`mcp:<name>`) with its own least-privilege policy, signed baseline,
  and drift. Local stdio servers launch through an **authenticated parent broker**
  that only starts exact pre-registered definitions — a package/argument swap
  becomes high-severity identity drift.
- **Remote MCP confinement.** Remote (`url`) servers run through a sandboxed
  stdio↔HTTP bridge as their own principal with **egress locked to only the
  declared host** — both transports (Streamable HTTP and legacy SSE), with the
  negotiated protocol-version header and expired-session recovery. Endpoint URLs
  and auth headers travel through private env, never the log.
- **Signed community registry.** `driftward registry` shares and adopts reviewed,
  Ed25519-signed behavior baselines (and optional policies), deny-by-default
  trust, entirely offline — no cloud.
- **Behavioral intelligence, CI gate, dashboard.** Host risk classification,
  `driftward gate --fail-on-new` for CI, and a local read-only console with a
  drift inbox.
- **Honest threat model** (`docs/THREAT_MODEL.md`) with a residual-risk register.

## What it does — and doesn't — guarantee

Under `driftward run` (macOS Seatbelt): credential stores and Driftward's own key
are unreadable to the agent; a direct socket fails closed so recorded egress is
complete; denied binaries can't exec; env credentials are scoped to the agent.

It does **not**: inspect TLS payloads (records *which host*, not contents — no
MITM); confine filesystem *reads* unless you pass `--strict-read`; act as a
hardened sandbox for arbitrary malware (use the container harness in `detonate/`);
or fully pin Linux egress yet (a network-namespace pin is the documented next
step). Pure Python standard library, no dependencies, sends no telemetry.

## Install

```bash
pip install .        # from a clone; PyPI to follow
driftward doctor     # live enforcement self-test — proves the guarantees on your machine
driftward run claude
```

macOS + Linux, Python 3.11+.

## Known limitations in this alpha

- The remote MCP bridge has been tested against mock servers and one localhost
  end-to-end run — **not yet against a fleet of real hosted services**. Reports
  from real endpoints are exactly what I'm looking for.
- The registry under `registry/examples/` is a **template signed by a throwaway
  key** — it demonstrates the format, not a production trust root.
- SSE stream resumption (event-id replay) is not yet implemented.

## Verification

The full test suite passes on macOS + Linux across Python 3.11–3.13 in CI;
`driftward doctor` runs a live macOS Seatbelt enforcement test; the wheel builds
and installs in a clean virtualenv.

## Asks

- **Security reviewers:** try to bypass enforcement, evade recording, or forge a
  receipt — see `SECURITY.md` for private reporting.
- **MCP contributors:** run the remote bridge against real servers and file what
  breaks; contribute reviewed registry entries (`registry/CONTRIBUTING.md`).

Not production-hardened. Read the threat model before you rely on it.
