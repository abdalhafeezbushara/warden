# Dynamic detonation harness

Runs untrusted MCP servers **for real** to see where they phone home — safely,
because each one executes inside a disposable Docker container, unprivileged,
with no host mounts, and the container is destroyed after.

This is the counterpart to `warden scan --static-only`: static analysis reads a
skill's code without running it; detonation *runs* it and watches the network.
Egress is captured two ways so nothing slips past:

- **DNS capture** (tcpdump at the container boundary) — app-agnostic, so it sees
  hosts even when the server ignores `HTTP_PROXY` (Node's `fetch` does).
- **Warden's proxy** — verdicts for proxy-honoring clients (curl, Python).

Capture covers the **whole container lifetime**, so a package that beacons from
an `npm postinstall` script — where real supply-chain attacks fire — is caught,
not just runtime behavior. npm/node's own infrastructure is filtered out.

## One-time setup

```bash
cd ~/Desktop/warden
docker build -f detonate/Dockerfile -t warden-detonate .
```

## Run

```bash
~/Desktop/warden/detonate/warden-detonate.sh @upstash/context7-mcp mcp-server-kubernetes
# or a list, one npm package per line:
~/Desktop/warden/detonate/warden-detonate.sh --file packages.txt
```

Writes `finding.html` + `results.jsonl` to a timestamped folder on your Desktop.

## What to expect (honest)

- **Reputable servers usually show no egress.** Most gate on an API key/token
  and exit early without one, and well-behaved packages don't beacon. Clean is
  the correct result — the harness is validated to catch a beacon when there is
  one (a simulated `ngrok`/exfil call is flagged), so "no egress" is trustworthy.
- The compelling hits come from the **long tail**: obscure, low-download packages
  with postinstall beacons or startup telemetry to undisclosed hosts. Feed the
  harness a broad `--file` list to find them.

## Safety

The container is the boundary — treat it as strong, not absolute. Run this on a
machine you're willing to treat as disposable, ideally not your primary one.
Never run it with host directories mounted or with `--privileged`.
