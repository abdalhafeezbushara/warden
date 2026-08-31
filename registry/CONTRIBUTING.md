# Contributing an entry

An entry is a claim: *"this server/skill legitimately does X, and nothing more."*
It is only as good as the review behind it. Contribute one like this.

## 1. Observe the real behavior

Run the server under Warden and let it do representative work, so its actual
capabilities are recorded:

```bash
# an MCP server, as its own confined principal
warden mcp run <name>            # drive it through your agent, or exercise its tools
# then inspect what it did
warden report
warden behavior
```

For fuller filesystem/process coverage, add `--deep` (needs Full Disk Access +
sudo on macOS). The more representative the session, the fewer false-positive
drifts consumers will see.

## 2. Approve and publish

```bash
warden baseline approve <session>          # sign it locally
warden registry publish "<baseline-name>" \
    --out entries/<slug>.json \
    --reviewer "your-name" \
    --source "https://link-to-your-review-or-the-package" \
    --notes "what it reaches and why; anything a reviewer should double-check"
# optional: attach a reviewed least-privilege policy
#   --policy your.policy.yaml
```

## 3. Open a pull request

Include, in the PR description:

- **What the server is** and the package/version you reviewed.
- **Why each capability is legitimate** — especially every network host. An entry
  that reaches a host with no explanation will not be merged.
- **How you observed it** (normal run vs `--deep`, which tools you exercised).

## Review standard (what maintainers check)

- Every network destination is justified and is the vendor's own infrastructure,
  not a tunnel, webhook catcher, or analytics/telemetry endpoint.
- No credential-store or unexpected filesystem access unless the server's purpose
  requires it and it is called out.
- Capabilities are minimal — an over-broad baseline defeats drift detection.

On merge, a maintainer re-signs the entry with a maintainer key (the key
consumers actually trust — see [TRUSTED_KEYS.md](TRUSTED_KEYS.md)). Your
submission's own signature is preserved in provenance.

## The golden rule

A signature proves *who* signed an entry, never that the behavior is safe. Write
entries, and review them, as if someone will trust them without reading the code —
because that is the point.
