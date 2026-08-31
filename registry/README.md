# Warden community registry

A registry of **reviewed, Ed25519-signed behavior baselines** (and optional
least-privilege policies) for popular MCP servers and skills. Adopt one and your
Warden drift checks and CI gates run against a community-reviewed profile instead
of one you had to build from scratch — but only after you decide to trust the
signer.

There is no network and no cloud. This directory *is* the registry: signed JSON
files under [`entries/`](entries/). Clone it, vendor it, or receive it any way you
like; Warden reads it locally.

## Use it

```bash
# 1. Trust a reviewer key you have independently verified (see TRUSTED_KEYS.md)
warden registry trust <publisher-key> --label warden-maintainers

# 2. Check what the registry contains and that every entry verifies
warden registry verify ./entries/

# 3. Adopt a trusted entry as a local baseline (works in any project)
warden registry install @modelcontextprotocol/server-github --from ./entries/

# optional: also write the entry's reviewed policy
warden registry install @modelcontextprotocol/server-github --from ./entries/ \
    --policy-out github.policy.json
```

Trust is **deny-by-default**: an entry whose signer is not in your trust store is
never installed. Adopting an entry re-signs a *local* baseline (with provenance
recording the original signer), so it becomes a first-class baseline for `warden
diff` and `warden gate`.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: observe a server under Warden,
approve a baseline, `warden registry publish` it, and open a pull request. A
maintainer reviews the behavior and re-signs it with a maintainer key.

## Trust model

Verifying a signature proves *who signed an entry*, not that the behavior is safe.
That judgment is the reviewer's, and yours. Only trust keys you have reason to —
see [TRUSTED_KEYS.md](TRUSTED_KEYS.md). The entry format and signing details are
in [SCHEMA.md](SCHEMA.md).
