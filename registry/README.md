# Driftward community registry (template)

A registry of **reviewed, Ed25519-signed behavior baselines** (and optional
least-privilege policies) for popular MCP servers and skills. Adopt one and your
Driftward drift checks and CI gates run against a community-reviewed profile instead
of one you had to build from scratch — but only after you decide to trust the
signer.

> **This is a starter template, not a production registry.** The entries under
> [`examples/`](examples/) are **examples signed by a throwaway development key**
> and are not version-pinned — do not trust them for real use. They exist to show
> the format and the workflow. A production registry needs an independently
> published maintainer key (see [TRUSTED_KEYS.md](TRUSTED_KEYS.md)) and
> reproducibly reviewed, definition-pinned entries.

There is no network and no cloud. A registry is just a directory of signed JSON
files. Clone it, vendor it, or receive it any way you like; Driftward reads it
locally.

## Use it

```bash
# 1. Trust a reviewer key you have independently verified (see TRUSTED_KEYS.md)
driftward registry trust <publisher-key> --label driftward-maintainers

# 2. Check what the registry contains and that every entry verifies
driftward registry verify ./examples/

# 3. Adopt a trusted entry as a local baseline (works in any project)
driftward registry install @modelcontextprotocol/server-github --from ./examples/

# optional: also write the entry's reviewed policy
driftward registry install @modelcontextprotocol/server-github --from ./examples/ \
    --policy-out github.policy.json
```

Trust is **deny-by-default**: an entry whose signer is not in your trust store is
never installed. Adopting an entry re-signs a *local* baseline (with provenance
recording the original signer), so it becomes a first-class baseline for `driftward
diff` and `driftward gate`.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: observe a server under Driftward,
approve a baseline, `driftward registry publish` it, and open a pull request. A
maintainer reviews the behavior and re-signs it with a maintainer key.

## Trust model

Verifying a signature proves *who signed an entry*, not that the behavior is safe.
That judgment is the reviewer's, and yours. Only trust keys you have reason to —
see [TRUSTED_KEYS.md](TRUSTED_KEYS.md). The entry format and signing details are
in [SCHEMA.md](SCHEMA.md).
