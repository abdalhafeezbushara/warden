# Trusted keys

Warden will not install an entry unless its signer is in your local trust store.
Trusting a key is a judgment you make — this file only *lists* keys; it cannot
make them trustworthy. Verify a key through a second channel before you trust it.

## Maintainer keys

| Label | Ed25519 public key | Notes |
|-------|--------------------|-------|
| `warden-maintainers` (example) | `77308524a868d0d6c838ad8bd8a02d89f79f79bd6daae9fedaa0223fe4a6a335` | Seed key used to sign the example entries in this repo. **Replace with a real, independently published maintainer key before relying on it.** |

Trust one with:

```bash
warden registry trust 77308524a868d0d6c838ad8bd8a02d89f79f79bd6daae9fedaa0223fe4a6a335 \
    --label warden-maintainers
```

List and manage what you trust:

```bash
warden registry trust --list
warden registry trust <key> --remove
```

## Why this matters

The seed entries here are signed by a development key for demonstration. In a real
deployment the maintainer key should be published where it can be verified out of
band (a signed release, a well-known website, a keybase-style proof), and rotated
if compromised. Warden's job is to make the *chain* verifiable; deciding whom to
trust is, and should be, yours.
