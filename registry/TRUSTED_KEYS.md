# Trusted keys

Driftward will not install an entry unless its signer is in your local trust store.
Trusting a key is a judgment you make — this file only *lists* keys; it cannot
make them trustworthy. Verify a key through a second channel before you trust it.

## Maintainer keys

| Label | Ed25519 public key | Notes |
|-------|--------------------|-------|
| `driftward-maintainers` (example) | `f6d1c44665847e2e457157bf4a3b5931400570bc723a0110bf8619613813ef3e` | Seed key used to sign the example entries in this repo. **Replace with a real, independently published maintainer key before relying on it.** |

Trust one with:

```bash
driftward registry trust f6d1c44665847e2e457157bf4a3b5931400570bc723a0110bf8619613813ef3e \
    --label driftward-maintainers
```

List and manage what you trust:

```bash
driftward registry trust --list
driftward registry trust <key> --remove
```

## Why this matters

The seed entries here are signed by a development key for demonstration. In a real
deployment the maintainer key should be published where it can be verified out of
band (a signed release, a well-known website, a keybase-style proof), and rotated
if compromised. Driftward's job is to make the *chain* verifiable; deciding whom to
trust is, and should be, yours.
