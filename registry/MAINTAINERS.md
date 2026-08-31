# Running a real registry (maintainers)

The signing/trust/adopt machinery ships today. Turning the template under
[`examples/`](examples/) into a registry people can actually trust is a process,
not a feature. Here it is.

## 1. A dedicated signing identity

Driftward signs with a per-machine Ed25519 key (`~/.driftward/signing.key`). A registry
maintainer key should live on a **controlled signing machine** (or an offline
box), separate from day-to-day dev keys. Its public key is what users trust:

```bash
driftward key           # prints this machine's public key — this is the maintainer key
```

**Publish that public key out of band** so users can verify it independently — a
signed GitHub release, a well-known URL, a keybase-style proof. A key listed only
inside the same repo it signs proves nothing. Rotate it if it is ever exposed.

Replace the example key in [TRUSTED_KEYS.md](TRUSTED_KEYS.md) with the real one,
and re-sign every entry with it (`driftward registry publish …` on the signing
machine).

## 2. Definition-pinned entries

An entry should pin the exact package it was reviewed against, so a later
package or argument swap becomes identity drift instead of silently passing. Pin
it by reviewing the **canonical install** and carrying its `definition_sha256`
(see [`examples/github-pinned.json`](examples/github-pinned.json)).

Caveat worth stating plainly: the entry's `subject.name` must match the **server
name in the consumer's config** (people name their GitHub server `github`, not
`@modelcontextprotocol/server-github`), and the pinned definition only matches
consumers who use the same command/args. Servers whose args vary per user (e.g. a
filesystem server with a path argument) cannot be meaningfully pinned — review
those as capability baselines only, and say so in the entry's notes.

## 3. Reproducible review

Every merged entry should be reproducible: given the package and the documented
steps, a second reviewer should observe the same capabilities. The
[CONTRIBUTING.md](CONTRIBUTING.md) review standard is the bar — no unexplained
network hosts, minimal capabilities, credential access only where the server's
purpose requires it.

## 4. Versioning

Tie entries to package versions. When a server releases a new version, review it
and publish a new pinned entry rather than editing the old one in place — the
history of what was reviewed, and against which version, is the point.

---

Until all four are in place, announce the **signed-registry primitive**, not a
production community registry. The examples here demonstrate the format; they are
signed by a throwaway development key and must not be trusted for real use.
