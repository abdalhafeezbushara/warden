# Registry entry format (`warden.registry-entry/v1`)

Each file under `entries/` is one JSON object, signed with Ed25519 over the
canonical (sorted-key, comma/colon-separated) serialization of everything except
the `signature` field. The signature carries the signer's public key and a
SHA-256 of the signed payload, so an entry is verifiable entirely offline.

```json
{
  "schema": "warden.registry-entry/v1",
  "subject": {
    "name": "@modelcontextprotocol/server-github",
    "kind": "mcp",
    "definition_sha256": null
  },
  "capabilities": {
    "network":    [{"action": "connect", "resource": "api.github.com", "port": 443}],
    "process":    [],
    "filesystem": [],
    "ipc":        [],
    "credential": []
  },
  "coverage":   {"network": "hard", "deep": false, "credentials": true},
  "provenance": {
    "reviewer": "warden-maintainers",
    "reviewed_at": 1234567890.0,
    "source": "https://github.com/.../warden-registry",
    "notes": "GitHub MCP server: reaches only api.github.com.",
    "warden_version": "0.2.0"
  },
  "policy": { "...optional reviewed Warden policy (see `warden run --policy`)..." },
  "signature": {
    "algorithm": "ed25519",
    "public_key": "<64-hex>",
    "value": "<128-hex>",
    "payload_sha256": "<64-hex>"
  }
}
```

Fields:

- **subject** — what the entry is about. `kind` is `mcp`, `skill`, `agent`, or
  `command`; `name` is how you install it (`warden registry install <name>`).
  `definition_sha256` optionally pins the entry to an exact package definition
  (command + args + transport + env-var names).
- **capabilities** — the reviewed, normalized behavior in five categories. This
  is what a session drifts *against*. Network resources are `host` with an
  optional `port` (443 for HTTPS), matching how Warden records real egress.
- **coverage** — how the baseline was observed (`network: hard` means egress was
  pinned to the recording proxy; `deep` means filesystem/process were captured).
- **provenance** — reviewer, review source/notes, and the Warden version used.
- **policy** — optional. A reviewed least-privilege policy document, installable
  with `--policy-out`.
- **signature** — Ed25519 over the canonical payload.

Adopting an entry (`warden registry install`) verifies the signature, checks the
signer is trusted, and re-signs a *local* baseline named `<kind>:<name>` — which
is workspace-independent, so it applies in any project.
