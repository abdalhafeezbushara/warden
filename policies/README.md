# Policy library

Reviewed, least-privilege policies you can point Driftward at.

- `agents/` — reference policies matching the built-in agent baselines. Useful
  as a starting point to copy into a project `.driftward.yaml` and tighten.
- `skills/` — policies for specific skills and MCP servers, contributed and
  reviewed by the community. Each one lists how its allow-list was derived.

## Using one

```bash
driftward run --policy policies/skills/example-fetch-skill.yaml -- <command>
```

## Contributing a skill policy

The honest way to derive a policy is to observe the skill, not guess:

```bash
driftward profile ./the-skill.sh --out policies/skills/the-skill.yaml
```

Then **review the allow-list** — remove any host you don't recognize or trust —
and add a comment at the top of the file describing the skill, its source, and
how you verified each host. A policy is only as trustworthy as its review, so
say what you checked. See [CONTRIBUTING.md](../CONTRIBUTING.md).
