# Contributing to Warden

Thanks for helping make AI agents safer to run. Warden has two firm principles;
everything else is negotiable.

1. **Standard library only.** Warden has zero runtime dependencies and that is a
   feature — it installs anywhere Python 3.11+ runs, and a security tool with no
   dependency supply chain is easier to trust. Do not add a third-party runtime
   dependency. (Dev-only tooling in `pip install .[dev]` is fine.)
2. **Never oversell enforcement.** If a change records something, say recorded.
   If it enforces, prove it with a test that a denied action is actually blocked.
   Honesty about limits is the product.

## Getting started

```bash
git clone <your-fork>
cd warden
python3 -m venv .venv && .venv/bin/pip install -e .
python3 -m unittest discover -s tests -v
python3 -m warden doctor
```

Use `python3 -m warden ...` during development.

## Good first contributions

- **Agent baselines** (`warden/agents.py`) — add or refine the egress allow-list
  for a coding agent. Ground it: run `warden record <tool>` and read the report.
- **Skill policies** (`policies/skills/*.yaml`) — a reviewed least-privilege
  policy for a popular skill or MCP server. Include how you derived it.
- **Docs and examples.**

## Larger work

The high-value items are in [docs/FEATURES.md](docs/FEATURES.md): the Endpoint
Security recorder (complete filesystem capture), the Linux backend, and live
approvals. Open an issue to discuss before a big change.

## Tests are required for behavior

Any change to enforcement, recording, policy parsing, or signing needs a test.
The bar for an enforcement change is a test that shows the *dangerous* action
failing under the sandbox and the *safe* action still working. See
`tests/test_warden.py` for the pattern.

## Style

Match the surrounding code. Type hints, small functions, comments only where the
code cannot explain itself. Run the suite before opening a PR.
