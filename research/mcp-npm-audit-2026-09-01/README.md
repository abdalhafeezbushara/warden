# npm MCP package coverage audit, 2026-09-01

This directory freezes the evidence behind the Medium article
[`docs/medium-mcp-static-analysis.md`](../../docs/medium-mcp-static-analysis.md).

## Scope

- Collection date: 2026-09-01
- Corpus: 300 unique npm package names returned by 11 paginated MCP-related
  registry searches and containing `mcp` in the package name
- Unit of analysis: the latest published tarball resolved at collection time
- Execution: none; package code and lifecycle scripts were never run
- Integrity: the audit verifies npm's published SRI value when present

This is a search-ranked convenience sample. It is not a random sample, a list
of 300 confirmed servers, or an estimate of the whole MCP ecosystem.

## Files

- `packages.txt`: the ordered discovery manifest
- `results.json`: exact names, versions, tarball URLs, integrity values, coverage,
  and static signals
- `summary.json`: aggregate counts used by the article
- `audit.py`: read-only tarball auditor

`results.json` doubles as a lock file. Passing it back to `audit.py` downloads
the same versioned tarball URLs instead of resolving current `latest` versions.

## Coverage definition

`scanner_blind_to_runtime_code` is true when the tarball contains at least one
runtime code file outside tests/examples, but zero code files eligible under
Driftward's precision-oriented static rules. Those rules exclude `dist/`,
`build/`, minified files, tests, fixtures, examples, source maps, and files over
1 MB.

This field describes one scanner's coverage. It does not claim that a bundle is
impossible to analyze with other static techniques.

## Reproduce the frozen audit

From the repository root:

```bash
python3 research/mcp-npm-audit-2026-09-01/audit.py \
  research/mcp-npm-audit-2026-09-01/results.json \
  /tmp/mcp-audit-rerun.json
```

## Collect a current corpus

```bash
N=300 ./detonate/fetch-corpus.sh /tmp/mcp-packages.txt

python3 research/mcp-npm-audit-2026-09-01/audit.py \
  /tmp/mcp-packages.txt \
  /tmp/mcp-audit-current.json
```

The second command requires the repository root on `PYTHONPATH`, which is true
when it is run from the root as shown.
