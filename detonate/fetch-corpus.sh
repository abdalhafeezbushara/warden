#!/bin/bash
#
# fetch-corpus.sh — build a BROAD list of public MCP-server npm packages (the
# long tail, not just the reputable top results) and write it to packages.txt.
# Feed that list to BOTH tools:
#   - static scan (safe on your Mac):   see below
#   - dynamic detonation (in Docker):   detonate/warden-detonate.sh --file packages.txt
#
# Usage:
#   ~/Desktop/warden/detonate/fetch-corpus.sh            # ~300 packages -> ./packages.txt
#   N=600 ~/Desktop/warden/detonate/fetch-corpus.sh out.txt

set -uo pipefail
OUT="${1:-packages.txt}"
N="${N:-300}"
PY="$(command -v python3.13 || command -v python3)"

"$PY" - "$N" > "$OUT" <<'PYEOF'
import json, sys, urllib.request, urllib.parse
want = int(sys.argv[1])
# Many queries + pagination to reach the long tail, not just the popular head.
queries = ["mcp server", "mcp-server", "model context protocol", "modelcontextprotocol",
           "mcp tool", "claude mcp", "mcp integration", "@modelcontextprotocol",
           "mcp ai", "mcp connector", "mcp plugin"]
seen, out = set(), []
for q in queries:
    for frm in (0, 100, 200):
        url = ("https://registry.npmjs.org/-/v1/search?text="
               + urllib.parse.quote(q) + f"&size=100&from={frm}")
        try:
            data = json.load(urllib.request.urlopen(url, timeout=25))
        except Exception:
            continue
        for obj in data.get("objects", []):
            p = obj.get("package", {})
            name = p.get("name", "")
            if name and name not in seen and "mcp" in name.lower():
                seen.add(name); out.append(name)
        if len(out) >= want:
            break
    if len(out) >= want:
        break
for name in out[:want]:
    print(name)
PYEOF

echo "wrote $(wc -l < "$OUT" | tr -d ' ') packages to $OUT" >&2
