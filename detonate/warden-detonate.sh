#!/bin/bash
#
# warden-detonate.sh — DYNAMIC detonation of MCP servers in disposable Docker
# containers. Each server is installed and run under Warden inside a throwaway
# `--rm` container. The container is the isolation boundary; egress is captured
# two ways: DNS queries (tcpdump — app-agnostic, catches Node fetch that ignores
# HTTP_PROXY) and Warden's proxy (verdicts for proxy-honoring clients).
#
# This step actually EXECUTES third-party code. It runs it UNPRIVILEGED, in a
# fresh container, with NO host mounts, and destroys the container after. Do this
# on a machine you're willing to treat as disposable — never trust a container
# boundary absolutely.
#
# PREREQUISITES:
#   - Docker running.
#   - Image built once:  cd ~/Desktop/warden && docker build -f detonate/Dockerfile -t warden-detonate .
#
# HOW TO RUN (from anywhere):
#   ~/Desktop/warden/detonate/warden-detonate.sh @upstash/context7-mcp mcp-server-kubernetes
#   ~/Desktop/warden/detonate/warden-detonate.sh --file packages.txt
#
# Output: finding.html + results.jsonl in a timestamped folder on your Desktop.

set -uo pipefail

WARDEN_REPO="${WARDEN_REPO:-$HOME/Desktop/warden}"
IMAGE="${IMAGE:-warden-detonate}"
RUNSECS="${RUNSECS:-15}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$HOME/Desktop/warden-detonate-$STAMP"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || {
  warn "Docker is not running. Start Docker Desktop and re-run."; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  say "Building $IMAGE (one time)…"
  ( cd "$WARDEN_REPO" && docker build -f detonate/Dockerfile -t "$IMAGE" . ) || { warn "build failed"; exit 1; }
}

PKGS=()
if [ "${1:-}" = "--file" ]; then
  [ -f "${2:-}" ] || { warn "file not found: ${2:-}"; exit 1; }
  while IFS= read -r l; do l="$(printf '%s' "$l" | tr -d '[:space:]')"; [ -n "$l" ] && PKGS+=("$l"); done < "$2"
else
  PKGS=("$@")
fi
[ "${#PKGS[@]}" -gt 0 ] || { warn "No packages. Pass npm names or --file <list>."; exit 1; }

mkdir -p "$OUT"; RESULTS="$OUT/results.jsonl"; : > "$RESULTS"

# Minimal MCP handshake fed to each server so it initializes (and reveals any
# phone-home). Kept as one line stream on the server's stdin.
MCP_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"warden","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# This script runs INSIDE each container (kept as a heredoc string).
INNER='
set -o pipefail
# Capture DNS for the WHOLE lifetime — INSTALL included — because a malicious
# package beacons from its postinstall script, which runs during `npm install`.
tcpdump -l -n -i any udp port 53 >/tmp/dns.log 2>/dev/null &
sleep 1
ls /usr/local/bin | sort > /tmp/bins.before
npm install -g "$PKG" >/tmp/npm.log 2>&1 || true
ls /usr/local/bin | sort > /tmp/bins.after
BIN="$(comm -13 /tmp/bins.before /tmp/bins.after | head -1)"
[ -z "$BIN" ] && BIN="$(node -e "try{const p=require(\"/usr/local/lib/node_modules/$PKG/package.json\");const b=p.bin;process.stdout.write(typeof b===\"string\"?p.name.split(\"/\").pop():Object.keys(b||{})[0]||\"\")}catch(e){}" 2>/dev/null)"
if [ -n "$BIN" ]; then
  printf "%s" "$MCP_INIT" | runuser -u detonator -- env WARDEN_HOME=/tmp/warden PYTHONPATH=/opt/warden \
      timeout "${RUNSECS}s" python3 -m warden record -- "$BIN" >/tmp/rec.log 2>&1 || true
fi
sleep 1
python3 - <<PYEOF
import json,sys,re,glob,os
sys.path.insert(0,"/opt/warden")
from warden import intelligence
# npm/node own infrastructure — expected during install, not a finding.
NPM_INFRA=("registry.npmjs.org","npmjs.org","npmjs.com","nodejs.org",
           "registry.yarnpkg.com","get.pnpm.io")
def infra(h):
  return any(h==d or h.endswith("."+d) for d in NPM_INFRA)
dns=set()
try:
  for line in open("/tmp/dns.log"):
    for m in re.findall(r"A+\? ([A-Za-z0-9._-]+)", line):
      h=m.rstrip(".").lower()
      if h and "." in h and not h.endswith(".local") and not infra(h): dns.add(h)
except FileNotFoundError: pass
proxy=set()
os.environ["WARDEN_HOME"]="/tmp/warden"
try:
  from warden import sessions
  for sid in sessions.list_session_ids():
    s=sessions.summarize(sid)
    for grp in ("allowed","blocked","warned"):
      for e in s.get(grp,[]): proxy.add(e["host"].lower())
except Exception: pass
hosts=sorted(dns|proxy)
susp=[h for h in hosts if intelligence.classify_host(h)[0]=="suspicious"]
ran=os.path.exists("/tmp/rec.log")
print(json.dumps({"name":os.environ["PKG"],"observed_hosts":hosts,"suspicious_hosts":susp,"ran":ran}))
PYEOF
'

say "Detonating ${#PKGS[@]} MCP server(s) — each in a disposable container (~${RUNSECS}s)"
i=0
for pkg in "${PKGS[@]}"; do
  i=$((i+1)); printf '  [%d/%d] %s … ' "$i" "${#PKGS[@]}" "$pkg"
  line="$(docker run --rm --cap-add=NET_RAW -e "PKG=$pkg" -e "RUNSECS=$RUNSECS" -e "MCP_INIT=$MCP_INIT" \
            "$IMAGE" bash -lc "$INNER" 2>/dev/null | tail -1)"
  [ -z "$line" ] && line="{\"name\":\"$pkg\",\"observed_hosts\":[],\"suspicious_hosts\":[],\"ran\":false,\"error\":\"container failed\"}"
  echo "$line" >> "$RESULTS"
  printf '%s' "$line" | python3 -c 'import json,sys;d=json.load(sys.stdin);h=d.get("observed_hosts",[]);s=d.get("suspicious_hosts",[]);print((", ".join(h) or "(no egress)")+("   ⚠ "+", ".join(s) if s else ""))' 2>/dev/null || echo "?"
done

say "Building the finding"
python3 - "$RESULTS" "$OUT" "$WARDEN_REPO" <<'PYEOF'
import json, sys, os
sys.path.insert(0, sys.argv[3])
from warden import scanner, scan_report
results=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    results.append({"name":d["name"],"detonated":bool(d.get("ran")),
        "observed_hosts":d.get("observed_hosts",[]),"undisclosed_hosts":[],
        "suspicious_hosts":d.get("suspicious_hosts",[]),
        "risk":{"score":(50 if d.get("suspicious_hosts") else 0),
                "level":("high" if d.get("suspicious_hosts") else "none"),
                "reasons":(["reached suspicious infrastructure"] if d.get("suspicious_hosts") else [])},
        "static":{"network":[],"url_hosts":[],"credential_hits":0,"subprocess_hits":0,"injection":[]}})
agg=scanner.aggregate(results)
open(os.path.join(sys.argv[2],"finding.html"),"w").write(
    scan_report.render_html(agg,title="MCP Servers — Dynamic Detonation"))
open(os.path.join(sys.argv[2],"finding.json"),"w").write(scan_report.render_json(agg,results))
ran=sum(1 for r in results if r["detonated"])
print(f"\n  {agg['total']} servers, {ran} ran | {agg['pct_contacting_suspicious']}% suspicious | hosts contacted:")
for h,n in agg["top_hosts"][:15]: print(f"    {h}  ({n})")
PYEOF

ok "Finding: $OUT/finding.html"
ok "Raw:     $OUT/results.jsonl"
command -v open >/dev/null 2>&1 && open "$OUT/finding.html" 2>/dev/null || true
