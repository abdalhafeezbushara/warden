#!/bin/bash
#
# warden-launch.sh — do the two launch steps for Warden:
#   (A) fetch a real corpus of public MCP servers from npm and STATICALLY scan
#       them (no code is executed — safe to run on your Mac), producing a
#       shareable finding page.
#   (B) verify Warden's --deep recording live on this Mac (needs Full Disk
#       Access, which you grant once in System Settings — see below).
#
# HOW TO RUN:
#   1. Open Terminal.
#   2. chmod +x ~/Desktop/warden/scripts/warden-launch.sh
#   3. ~/Desktop/warden/scripts/warden-launch.sh
#
# It creates a timestamped results folder on your Desktop and prints where the
# finding page landed. Re-runnable; nothing is installed system-wide.
#
# Optional environment overrides:
#   N=80  ~/Desktop/warden/scripts/warden-launch.sh     # fetch 80 servers (default 40)
#   SKIP_DEEP=1 ...                                      # skip Part B

set -uo pipefail

# ----------------------------------------------------------------------------
# config
# ----------------------------------------------------------------------------
WARDEN_REPO="${WARDEN_REPO:-$HOME/Desktop/warden}"
N="${N:-40}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$HOME/Desktop/warden-scan-$STAMP"
CORPUS="$WORK/corpus"
export WARDEN_HOME="$WORK/.warden"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

# ----------------------------------------------------------------------------
# locate python (need 3.11+) and the warden repo
# ----------------------------------------------------------------------------
PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then
    if "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  warn "Need Python 3.11 or newer. Install it (e.g. 'brew install python@3.13') and re-run."
  exit 1
fi
if [ ! -d "$WARDEN_REPO/warden" ]; then
  warn "Can't find the Warden code at $WARDEN_REPO."
  warn "Set WARDEN_REPO=/path/to/warden and re-run."
  exit 1
fi
WARDEN() { ( cd "$WARDEN_REPO" && "$PY" -m warden "$@" ); }
ok "Using $PY ($($PY --version 2>&1)) and Warden at $WARDEN_REPO"

mkdir -p "$CORPUS"

# ============================================================================
# PART A — fetch real public MCP servers and statically scan them
# ============================================================================
say "PART A — building a corpus of public MCP servers from npm"

if ! command -v npm >/dev/null 2>&1; then
  warn "npm not found — skipping the corpus fetch (Part A needs Node/npm)."
  warn "Install Node from https://nodejs.org and re-run, or run Part B only."
else
  say "Searching the npm registry for MCP server packages…"
  # Pull candidate package names from the npm search API (no code executed).
  NAMES="$("$PY" - "$N" <<'PYEOF'
import json, sys, urllib.request, urllib.parse
n = int(sys.argv[1])
seen, out = set(), []
for q in ("mcp server", "model context protocol", "mcp-server"):
    url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(q)}&size=100"
    try:
        data = json.load(urllib.request.urlopen(url, timeout=20))
    except Exception:
        continue
    for obj in data.get("objects", []):
        name = obj.get("package", {}).get("name", "")
        # keep things that look like MCP servers; skip our own noise
        if name and name not in seen and ("mcp" in name.lower()):
            seen.add(name); out.append(name)
    if len(out) >= n:
        break
for name in out[:n]:
    print(name)
PYEOF
)"
  import_count=0
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    slug="$(printf '%s' "$pkg" | tr '/@' '__' | tr -c 'a-zA-Z0-9_.-' '-')"
    dest="$CORPUS/$slug"
    mkdir -p "$dest"
    # `npm pack` downloads the tarball only — it does NOT run install scripts.
    if ( cd "$dest" && npm pack "$pkg" --silent >/dev/null 2>&1 ); then
      tarball="$(ls "$dest"/*.tgz 2>/dev/null | head -1)"
      if [ -n "$tarball" ]; then
        tar -xzf "$tarball" -C "$dest" 2>/dev/null && rm -f "$tarball"
        import_count=$((import_count+1))
        printf '  fetched %s\n' "$pkg"
      fi
    else
      rmdir "$dest" 2>/dev/null || true
    fi
  done <<< "$NAMES"
  ok "Imported $import_count package(s) into $CORPUS"

  if [ "$import_count" -gt 0 ]; then
    say "Statically scanning the corpus (no code is executed)…"
    WARDEN scan "$CORPUS" --static-only \
      --title "Public MCP Servers — Behavior Scan ($STAMP)" \
      --html "$WORK/finding.html" --json "$WORK/finding.json"
    ok "Finding page: $WORK/finding.html"
    ok "Raw results:  $WORK/finding.json"
    command -v open >/dev/null 2>&1 && open "$WORK/finding.html" 2>/dev/null || true
  else
    warn "No packages imported — check your network and re-run."
  fi
fi

# ============================================================================
# PART B — verify --deep (comprehensive file/process recording) on this Mac
# ============================================================================
if [ "${SKIP_DEEP:-0}" = "1" ]; then
  say "Skipping Part B (SKIP_DEEP=1)."
  exit 0
fi

say "PART B — verifying Warden --deep recording on this Mac"
cat <<'NOTE'
  --deep uses macOS Endpoint Security (eslogger), which requires ONE manual,
  one-time grant that no script can do for you:

    System Settings  →  Privacy & Security  →  Full Disk Access
    → turn ON your terminal app (Terminal or iTerm)
    → then FULLY QUIT and reopen the terminal, and re-run this script.

  If you have not granted it yet, Part B will simply report "no deep events" —
  that is expected, not a failure. Grant it, reopen the terminal, re-run.
NOTE

say "Caching your sudo credential (eslogger needs root)…"
if ! sudo -v; then
  warn "sudo not available — skipping the --deep check."
  exit 0
fi

say "Running a controlled --deep session (reads ~/.gitconfig, creates a canary)…"
CANARY="/tmp/warden-deep-canary-$STAMP"
WARDEN run --deep -- sh -c "cat \"$HOME/.gitconfig\" >/dev/null 2>&1; /usr/bin/touch \"$CANARY\"" || true

say "What the deep recorder captured:"
LATEST="$(ls -t "$WARDEN_HOME"/sessions/*.log 2>/dev/null | head -1)"
if [ -n "$LATEST" ]; then
  "$PY" - "$LATEST" <<'PYEOF'
import json, sys
counts = {}
note = None
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    o = json.loads(line)
    e = o.get("event")
    if not e: continue
    k = e["kind"]
    if k.startswith(("fs.","proc.","ipc.")):
        counts[k] = counts.get(k,0)+1
    if k == "deep.summary":
        note = e["data"].get("note")
if counts:
    print("  DEEP RECORDING WORKS. Captured:")
    for k,v in sorted(counts.items()):
        print(f"    {k}: {v}")
    print("\n  --deep is verified on this machine.")
else:
    print("  No deep events captured.")
    if note: print("  Reason:", note)
    print("  -> Grant Full Disk Access to your terminal (see above), reopen it, re-run.")
PYEOF
else
  warn "No session log found — the run may have failed."
fi

rm -f "$CANARY" 2>/dev/null || true
say "Done. Finding page (Part A) is at: $WORK/finding.html"
