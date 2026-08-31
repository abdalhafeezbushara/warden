"""Behavioral intelligence: host reputation, risk scoring, and agent baselines.

Warden records what an agent did; this module reasons about whether it looks
right. Three capabilities:

  * classify_host  — put an egress host in a category (provider / dev-infra /
    cloud / unrecognized / suspicious), recognizing real exfiltration
    infrastructure (webhook catchers, tunnels, paste sites, OOB-interaction
    domains) that a poisoned skill reaches to phone home.
  * session_risk   — a 0-100 risk score for one session from its blocked egress,
    unrecognized/suspicious hosts, and integrity.
  * baselines      — a per-agent fingerprint of normal behavior, so a session
    that contacts hosts or spawns processes the agent has never used before is
    flagged as anomalous.

Pure logic over recorded summaries; no network, no dependencies.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import math
import os
import re
from pathlib import Path

from . import agents

# Infrastructure commonly used to exfiltrate data or receive out-of-band
# callbacks. A coding agent reaching one of these is worth a hard look — these
# are the endpoints poisoned skills and injected prompts use to phone home.
EXFIL_INFRA = [
    "*webhook.site*", "*requestbin*", "*pipedream.net", "*.ngrok.io", "*.ngrok-free.app",
    "*.ngrok.app", "*.trycloudflare.com", "*.loca.lt", "*.localtunnel.me",
    "*burpcollaborator.net", "*.oast.fun", "*.oast.site", "*.oast.pro", "*.oast.live",
    "*interact.sh", "*.interactsh.com", "*.dnslog.cn", "*.canarytokens.com",
    "*pastebin.com", "*paste.ee", "*ghostbin*", "*hastebin*", "*.transfer.sh",
    "*file.io", "*0x0.st", "*termbin.com", "*.serveo.net", "*.portmap.io",
    # Chat webhooks are a very common LLM/skill exfil channel. classify_host
    # only sees the hostname (not the /api/webhooks path), so match at host level
    # — a coding agent has no legitimate need to reach these.
    "discord.com", "*.discord.com", "discordapp.com", "*.discordapp.com",
    "hooks.slack.com", "*.hooks.slack.com", "api.telegram.org",
]

# Uncommon TLDs disproportionately used for throwaway/malicious infra. Presence
# is a soft signal (raises suspicion), never a verdict on its own.
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".link",
    ".work", ".zip", ".mov", ".rest", ".cam", ".lol", ".sbs",
}


def _matches_any(host: str, patterns: list[str]) -> bool:
    h = host.lower()
    return any(fnmatch.fnmatch(h, p.lower()) for p in patterns)


def _is_ip_literal(host: str) -> bool:
    h = host.strip()
    # Bracketed IPv6, e.g. [::1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Non-dotted encodings curl/resolvers still route to an IP:
    #   decimal integer (2130706433), hex (0x7f000001), octal (0177.0.0.1 parts)
    try:
        if h.isdigit() and 0 <= int(h) <= 0xFFFFFFFF:
            return True
        if h.lower().startswith("0x") and int(h, 16) <= 0xFFFFFFFF:
            return True
    except ValueError:
        pass
    return False


def _high_entropy_label_str(label: str) -> bool:
    """A DGA-like label: long, high Shannon entropy, few vowels."""
    if len(label) < 12:
        return False
    counts = {c: label.count(c) for c in set(label)}
    entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in counts.values())
    vowels = sum(label.count(v) for v in "aeiou")
    return entropy > 3.5 and vowels / len(label) < 0.25


def _known_good() -> set[str]:
    hosts = set(agents.DEVELOPER_BASELINE)
    for a in agents.REGISTRY.values():
        hosts.update(a.egress)
    return hosts


CLOUD_SUFFIXES = ("amazonaws.com", "azure.com", "azurewebsites.net", "googleapis.com",
                  "cloudfront.net", "core.windows.net", "gcr.io", "cloudflare.com")


def classify_host(host: str) -> tuple[str, str]:
    """Return (category, reason). Categories, worst-first:
    suspicious, unrecognized, cloud, dev-infra, provider."""
    h = (host or "").lower().strip()
    if not h:
        return "unrecognized", "empty host"

    # Hard signals first — these override even an allow-list match, because a
    # host that looks like exfil infra or a raw IP should never be waved through.
    if _matches_any(h, EXFIL_INFRA):
        return "suspicious", "matches known exfiltration / callback infrastructure"
    if _is_ip_literal(h):
        # Raw IP egress bypasses hostname allow-lists and is unusual for agents.
        return "suspicious", "raw IP address (bypasses hostname allow-lists)"
    if h.startswith("xn--") or ".xn--" in h:
        return "suspicious", "punycode/internationalized domain (homograph risk)"

    # Known-good and cloud classification BEFORE the entropy heuristic, so a
    # legitimate content-hash CDN host (e.g. abcdef0123.cloudfront.net) is not
    # mislabeled suspicious by its high-entropy label.
    known = _known_good()
    for k in known:
        kl = k.lower()
        if kl == h or fnmatch.fnmatch(h, kl) or h.endswith("." + kl):
            for a in agents.REGISTRY.values():
                if kl in (e.lower() for e in a.egress):
                    return "provider", f"known endpoint for {a.name}"
            return "dev-infra", "known developer/package infrastructure"

    if any(h == s or h.endswith("." + s) for s in CLOUD_SUFFIXES):
        return "cloud", "generic cloud provider (legitimate or exfil — check context)"

    # Entropy is a soft signal, applied only to still-unrecognized hosts, and
    # across all labels (not just the leftmost) so cdn.<dga>.evil.com is caught.
    if any(_high_entropy_label_str(lbl) for lbl in h.split(".")):
        return "suspicious", "high-entropy label (algorithmically-generated pattern)"

    tld = "." + h.rsplit(".", 1)[-1] if "." in h else ""
    if tld in SUSPICIOUS_TLDS:
        return "unrecognized", f"unlisted host on a frequently-abused TLD ({tld})"

    return "unrecognized", "not in any known allow-list"


_LEVELS = [(80, "critical"), (50, "high"), (25, "medium"), (1, "low"), (0, "none")]


def _level(score: int) -> str:
    for threshold, name in _LEVELS:
        if score >= threshold:
            return name
    return "none"


def session_risk(summary: dict) -> dict:
    """Compute a 0-100 risk score and reasons for one session summary."""
    score = 0
    reasons: list[str] = []

    hosts = ({e["host"] for e in summary.get("allowed", [])}
             | {e["host"] for e in summary.get("blocked", [])}
             | {e["host"] for e in summary.get("warned", [])})
    blocked_hosts = {e["host"] for e in summary.get("blocked", [])}
    warned_hosts = {e["host"] for e in summary.get("warned", [])}

    suspicious = [h for h in hosts if classify_host(h)[0] == "suspicious"]
    if suspicious:
        # A single confirmed exfil-infra / raw-IP contact is high on its own.
        score += 50 + 10 * (len(suspicious) - 1)
        reasons.append(f"{len(suspicious)} suspicious host(s): {', '.join(sorted(suspicious)[:3])}")

    if blocked_hosts:
        score += 20
        reasons.append(f"{len(blocked_hosts)} egress destination(s) blocked")

    # Warned (monitor-mode) egress that was let through is riskier than blocked.
    warned_suspicious = [h for h in warned_hosts if classify_host(h)[0] in ("suspicious", "unrecognized")]
    if warned_suspicious:
        score += 25
        reasons.append(f"{len(warned_suspicious)} unlisted host(s) let through in monitor mode")

    unrec = [h for h in hosts if classify_host(h)[0] == "unrecognized"]
    if unrec:
        score += 8 * min(len(unrec), 3)
        reasons.append(f"{len(unrec)} unrecognized host(s)")

    if not summary.get("integrity_ok", True):
        score += 50
        reasons.append("session log integrity check FAILED (tampered)")

    score = max(0, min(100, score))
    return {"score": score, "level": _level(score), "reasons": reasons}


# ---- per-agent behavioral baselines ------------------------------------

def _baseline_dir() -> Path:
    base = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden")) / "baselines"
    base.mkdir(parents=True, exist_ok=True)
    return base


def build_baseline(agent: str, summaries: list[dict]) -> dict:
    """Fold an agent's historical sessions into a fingerprint of normal behavior."""
    hosts: set[str] = set()
    n = 0
    for s in summaries:
        if s.get("agent") != agent:
            continue
        n += 1
        for group in ("allowed", "warned", "blocked"):
            hosts.update(e["host"] for e in s.get(group, []))
    return {"agent": agent, "sessions": n, "hosts": sorted(hosts)}


def save_baseline(baseline: dict) -> None:
    path = _baseline_dir() / f"{baseline['agent']}.json"
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(agent: str) -> dict | None:
    path = _baseline_dir() / f"{agent}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def compare_to_baseline(summary: dict, baseline: dict) -> dict:
    """Return the hosts in this session that the agent's baseline has never seen."""
    known = set(baseline.get("hosts", []))
    hosts = ({e["host"] for e in summary.get("allowed", [])}
             | {e["host"] for e in summary.get("blocked", [])}
             | {e["host"] for e in summary.get("warned", [])})
    new = sorted(hosts - known)
    return {
        "agent": baseline.get("agent"),
        "baseline_sessions": baseline.get("sessions", 0),
        "new_hosts": new,
        "anomalous": bool(new) and baseline.get("sessions", 0) >= 2,
    }
