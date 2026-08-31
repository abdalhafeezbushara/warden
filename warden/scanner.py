"""`warden scan` — the batch finding engine.

Point it at a corpus of agent skills / MCP servers and it reports what they
*actually do*, at scale. Two lenses per target, combined:

  * **Static** — read the skill's files (SKILL.md, code, manifest) for network
    calls, credential-path access, subprocess use, and prompt-injection patterns,
    and note which hosts the skill *declares*.
  * **Dynamic** — time-box the skill under Warden (strict read/write confinement,
    egress blocked by default and recorded) and observe the hosts it attempts to
    reach and the risk it scores. This host sandbox is for semi-trusted code;
    unknown code belongs in the disposable container harness under detonate/.

The payoff is the cross-check static analysis alone can't make and runtime alone
can't explain: *"this skill contacted a host it never disclosed"*, aggregated
across a whole corpus into a shareable finding.

Corpus format: a directory whose immediate subdirectories are skills. A skill may
include a `scan.json` describing how to run it and what it declares:

    { "name": "fetch-skill",
      "command": ["sh", "run.sh"],        # optional: enables dynamic detonation
      "declared_hosts": ["api.example.com"] }

With no command, a skill is analyzed statically only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- static signal patterns ------------------------------------------------

NETWORK_PATTERNS = [
    (re.compile(r"\b(?:urllib|http\.client|httpx|requests)\b"), "python-http"),
    (re.compile(r"\b(?:socket)\.(?:socket|create_connection)\b"), "raw-socket"),
    (re.compile(r"\bfetch\s*\(|XMLHttpRequest|WebSocket\b"), "js-fetch"),
    (re.compile(r"\b(?:axios|got|node-fetch|undici)\b"), "js-http-lib"),
    (re.compile(r"\b(?:curl|wget)\b"), "shell-http"),
    (re.compile(r"https?://[^\s\"'`)]+"), "url-literal"),
]

# Deliberately narrow: reading an actual credential *store* by path. Generic
# `process.env` / `token` / `api_key` mentions are NOT here — every server has
# those legitimately, and counting them makes the finding noise, not signal.
CREDENTIAL_PATTERNS = [
    re.compile(r"\.ssh/|id_rsa|id_ed25519|id_dsa|id_ecdsa"),
    re.compile(r"\.aws/credentials|\.aws/config"),
    re.compile(r"\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b"),
    re.compile(r"\.env\.local|\.env\.production|\.env\.development"),
    re.compile(r"(?i)login\.keychain|security\s+find-generic-password|/Keychains/"),
    re.compile(r"\.docker/config\.json|\.kube/config\b|gcloud/credentials"),
]

SUBPROCESS_PATTERNS = [
    re.compile(r"\bsubprocess\.|os\.system\(|\bPopen\("),
    re.compile(r"child_process|execSync|spawnSync"),
    re.compile(r"\beval\s*\(|\bexec\s*\("),
    re.compile(r"\|\s*(?:sh|bash|zsh)\b|curl[^\n|]*\|\s*(?:sh|bash)"),
]

# Prompt-injection patterns in skill instructions. Deliberately HIGH-PRECISION:
# these phrases almost never appear innocently, so a hit is worth a human's
# attention. Noisier signals (the words "steal"/"exfiltrate", lone base64) were
# removed because on real code they fire on test cases, error strings, and docs
# — a published finding cannot afford false positives.
INJECTION_PATTERNS = [
    (re.compile(r"(?i)ignore (?:all |the |your )?(?:previous|prior|above|earlier) (?:instructions|prompts?|context)"),
     "override-instructions"),
    (re.compile(r"(?i)disregard (?:all |the |your )?(?:previous|prior|above) (?:instructions|prompts?)"),
     "override-instructions"),
    (re.compile(r"(?i)do not (?:tell|inform|mention|notify|reveal|alert)[^.\n]{0,40}(?:user|human|owner|operator)"),
     "hide-from-user"),
    (re.compile(r"(?i)(?:without (?:telling|informing|alerting|notifying)|do not warn) (?:the )?(?:user|human|owner)"),
     "act-behind-users-back"),
    # Bidirectional control characters — the "Trojan Source" / Rules-File-Backdoor
    # attack (CVE-2021-42574). These reorder how text renders vs. how it parses
    # and are essentially never legitimate in skill instructions. NOT the
    # zero-width joiner (U+200D), which is a normal part of emoji sequences.
    (re.compile("[‪‫‬‭‮⁦⁧⁨⁩؜]"),
     "bidi-control-chars"),
]

# Files that are not the skill's authored instructions/logic — skip them so a
# security TEST case or a minified bundle can't create false positives.
SKIP_MARKERS = ("/test", "/tests/", "/__tests__/", "/spec/", ".test.", ".spec.",
                "/dist/", "/build/", "/node_modules/", ".min.", ".map",
                "/fixtures/", "/examples/", "/example/", "/e2e/")

TEXT_EXTS = {".md", ".txt", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml",
             ".mjs", ".cjs", ".rb", ".go", ".toml"}
# Behavioral signals (network calls, credential access, subprocess) count only in
# CODE files. URLs in README/markdown/manifests are doc/sponsor/badge links —
# NOT runtime behavior — and counting them turns a README's "Discord sponsor"
# link into a false "reaches suspicious infra". Injection patterns, by contrast,
# are scanned everywhere (a SKILL.md is exactly where a prompt injection hides).
CODE_EXTS = {".py", ".js", ".ts", ".sh", ".mjs", ".cjs", ".rb", ".go"}
MAX_FILE_BYTES = 1_000_000


@dataclass
class StaticFindings:
    files_scanned: int = 0
    network: list[str] = field(default_factory=list)     # signal labels
    url_literals: list[str] = field(default_factory=list)
    credential_hits: int = 0
    subprocess_hits: int = 0
    injection: list[str] = field(default_factory=list)   # pattern labels

    def to_dict(self):
        return {
            "files_scanned": self.files_scanned,
            "network": sorted(set(self.network)),
            "url_hosts": sorted(set(_host_of(u) for u in self.url_literals if _host_of(u))),
            "credential_hits": self.credential_hits,
            "subprocess_hits": self.subprocess_hits,
            "injection": sorted(set(self.injection)),
        }


# A real hostname: dotted labels, valid TLD, no template/interpolation junk.
_VALID_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def _host_of(url: str) -> str | None:
    m = re.match(r"https?://([^/:\s\"'`)]+)", url)
    if not m:
        return None
    host = m.group(1).lower()
    # Reject template-literal fragments (${...}, {{...}}, %s, <placeholder>) and
    # anything that isn't a syntactically valid hostname — otherwise real-world
    # code full of `https://${host}/…` pollutes the finding with garbage "hosts".
    if any(c in host for c in "${}<>%*() \t") or not _VALID_HOST.match(host):
        return None
    return host


def analyze_files(root: Path) -> StaticFindings:
    """Static scan of every text file under `root`."""
    f = StaticFindings()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTS:
            continue
        posix = path.as_posix().lower()
        if any(m in posix for m in SKIP_MARKERS):
            continue  # not the skill's authored instructions/logic
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        f.files_scanned += 1
        # Injection patterns: everywhere (docs included — that's where they hide).
        for pat, label in INJECTION_PATTERNS:
            if pat.search(text):
                f.injection.append(label)
        # Behavioral signals: code files only (docs/manifests hold doc links,
        # not runtime behavior).
        if path.suffix.lower() not in CODE_EXTS:
            continue
        for pat, label in NETWORK_PATTERNS:
            for m in pat.finditer(text):
                if label == "url-literal":
                    f.url_literals.append(m.group(0))
                else:
                    f.network.append(label)
        for pat in CREDENTIAL_PATTERNS:
            f.credential_hits += len(pat.findall(text))
        for pat in SUBPROCESS_PATTERNS:
            f.subprocess_hits += len(pat.findall(text))
    return f


# --- corpus loading --------------------------------------------------------

@dataclass
class Target:
    name: str
    path: Path
    command: list[str] | None = None
    declared_hosts: list[str] = field(default_factory=list)


def load_corpus(root: str | Path) -> list[Target]:
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"corpus is not a directory: {root}")
    targets = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        meta = {}
        cfg = sub / "scan.json"
        if cfg.is_file():
            try:
                meta = json.loads(cfg.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                meta = {}
        targets.append(Target(
            name=str(meta.get("name", sub.name)),
            path=sub,
            command=meta.get("command"),
            declared_hosts=[str(h).lower() for h in meta.get("declared_hosts", [])],
        ))
    return targets


# --- dynamic detonation + per-target scan ----------------------------------

def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "skill"


SCAN_TIMEOUT_S = 60


def scan_target(target: Target, index: int = 0, allow_egress: bool = False,
                static_only: bool = False) -> dict:
    """Static-analyze a target and, if it has a command, run it under confinement.

    static_only=True never executes anything — safe to run at scale on a corpus
    of untrusted third-party code.
    """
    import os

    static = analyze_files(target.path).to_dict()
    result = {
        "name": target.name,
        "declared_hosts": target.declared_hosts,
        "static": static,
        "detonated": False,
        "observed_hosts": [],
        "undisclosed_hosts": [],
        "suspicious_hosts": [],
        "risk": {"score": 0, "level": "none", "reasons": []},
    }
    # Static risk (no execution): reading a credential store and injection-shaped
    # instructions are the strong signals. Merely referencing external hosts is
    # NOT risky by itself (it's an MCP server's job); "undisclosed" only means
    # something when the skill actually declared a host list to compare against.
    if static_only or not target.command:
        from . import intelligence

        declared = set(target.declared_hosts)
        hosts = static["url_hosts"]
        suspicious = [h for h in hosts if intelligence.classify_host(h)[0] == "suspicious"]
        undis = [h for h in hosts if h not in declared] if declared else []
        result["network_hosts"] = hosts
        result["static_undisclosed_hosts"] = undis
        result["suspicious_hosts"] = suspicious
        cred, inj = static["credential_hits"], static["injection"]
        if undis or suspicious or cred or inj:
            score = min(100, 40 * bool(suspicious) + 30 * bool(cred)
                        + 25 * bool(inj) + 15 * bool(undis))
            result["risk"] = {"score": score, "level": intelligence._level(score), "reasons": [
                r for r in [
                    f"reaches suspicious infra: {', '.join(suspicious[:2])}" if suspicious else None,
                    "reads a credential store" if cred else None,
                    f"injection-shaped text: {', '.join(inj[:3])}" if inj else None,
                    f"{len(undis)} host(s) not in declared list" if undis else None,
                ] if r]}
        return result

    if not target.command:
        return result

    from . import intelligence, runner, sessions
    from .policy import (DEFAULT_SECRET_DENY, FilesystemRules, NetworkRules,
                         Policy, ProcessRules)

    workdir = str(target.path)
    # Default detonation blocks ALL egress. Declared hosts are comparison data,
    # not trusted destinations: a malicious package could simply "declare" its
    # collector. --allow-egress is the explicit semi-trusted escape hatch.
    pol = Policy(
        name="scan",
        filesystem=FilesystemRules(read=[workdir + "/**"], write=[workdir + "/**", "/tmp/**"],
                                   deny=list(DEFAULT_SECRET_DENY)),
        network=NetworkRules(allow=(["*"] if allow_egress else []),
                             deny_all_other=True),
        process=ProcessRules(deny=["ssh", "scp"]),
        on_violation="block+receipt",
        strict_fs=True,
        strict_read=True,
    )
    sid = f"scan-{index:03d}-{_slug(target.name)}"
    cwd = os.getcwd()
    try:
        os.chdir(workdir)
        runner.run(list(target.command), pol, enforce=True, session=sid, quiet=True,
                   timeout=SCAN_TIMEOUT_S)
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        os.chdir(cwd)

    s = sessions.summarize(sid)
    if s.get("not_started"):
        result.update({
            "session": sid,
            "error": "enforcement unavailable; target was not executed",
            "risk": s["risk"],
        })
        return result

    observed = sorted({e["host"] for e in s["allowed"]}
                      | {e["host"] for e in s["blocked"]}
                      | {e["host"] for e in s.get("warned", [])})
    declared = set(target.declared_hosts)
    result.update({
        "detonated": True,
        "session": sid,
        "observed_hosts": observed,
        "undisclosed_hosts": [h for h in observed if h not in declared],
        "suspicious_hosts": [h for h in observed
                             if intelligence.classify_host(h)[0] == "suspicious"],
        "risk": s["risk"],
    })
    return result


def scan_corpus(targets: list[Target], allow_egress: bool = False,
                static_only: bool = False, log=None) -> list[dict]:
    results = []
    for i, t in enumerate(targets):
        if log:
            deton = "" if (t.command and not static_only) else " (static only)"
            log(f"[{i + 1}/{len(targets)}] scanning {t.name}{deton}")
        results.append(scan_target(t, index=i, allow_egress=allow_egress,
                                   static_only=static_only))
    return results


def aggregate(results: list[dict]) -> dict:
    """Roll per-target results into the corpus-level finding."""
    from collections import Counter

    n = len(results)
    detonated = [r for r in results if r["detonated"]]
    host_counter: Counter = Counter()
    undisclosed_counter: Counter = Counter()
    suspicious_counter: Counter = Counter()

    with_network = with_undisclosed = with_suspicious = 0
    with_cred_refs = with_injection = with_subprocess = 0
    for r in results:
        st = r["static"]
        # Undisclosed hosts come from the dynamic run, or (static-only) from URL
        # literals in the code that the skill's docs never declared.
        undisclosed = r["undisclosed_hosts"] or r.get("static_undisclosed_hosts", [])
        net_hosts = r["observed_hosts"] or r.get("network_hosts", [])
        if net_hosts or st["network"]:
            with_network += 1
        if st["credential_hits"]:
            with_cred_refs += 1
        if st["injection"]:
            with_injection += 1
        if st["subprocess_hits"]:
            with_subprocess += 1
        if undisclosed:
            with_undisclosed += 1
        if r["suspicious_hosts"]:
            with_suspicious += 1
        for h in net_hosts:
            host_counter[h] += 1
        for h in undisclosed:
            undisclosed_counter[h] += 1
        for h in r["suspicious_hosts"]:
            suspicious_counter[h] += 1

    def pct(x):
        return round(100 * x / n, 1) if n else 0.0

    worst = sorted(results, key=lambda r: r["risk"]["score"], reverse=True)[:10]
    return {
        "total": n,
        "detonated": len(detonated),
        "static_only": n - len(detonated),
        "pct_with_network": pct(with_network),
        "pct_contacting_undisclosed": pct(with_undisclosed),
        "pct_contacting_suspicious": pct(with_suspicious),
        "pct_credential_refs": pct(with_cred_refs),
        "pct_injection_patterns": pct(with_injection),
        "pct_subprocess": pct(with_subprocess),
        "top_hosts": host_counter.most_common(15),
        "top_undisclosed": undisclosed_counter.most_common(15),
        "top_suspicious": suspicious_counter.most_common(15),
        "worst_offenders": [
            {"name": r["name"], "risk": r["risk"]["score"], "level": r["risk"]["level"],
             "undisclosed": r["undisclosed_hosts"] or r.get("static_undisclosed_hosts", []),
             "suspicious": r["suspicious_hosts"],
             "injection": r["static"]["injection"]}
            for r in worst
            if r["risk"]["score"] > 0 or r["undisclosed_hosts"]
            or r.get("static_undisclosed_hosts") or r["static"]["injection"]
        ],
    }
