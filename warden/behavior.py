"""Versioned behavioral manifests, signed approvals, and deterministic drift.

Warden deliberately separates three ideas that security tools often blur:

* an *observation* is what one recorded session attempted;
* a *baseline* is an observation a human explicitly approved and signed; and
* *drift* is the explainable difference from that approved baseline.

Nothing in this module learns automatically.  A first run is evidence, not
trust.  The file format is intentionally JSON + Ed25519 and standard-library
only so other open-source tools can produce and verify it without Warden Cloud.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

MANIFEST_SCHEMA = "warden.behavior/v1"
BASELINE_SCHEMA = "warden.baseline/v1"
CATEGORIES = ("network", "process", "filesystem", "ipc", "credential")
SEVERITY_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3,
                  "high": 4, "critical": 5}


class BehaviorError(ValueError):
    """Raised when behavior evidence or a baseline cannot be trusted."""


def _canon(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value) -> str:
    return hashlib.sha256(_canon(value)).hexdigest()


def _warden_home() -> Path:
    home = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden"))
    home.mkdir(parents=True, exist_ok=True)
    return home


def baselines_dir() -> Path:
    path = _warden_home() / "baselines"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _baseline_filename(name: str) -> str:
    """Map a human identity to a traversal-safe, collision-resistant filename."""
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.").lower() or "behavior"
    if clean == name.lower() and len(clean) <= 72:
        return clean + ".json"
    return f"{clean[:60]}-{hashlib.sha256(name.encode()).hexdigest()[:10]}.json"


def baseline_path(name: str) -> Path:
    return baselines_dir() / _baseline_filename(name)


def default_baseline_name(manifest: dict) -> str:
    """Default approval cohort: one subject inside one workspace.

    Agent behavior varies materially by repository.  Mixing every Claude/Codex
    run on a machine into one baseline creates permanent noise and lets one
    project teach capabilities to another.
    """
    key = manifest.get("subject", {}).get("key") or "unknown"
    workspace = manifest.get("context", {}).get("workspace")
    return f"{key}@{workspace}" if workspace else key


def _subject_identity(summary: dict) -> tuple[str, str]:
    """Return (key, kind). An explicit subject (an MCP server given its own
    principal) wins over the launching agent, so its baseline and drift are
    tracked apart — a rug-pull in one server is not lost in the agent's noise."""
    subject = summary.get("subject") or {}
    name = subject.get("name")
    if name:
        kind = subject.get("kind") or "command"
        return f"{kind}:{name}", kind
    if summary.get("agent"):
        return str(summary["agent"]), "agent"
    return _subject_key(summary), "command"


def _subject_key(summary: dict) -> str:
    if summary.get("agent"):
        return str(summary["agent"])
    argv = summary.get("argv") or []
    if argv:
        # Keep the script/module operand so `sh clean.sh` and `sh deploy.sh` do
        # not share a baseline. Arguments after it are task inputs, not identity.
        head = Path(str(argv[0])).name
        second = next((str(a) for a in argv[1:] if not str(a).startswith("-")), None)
        return " ".join([head] + ([second] if second else []))
    return summary.get("command") or summary.get("id") or "unknown"


def _path_scope(raw: str | None, cwd: str | None) -> str:
    """Reduce noisy absolute paths to portable security-relevant scopes."""
    if not raw:
        return "unknown"
    try:
        path = Path(raw).expanduser()
    except (TypeError, ValueError):
        return "unknown"
    value = os.path.normpath(str(path))
    home = os.path.normpath(str(Path.home()))
    work = os.path.normpath(cwd) if cwd else None

    def inside(child: str, parent: str) -> bool:
        try:
            return os.path.commonpath([child, parent]) == parent
        except (ValueError, OSError):
            return False

    basename = os.path.basename(value).lower()
    if work and inside(value, work):
        rel = os.path.relpath(value, work)
        if basename == ".env" or basename.startswith(".env."):
            return "project/.env*"
        if rel == ".git-credentials" or basename in {"id_rsa", "id_ed25519"}:
            return "project/credential-file"
        return "project/**"
    if inside(value, home):
        rel = os.path.relpath(value, home)
        sensitive = (
            (".ssh", "home/.ssh/**"), (".aws", "home/.aws/**"),
            (".gnupg", "home/.gnupg/**"), (".kube", "home/.kube/**"),
            (".docker", "home/.docker/**"), (".config/gcloud", "home/.config/gcloud/**"),
            ("library/keychains", "home/Library/Keychains/**"),
        )
        low = rel.lower()
        for prefix, scope in sensitive:
            if low == prefix or low.startswith(prefix + os.sep):
                return scope
        first = rel.split(os.sep, 1)[0]
        return f"home/{first}/**"
    if value.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")):
        return "temp/**"
    for prefix, label in (("/usr/", "system/usr/**"), ("/bin/", "system/bin/**"),
                          ("/sbin/", "system/sbin/**"), ("/System/", "system/System/**"),
                          ("/Library/", "system/Library/**")):
        if value.startswith(prefix):
            return label
    parts = [p for p in Path(value).parts if p not in (os.sep, "")]
    return "external/" + (parts[0] if parts else "unknown") + "/**"


def _cap(action: str, resource: str, **extra) -> dict:
    value = {"action": action, "resource": resource}
    value.update({k: v for k, v in extra.items() if v is not None})
    return value


def _unique(values: list[dict]) -> list[dict]:
    by_key = {_canon(value): value for value in values}
    return [by_key[key] for key in sorted(by_key)]


def build_manifest(summary: dict) -> dict:
    """Build one portable capability manifest from a session summary."""
    network = []
    for outcome in ("allowed", "warned", "blocked"):
        for event in summary.get(outcome, []):
            host = str(event.get("host") or "unknown").lower().rstrip(".")
            port = event.get("port")
            network.append(_cap("connect", host, port=port))
    # A single destination often surfaces as both a port-bearing net.connect and a
    # port-less net.request; keep the concrete-port form and drop its port-less
    # twin so one host is not counted (and later flagged as drift) twice.
    ported_hosts = {cap["resource"] for cap in network if cap.get("port")}
    network = [cap for cap in network if cap.get("port") or cap["resource"] not in ported_hosts]

    process, filesystem, ipc = [], [], []
    cwd = summary.get("cwd")
    for event in summary.get("deep_events", []):
        kind = event.get("kind")
        if kind == "proc.exec":
            path = event.get("path")
            process.append(_cap("exec", Path(path).name if path else "unknown"))
        elif kind in ("fs.open", "fs.create", "fs.write"):
            action = "read" if kind == "fs.open" else "write"
            filesystem.append(_cap(action, _path_scope(event.get("path"), cwd)))
        elif kind == "ipc.connect":
            ipc.append(_cap("connect", _path_scope(event.get("path"), cwd)))

    credential = [_cap("available", name) for name in summary.get("env_allowed", [])]
    capabilities = {
        "network": _unique(network),
        "process": _unique(process),
        "filesystem": _unique(filesystem),
        "ipc": _unique(ipc),
        "credential": _unique(credential),
    }
    argv = summary.get("argv") or []
    subject_key, subject_kind = _subject_identity(summary)
    subject = {
        "key": subject_key,
        "kind": subject_kind,
        "agent": summary.get("agent"),
        "name": (summary.get("subject") or {}).get("name"),
        "definition_sha256": (summary.get("subject") or {}).get("definition_sha256"),
        "executable": Path(str(argv[0])).name if argv else None,
        "executable_sha256": summary.get("executable_sha256"),
    }
    context = {
        "policy": summary.get("policy"),
        "policy_sha256": summary.get("policy_sha256"),
        "mode": summary.get("mode"),
        "backend": summary.get("backend"),
        "platform": summary.get("platform"),
        "workspace": Path(cwd).name if cwd else None,
    }
    core = {"subject": subject, "context": context, "capabilities": capabilities}
    return {
        "schema": MANIFEST_SCHEMA,
        "session": {
            "id": summary.get("id"), "timestamp": summary.get("ts"),
            "integrity_ok": bool(summary.get("integrity_ok")),
        },
        **core,
        "fingerprint": _sha(core),
        "coverage": {
            "network": ("hard" if summary.get("mode") == "enforce"
                        and summary.get("backend") == "seatbelt" else "best-effort"),
            "deep": bool(summary.get("deep_summary") or summary.get("deep_events")),
            "credentials": "env_allowed" in summary,
        },
    }


def manifest_for_session(session_id: str) -> dict:
    from . import sessions
    return build_manifest(sessions.summarize(session_id))


def write_manifest(manifest: dict, path: str | Path) -> Path:
    target = Path(path)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def _baseline_payload(baseline: dict) -> dict:
    return {k: v for k, v in baseline.items() if k != "signature"}


def approve(manifest: dict, name: str | None = None, *, force: bool = False) -> tuple[dict, Path]:
    """Explicitly approve and Ed25519-sign a manifest as the trusted baseline."""
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise BehaviorError("unsupported behavior manifest schema")
    if not manifest.get("session", {}).get("integrity_ok"):
        raise BehaviorError("cannot approve a session whose receipt is not intact")
    identity = name or default_baseline_name(manifest)
    if not identity:
        raise BehaviorError("baseline needs a subject name")
    target = baseline_path(identity)
    if target.exists() and not force:
        raise BehaviorError(f"baseline '{identity}' already exists; use --force to replace it")

    baseline = {
        "schema": BASELINE_SCHEMA,
        "name": identity,
        "state": "approved",
        "approved_at": round(time.time(), 3),
        "source_sessions": [manifest.get("session", {}).get("id")],
        "manifest_fingerprint": manifest.get("fingerprint"),
        "subject": manifest.get("subject", {}),
        "context": manifest.get("context", {}),
        "capabilities": manifest.get("capabilities", {}),
        "coverage": manifest.get("coverage", {}),
    }
    from . import crypto
    payload = _canon(baseline)
    sig, pub = crypto.sign_hex(payload)
    baseline["signature"] = {
        "algorithm": "ed25519", "public_key": pub, "value": sig,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(baseline, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    finally:
        os.close(fd)
    return baseline, target


def adopt(name: str, subject: dict, capabilities: dict, coverage: dict | None, *,
          provenance: dict, force: bool = False) -> tuple[dict, Path]:
    """Build and *locally* sign a baseline from explicit capabilities — e.g. one
    adopted from a signature-verified community registry entry. ``provenance``
    records where it came from; re-signing locally makes it a first-class baseline
    for diff/gate while keeping the original signer on record."""
    target = baseline_path(name)
    if target.exists() and not force:
        raise BehaviorError(f"baseline '{name}' already exists; use --force to replace it")
    baseline = {
        "schema": BASELINE_SCHEMA,
        "name": name,
        "state": "registry",
        "approved_at": round(time.time(), 3),
        "source_sessions": [],
        "manifest_fingerprint": None,
        "subject": subject,
        "context": {},
        "capabilities": capabilities,
        "coverage": coverage or {},
        "provenance": provenance,
    }
    from . import crypto
    payload = _canon(baseline)
    sig, pub = crypto.sign_hex(payload)
    baseline["signature"] = {
        "algorithm": "ed25519", "public_key": pub, "value": sig,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(baseline, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    finally:
        os.close(fd)
    return baseline, target


def verify_baseline(baseline: dict, expect_pubkey: str | None = None) -> tuple[bool, str]:
    if baseline.get("schema") != BASELINE_SCHEMA:
        return False, "unsupported baseline schema"
    signature = baseline.get("signature") or {}
    if signature.get("algorithm") != "ed25519":
        return False, "baseline is not Ed25519-signed"
    payload = _canon(_baseline_payload(baseline))
    digest = hashlib.sha256(payload).hexdigest()
    if digest != signature.get("payload_sha256"):
        return False, "baseline payload digest mismatch"
    pub = signature.get("public_key", "")
    if expect_pubkey and pub != expect_pubkey:
        return False, "baseline signing key does not match the expected key"
    from . import crypto
    if not crypto.verify_hex(payload, signature.get("value", ""), pub):
        return False, "baseline signature is invalid"
    return True, f"approved baseline signed by {pub[:12]}…"


def load_baseline(reference: str | Path, *, require_valid: bool = True) -> dict:
    direct = Path(reference).expanduser()
    target = direct if direct.exists() else baseline_path(str(reference))
    if not target.exists():
        raise BehaviorError(f"no approved baseline found for '{reference}'")
    try:
        baseline = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BehaviorError(f"cannot read baseline '{reference}': {exc}") from exc
    if require_valid:
        ok, reason = verify_baseline(baseline)
        if not ok:
            raise BehaviorError(f"refusing untrusted baseline: {reason}")
    return baseline


def baseline_for_manifest(manifest: dict) -> dict | None:
    name = default_baseline_name(manifest)
    if baseline_path(name).exists():
        return load_baseline(name)
    # A workspace-independent baseline named for the subject alone (e.g. a
    # community registry entry for an MCP server) applies in any project.
    key = manifest.get("subject", {}).get("key")
    if key and key != name and baseline_path(key).exists():
        return load_baseline(key)
    # A custom --name remains discoverable by the dashboard when it unambiguously
    # describes this subject/workspace cohort.
    matches = []
    for path in baselines_dir().glob("*.json"):
        try:
            candidate = load_baseline(path)
        except BehaviorError:
            continue
        if (candidate.get("subject", {}).get("key") == manifest.get("subject", {}).get("key")
                and candidate.get("context", {}).get("workspace")
                == manifest.get("context", {}).get("workspace")):
            matches.append(candidate)
    return matches[0] if len(matches) == 1 else None


def list_baselines() -> list[dict]:
    rows = []
    for path in sorted(baselines_dir().glob("*.json")):
        try:
            baseline = json.loads(path.read_text(encoding="utf-8"))
            ok, reason = verify_baseline(baseline)
            caps = baseline.get("capabilities", {})
            rows.append({
                "name": baseline.get("name") or path.stem,
                "approved_at": baseline.get("approved_at"),
                "source_sessions": baseline.get("source_sessions", []),
                "capability_count": sum(len(caps.get(c, [])) for c in CATEGORIES),
                "valid": ok, "verification": reason,
                "public_key": (baseline.get("signature") or {}).get("public_key"),
            })
        except (OSError, ValueError):
            rows.append({"name": path.stem, "valid": False,
                         "verification": "baseline file is not valid JSON"})
    return rows


def _cap_map(capabilities: dict, category: str) -> dict[bytes, dict]:
    return {_canon(cap): cap for cap in capabilities.get(category, [])}


def _severity(category: str, capability: dict) -> tuple[str, str]:
    action = capability.get("action")
    resource = str(capability.get("resource") or "unknown")
    low = resource.lower()
    if category == "credential":
        return "high", f"credential variable {resource} became available to the process"
    if category in ("filesystem", "ipc"):
        if any(secret in low for secret in (".ssh", ".aws", ".gnupg", ".kube",
                                             ".docker", "keychains", ".env", "credential")):
            return "critical", f"new {action} capability touches a credential-bearing scope"
        if low.startswith("home/") or low.startswith("external/"):
            return "high", f"new {action} capability reaches outside the project"
        if low == "project/**" or low.startswith("temp/"):
            return "low", f"new {action} capability is confined to a normal work scope"
        return "medium", f"new {action} capability affects {resource}"
    if category == "process":
        dangerous = {"ssh", "scp", "sftp", "curl", "wget", "nc", "ncat", "socat",
                     "aws", "gcloud", "kubectl", "docker", "podman", "osascript"}
        if Path(low).name in dangerous:
            return "high", f"new execution capability invokes security-sensitive tool {resource}"
        return "medium", f"new executable {resource} appeared in the process tree"
    if category == "network":
        from .intelligence import classify_host
        cls, reason = classify_host(resource)
        if cls == "suspicious":
            return "critical", f"new destination is suspicious: {reason}"
        if cls == "unrecognized":
            return "high", "new destination is not recognized as provider or developer infrastructure"
        if cls == "cloud":
            return "medium", "new destination is general-purpose cloud infrastructure"
        return "low", f"new destination is classified as {cls}"
    return "medium", "new behavior capability"


def diff(manifest: dict, baseline: dict) -> dict:
    """Explain a manifest's differences from one verified, approved baseline."""
    ok, verification = verify_baseline(baseline)
    if not ok:
        raise BehaviorError(f"refusing untrusted baseline: {verification}")
    new, removed, findings = {}, {}, []
    for category in CATEGORIES:
        observed = _cap_map(manifest.get("capabilities", {}), category)
        approved = _cap_map(baseline.get("capabilities", {}), category)
        new[category] = [observed[key] for key in sorted(observed.keys() - approved.keys())]
        removed[category] = [approved[key] for key in sorted(approved.keys() - observed.keys())]
        for capability in new[category]:
            severity, reason = _severity(category, capability)
            findings.append({"category": category, "capability": capability,
                             "severity": severity, "reason": reason})

    identity_changes = []
    for field, label in (("definition_sha256", "MCP definition digest"),
                         ("executable_sha256", "executable digest")):
        old = baseline.get("subject", {}).get(field)
        current = manifest.get("subject", {}).get(field)
        if old and current and old != current:
            identity_changes.append({"field": field, "before": old, "after": current,
                                     "severity": "high", "reason": f"{label} changed"})
    old_policy = baseline.get("context", {}).get("policy_sha256")
    new_policy = manifest.get("context", {}).get("policy_sha256")
    if old_policy and new_policy and old_policy != new_policy:
        identity_changes.append({"field": "policy_sha256", "before": old_policy,
                                 "after": new_policy, "severity": "medium",
                                 "reason": "the enforced policy changed"})

    old_context = baseline.get("context", {})
    new_context = manifest.get("context", {})
    for field, label in (("mode", "enforcement mode"), ("backend", "enforcement backend"),
                         ("platform", "runtime platform")):
        old, current = old_context.get(field), new_context.get(field)
        if old and current and old != current:
            severity = "critical" if field == "mode" and old == "enforce" else (
                "high" if field in ("mode", "backend") else "medium")
            identity_changes.append({"field": field, "before": old, "after": current,
                                     "severity": severity, "reason": f"{label} changed"})

    old_coverage = baseline.get("coverage", {})
    new_coverage = manifest.get("coverage", {})
    if old_coverage.get("network") == "hard" and new_coverage.get("network") != "hard":
        identity_changes.append({"field": "coverage.network", "before": "hard",
                                 "after": new_coverage.get("network"), "severity": "high",
                                 "reason": "network evidence coverage weakened"})
    for field in ("deep", "credentials"):
        if old_coverage.get(field) is True and new_coverage.get(field) is not True:
            identity_changes.append({"field": f"coverage.{field}", "before": True,
                                     "after": new_coverage.get(field), "severity": "high",
                                     "reason": f"{field} evidence coverage weakened"})

    severities = [f["severity"] for f in findings + identity_changes]
    highest = max(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else "none"
    new_count = sum(len(v) for v in new.values())
    removed_count = sum(len(v) for v in removed.values())
    return {
        "schema": "warden.behavior-diff/v1",
        "baseline": baseline.get("name"),
        "session": manifest.get("session", {}).get("id"),
        "subject": manifest.get("subject", {}).get("key"),
        "baseline_verified": True,
        "verification": verification,
        "status": "drift" if new_count or identity_changes else "stable",
        "highest_severity": highest,
        # A "stable" verdict is only meaningful if the observed session's own
        # receipt is intact — a tampered log can hide capabilities by dropping
        # events. Surface it so callers never certify drift-free from a bad log.
        "session_integrity_ok": bool(manifest.get("session", {}).get("integrity_ok")),
        "new_count": new_count,
        "removed_count": removed_count,
        "new": new,
        "removed": removed,
        "identity_changes": identity_changes,
        "findings": sorted(findings, key=lambda f: (-SEVERITY_ORDER[f["severity"]],
                                                     f["category"], _canon(f["capability"]))),
        "coverage": manifest.get("coverage", {}),
    }


def session_diff(summary: dict, reference: str | Path | None = None) -> dict | None:
    manifest = build_manifest(summary)
    baseline = load_baseline(reference) if reference else baseline_for_manifest(manifest)
    return diff(manifest, baseline) if baseline else None


def dashboard_state(summaries: list[dict] | None = None) -> dict:
    """Return latest approved drift per subject plus explicit coverage gaps."""
    if summaries is None:
        from . import sessions
        summaries = [sessions.summarize(sid) for sid in sessions.list_session_ids()]
    latest: dict[str, tuple[dict, dict]] = {}
    counts: dict[str, int] = {}
    for summary in summaries:
        manifest = build_manifest(summary)
        key = default_baseline_name(manifest)
        counts[key] = counts.get(key, 0) + 1
        ts = manifest.get("session", {}).get("timestamp") or 0
        if key not in latest or ts > (latest[key][0].get("session", {}).get("timestamp") or 0):
            latest[key] = (manifest, summary)

    findings, unbaselined, stable = [], [], []
    for key, (manifest, _summary) in sorted(latest.items()):
        try:
            baseline = baseline_for_manifest(manifest)
        except BehaviorError as exc:
            findings.append({"subject": key, "session": manifest["session"]["id"],
                             "highest_severity": "critical", "new_count": 0,
                             "new": {category: [] for category in CATEGORIES},
                             "findings": [], "identity_changes": [],
                             "invalid_baseline": True, "error": str(exc)})
            continue
        if baseline is None:
            unbaselined.append({"subject": key, "sessions": counts[key],
                               "latest_session": manifest["session"]["id"],
                               "capability_count": sum(len(manifest["capabilities"][c])
                                                       for c in CATEGORIES)})
            continue
        result = diff(manifest, baseline)
        row = {"subject": key, "session": result["session"],
               "highest_severity": result["highest_severity"],
               "new_count": result["new_count"], "new": result["new"],
               "findings": result["findings"],
               "identity_changes": result["identity_changes"]}
        (findings if result["status"] == "drift" else stable).append(row)
    return {
        "baselines": list_baselines(),
        "findings": sorted(findings, key=lambda r: -SEVERITY_ORDER[r["highest_severity"]]),
        "unbaselined": unbaselined,
        "stable": stable,
        "coverage": {
            "subjects": len(latest),
            "approved": len(stable) + sum(not row.get("invalid_baseline") for row in findings),
            "unapproved": len(unbaselined) + sum(bool(row.get("invalid_baseline")) for row in findings),
        },
    }
