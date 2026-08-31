"""A signed, offline-verifiable community registry of reviewed behavior profiles.

Approving a baseline is per-machine work. Most people run the same handful of
popular MCP servers and skills, so that review should be shareable — but only if
it is *verifiable*. A registry entry is an Ed25519-signed description of what a
named server/skill is expected to do; you adopt one only after checking it was
signed by a key you explicitly trust, and adopting it re-signs a local baseline
so drift and CI gates work against it.

No network, no Warden Cloud: a registry is just a directory of signed JSON files
(clone it, or receive it any way you like). Contributors `publish` a reviewed
baseline as an entry and open a pull request; reviewers' keys are what other
users `trust`. Deny-of-trust is the default — an unsigned or untrusted entry is
never adopted.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

ENTRY_SCHEMA = "warden.registry-entry/v1"
CATEGORIES = ("network", "process", "filesystem", "ipc", "credential")


class RegistryError(ValueError):
    """Raised when a registry entry or trust decision cannot be honored."""


def _canon(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _registry_home() -> Path:
    base = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden")) / "registry"
    base.mkdir(parents=True, exist_ok=True)
    try:
        base.chmod(0o700)
    except OSError:
        pass
    return base


def entries_dir() -> Path:
    path = _registry_home() / "entries"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _trust_path() -> Path:
    return _registry_home() / "trusted_keys.json"


# --------------------------------------------------------------------------
# Trust store — the set of publisher keys this machine will accept entries from.
# --------------------------------------------------------------------------

def trusted_keys() -> list[dict]:
    path = _trust_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return list(data.get("keys", []))


def is_trusted(public_key: str) -> bool:
    return any(entry.get("public_key") == public_key for entry in trusted_keys())


def trust_key(public_key: str, label: str = "") -> dict:
    public_key = public_key.strip().lower()
    if len(public_key) != 64 or any(c not in "0123456789abcdef" for c in public_key):
        raise RegistryError("a trusted key must be a 64-character hex Ed25519 public key")
    keys = [k for k in trusted_keys() if k.get("public_key") != public_key]
    record = {"public_key": public_key, "label": label, "added_at": round(time.time(), 3)}
    keys.append(record)
    _write_trust(keys)
    return record


def untrust_key(public_key: str) -> bool:
    public_key = public_key.strip().lower()
    keys = trusted_keys()
    remaining = [k for k in keys if k.get("public_key") != public_key]
    if len(remaining) == len(keys):
        return False
    _write_trust(remaining)
    return True


def _write_trust(keys: list[dict]) -> None:
    path = _trust_path()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"keys": keys}, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# Entries — build, sign, verify.
# --------------------------------------------------------------------------

def _entry_payload(entry: dict) -> dict:
    # Exclude the signature and any internal annotations (e.g. the "_path" added
    # when loading from disk) so the canonical payload matches what was signed.
    return {k: v for k, v in entry.items()
            if k != "signature" and not k.startswith("_")}


def build_entry(*, subject: dict, capabilities: dict, coverage: dict | None,
                provenance: dict, policy: dict | None = None) -> dict:
    """Assemble and locally sign a registry entry from reviewed capabilities, and
    optionally a reviewed least-privilege policy for the same subject."""
    from . import __version__, crypto

    clean_caps = {category: list(capabilities.get(category, [])) for category in CATEGORIES}
    entry = {
        "schema": ENTRY_SCHEMA,
        "subject": {
            "name": subject.get("name") or subject.get("key"),
            "kind": subject.get("kind") or "command",
            "definition_sha256": subject.get("definition_sha256"),
        },
        "capabilities": clean_caps,
        "coverage": coverage or {},
        "provenance": {
            "reviewer": provenance.get("reviewer", ""),
            "reviewed_at": round(time.time(), 3),
            "source": provenance.get("source", ""),
            "notes": provenance.get("notes", ""),
            "warden_version": __version__,
        },
    }
    if policy is not None:
        entry["policy"] = policy
    payload = _canon(entry)
    sig, pub = crypto.sign_hex(payload)
    entry["signature"] = {
        "algorithm": "ed25519", "public_key": pub, "value": sig,
        "payload_sha256": _sha(payload),
    }
    return entry


def entry_from_baseline(baseline: dict, provenance: dict, policy: dict | None = None) -> dict:
    """Turn one locally-approved behavior baseline into a shareable entry."""
    subject = dict(baseline.get("subject", {}))
    if not subject.get("name"):
        subject["name"] = subject.get("key")
    return build_entry(subject=subject, capabilities=baseline.get("capabilities", {}),
                       coverage=baseline.get("coverage", {}), provenance=provenance,
                       policy=policy)


def verify_entry(entry: dict) -> tuple[bool, str, str]:
    """Check an entry's signature is internally valid. Returns (ok, reason, signer)."""
    if entry.get("schema") != ENTRY_SCHEMA:
        return False, "unsupported registry entry schema", ""
    signature = entry.get("signature") or {}
    if signature.get("algorithm") != "ed25519":
        return False, "entry is not Ed25519-signed", ""
    payload = _canon(_entry_payload(entry))
    if _sha(payload) != signature.get("payload_sha256"):
        return False, "entry payload digest mismatch", ""
    pub = signature.get("public_key", "")
    from . import crypto
    if not crypto.verify_hex(payload, signature.get("value", ""), pub):
        return False, "entry signature is invalid", pub
    return True, f"signed by {pub[:12]}…", pub


def entry_trust(entry: dict) -> tuple[bool, str, str]:
    """Verify signature AND that the signer is explicitly trusted."""
    ok, reason, signer = verify_entry(entry)
    if not ok:
        return False, reason, signer
    if not is_trusted(signer):
        return False, (f"signer {signer[:12]}… is not trusted — add it with "
                       "`warden registry trust <key>` if you have reviewed it"), signer
    return True, f"trusted, signed by {signer[:12]}…", signer


# --------------------------------------------------------------------------
# Registry sources — directories/files of signed entries.
# --------------------------------------------------------------------------

def _iter_entry_files(paths):
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            yield from sorted(p.glob("*.json"))
        elif p.exists():
            yield p


def load_entries(paths=None) -> list[dict]:
    """Read entries from the given files/dirs, or the local registry by default."""
    sources = list(paths) if paths else [entries_dir()]
    out = []
    for file in _iter_entry_files(sources):
        try:
            entry = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(entry, dict) and entry.get("schema") == ENTRY_SCHEMA:
            entry["_path"] = str(file)
            out.append(entry)
    return out


def find_entry(name: str, kind: str | None = None, paths=None) -> dict | None:
    for entry in load_entries(paths):
        subject = entry.get("subject", {})
        if subject.get("name") == name and (kind is None or subject.get("kind") == kind):
            return entry
    return None


def publish(entry: dict, out_path: str | Path) -> Path:
    target = Path(out_path)
    target.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def install(entry: dict, *, force: bool = False) -> tuple[dict, Path]:
    """Adopt a *trusted* entry as a local, locally-signed baseline for diff/gate."""
    ok, reason, signer = entry_trust(entry)
    if not ok:
        raise RegistryError(f"refusing to install: {reason}")
    from . import behavior

    subject = entry.get("subject", {})
    kind = subject.get("kind") or "command"
    name = subject.get("name")
    if not name:
        raise RegistryError("registry entry has no subject name")
    key = f"{kind}:{name}"
    baseline_subject = {
        "key": key, "kind": kind, "name": name,
        "definition_sha256": subject.get("definition_sha256"),
    }
    provenance = {
        "source": "registry",
        "registry_signer": signer,
        "entry_sha256": _sha(_canon(_entry_payload(entry))),
        "reviewer": entry.get("provenance", {}).get("reviewer", ""),
        "review_source": entry.get("provenance", {}).get("source", ""),
    }
    return behavior.adopt(key, baseline_subject, entry.get("capabilities", {}),
                          entry.get("coverage", {}), provenance=provenance, force=force)
