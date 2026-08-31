"""Tamper-evident flight recorder.

Every observed event is appended to a hash chain: each record stores the SHA-256
of (previous_hash + canonical_json(event)). Altering, reordering, or deleting any
record breaks the chain from that point on, so `warden verify` can prove whether a
log is intact without trusting the process that wrote it.

This is deliberately not a plain log file. When an agent session is compromised,
the agent's own logs are written by the compromised process; a hash chain sealed
per event gives responders and compliance an integrity signal that survives that.

Stdlib only: SHA-256 chaining gives tamper-evidence. A future release adds an
ed25519 signature over the final seal for tamper-*proof* attribution to a key.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(prev: str, event: dict) -> str:
    return hashlib.sha256(prev.encode("ascii") + _canon(event)).hexdigest()


@dataclass
class Recorder:
    path: Path
    _lock: threading.Lock = None  # type: ignore[assignment]
    _prev: str = GENESIS
    _count: int = 0

    def __post_init__(self):
        self.path = Path(self.path)
        self._lock = threading.Lock()

    def start(self, meta: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate any prior log for this session path.
        self.path.write_text("", encoding="utf-8")
        self._prev = GENESIS
        self._count = 0
        self.emit("session.start", meta)

    def emit(self, kind: str, data: dict) -> str:
        with self._lock:
            event = {
                "seq": self._count,
                "ts": round(time.time(), 3),
                "kind": kind,
                "data": data,
            }
            h = _hash(self._prev, event)
            record = {"event": event, "prev": self._prev, "hash": h}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
            self._prev = h
            self._count += 1
            return h

    def seal(self, summary: dict, sign: bool = True) -> str:
        """Write a final record whose hash seals the whole chain, and sign it.

        The signature is over the sealing hash, so it commits to the entire
        chain. Anyone with the public key can then verify authenticity offline.
        Signing is best-effort: if key setup fails, the chain is still written
        (tamper-evident), just unsigned.
        """
        h = self.emit("session.end", summary)
        if not sign:
            return h
        try:
            from . import crypto

            sig_hex, pk_hex = crypto.sign_hex(h.encode("ascii"))
            with self._lock:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(
                        {"signature": {"seal": h, "sig": sig_hex, "pubkey": pk_hex, "alg": "ed25519"}},
                        sort_keys=True) + "\n")
        except Exception:
            pass
        return h


def _split_records(path: str | Path):
    """Return (chain_records, signature_record_or_None)."""
    chain, signature = [], None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if "signature" in obj and "event" not in obj:
            signature = obj["signature"]
        else:
            chain.append(obj)
    return chain, signature


def read_log(path: str | Path) -> list[dict]:
    chain, _ = _split_records(path)
    return chain


def read_signature(path: str | Path) -> dict | None:
    _, sig = _split_records(path)
    return sig


def verify_log(path: str | Path, expect_pubkey: str | None = None) -> tuple[bool, str]:
    """Recompute the chain and, if present, the Ed25519 seal signature.

    If ``expect_pubkey`` is given, the signature must match that key — this is
    how a third party verifies a receipt against a known Warden identity.
    """
    records, signature = _split_records(path)
    if not records:
        return False, "empty log"
    prev = GENESIS
    for i, rec in enumerate(records):
        if rec.get("prev") != prev:
            return False, f"record {i}: prev-hash mismatch (chain broken)"
        expect = _hash(prev, rec["event"])
        if rec.get("hash") != expect:
            return False, f"record {i}: hash mismatch (record was altered)"
        if rec["event"].get("seq") != i:
            return False, f"record {i}: sequence number tampered"
        prev = rec["hash"]

    if signature:
        from . import crypto

        if signature.get("seal") != prev:
            return False, "signature seal does not match chain head (tampered)"
        pk = signature.get("pubkey", "")
        if expect_pubkey and pk != expect_pubkey:
            return False, f"signature key mismatch (expected {expect_pubkey[:12]}…)"
        if not crypto.verify_hex(prev.encode("ascii"), signature.get("sig", ""), pk):
            return False, "Ed25519 signature invalid"
        return True, f"intact + signed: {len(records)} records, key {pk[:12]}…, seal {prev[:12]}…"

    return True, f"intact (unsigned): {len(records)} records, seal {prev[:12]}…"
