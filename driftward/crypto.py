"""Ed25519 signing for tamper-*proof* receipts, pure standard library.

Driftward's hash chain makes a log tamper-*evident* (you can tell it was altered).
Signing the final seal with Ed25519 makes a receipt tamper-*proof and portable*:
anyone with the public key can verify the log is authentic and unmodified,
without trusting the machine that produced it — which is what turns a session
log into compliance and incident-response evidence.

This is a compact implementation of Ed25519 (RFC 8032) using only Python's
integer arithmetic and hashlib. It is validated against the RFC 8032 test
vectors in the test suite. It is not constant-time; that is acceptable here
because Driftward signs its own local logs with a local key — there is no remote
attacker measuring signing time.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# ---- Ed25519 core (RFC 8032, ref-style) --------------------------------

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _q, y3 % _q, z3 % _q, t3 % _q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    x, y, z, t = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk: bytes) -> bytes:
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _Hint(m: bytes) -> int:
    h = _H(m)
    return int.from_bytes(h, "little")


def sign(message: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    r = _Hint(h[_b // 8:_b // 4] + message)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + message) * a) % _L
    return _encodepoint(R) + _encodeint(S)


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = (x, y, 1, (x * y) % _q)
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def _isoncurve(P) -> bool:
    x, y, z, t = P
    return (
        z % _q != 0
        and x * y % _q == z * t % _q
        and (y * y - x * x - z * z - _d * t * t) % _q == 0
    )


def verify(signature: bytes, message: bytes, pk: bytes) -> bool:
    if len(signature) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(pk)
        S = int.from_bytes(signature[32:], "little")
        h = _Hint(signature[:32] + pk + message)
        x1, y1, z1, t1 = _scalarmult(_B, S)
        x2, y2, z2, t2 = _edwards_add(R, _scalarmult(A, h))
        return (x1 * z2 - x2 * z1) % _q == 0 and (y1 * z2 - y2 * z1) % _q == 0
    except (ValueError, IndexError, OverflowError):
        return False


# ---- key management ----------------------------------------------------

def _key_dir() -> Path:
    base = Path(os.environ.get("DRIFTWARD_HOME", Path.home() / ".driftward"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def ensure_key() -> tuple[bytes, bytes]:
    """Return (seed, public_key), generating a per-machine key on first use."""
    kd = _key_dir()
    seed_path = kd / "signing.key"
    if seed_path.exists():
        seed = seed_path.read_bytes()
        if len(seed) != 32:
            raise ValueError("corrupt signing key")
    else:
        seed = os.urandom(32)
        # 0600 permissions; never leaves the machine.
        fd = os.open(str(seed_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, seed)
        finally:
            os.close(fd)
    pk = publickey(seed)
    (kd / "signing.pub").write_text(pk.hex() + "\n", encoding="utf-8")
    return seed, pk


def public_key_hex() -> str:
    _, pk = ensure_key()
    return pk.hex()


def sign_hex(message: bytes) -> tuple[str, str]:
    """Sign `message`, returning (signature_hex, public_key_hex)."""
    seed, pk = ensure_key()
    sig = sign(message, seed, pk)
    return sig.hex(), pk.hex()


def verify_hex(message: bytes, signature_hex: str, pk_hex: str) -> bool:
    try:
        return verify(bytes.fromhex(signature_hex), message, bytes.fromhex(pk_hex))
    except ValueError:
        return False
