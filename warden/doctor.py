"""`warden doctor` — verify Warden actually works on this machine.

Most security tools ask you to trust that they enforce. Warden proves it: the
doctor performs a *live* enforcement test — it writes a throwaway secret,
compiles a real deny policy, and confirms the sandbox blocks the read — plus a
signing round-trip and environment checks. If doctor is green, the guarantees in
the README hold here, not just in principle.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import crypto
from .policy import FilesystemRules, NetworkRules, Policy, ProcessRules

OK = "  \033[32mPASS\033[0m"
BAD = "  \033[31mFAIL\033[0m"
WARN = "  \033[33mWARN\033[0m"


def _p(mark: str, text: str, detail: str = ""):
    line = f"{mark}  {text}"
    if detail:
        line += f"\n        {detail}"
    print(line)


def _no_color():
    return not sys.stdout.isatty() or os.environ.get("NO_COLOR")


def run() -> int:
    ok = bad = warn = 0
    strip = _no_color()

    def mark(kind):
        m = {"ok": OK, "bad": BAD, "warn": WARN}[kind]
        return m.replace("\033[32m", "").replace("\033[31m", "").replace("\033[33m", "").replace("\033[0m", "") if strip else m

    print("Warden doctor — checking this machine\n")

    # 1. Python
    if sys.version_info >= (3, 11):
        _p(mark("ok"), f"Python {platform.python_version()} (>= 3.11)")
        ok += 1
    else:
        _p(mark("bad"), f"Python {platform.python_version()} is too old; need 3.11+")
        bad += 1

    # 2. Enforcement backend for this platform
    from . import backends
    backend = backends.selected()
    if backend == "seatbelt":
        _p(mark("ok"), "macOS Seatbelt (sandbox-exec) available")
        ok += 1
    elif backend == "bubblewrap":
        _p(mark("ok"), "Linux bubblewrap (bwrap) available")
        ok += 1
    else:
        _p(mark("warn"),
           f"no enforcement backend on {platform.system()} (recording still works); "
           "install bubblewrap on Linux for enforcement")
        warn += 1

    # 3. LIVE enforcement test (the important one) — via the selected backend
    if backend in ("seatbelt", "bubblewrap"):
        if _live_enforcement_test():
            _p(mark("ok"), f"Live enforcement test ({backend}): a denied secret was actually blocked")
            ok += 1
        else:
            _p(mark("bad"), "Live enforcement test FAILED — a denied path was still readable",
               "Warden could not enforce on this machine. Do not rely on it here.")
            bad += 1

    # 4. Signing round-trip
    try:
        seed, pk = crypto.ensure_key()
        sig = crypto.sign(b"warden-doctor", seed, pk)
        if crypto.verify(sig, b"warden-doctor", pk) and not crypto.verify(sig, b"x", pk):
            _p(mark("ok"), f"Ed25519 signing works (key {pk.hex()[:12]}…)")
            ok += 1
        else:
            _p(mark("bad"), "Signing round-trip failed")
            bad += 1
    except Exception as exc:
        _p(mark("bad"), f"Signing unavailable: {exc}")
        bad += 1

    # 5. Session store writable
    try:
        base = Path(os.environ.get("WARDEN_HOME", Path.home() / ".warden")) / "sessions"
        base.mkdir(parents=True, exist_ok=True)
        probe = base / ".doctor-probe"
        probe.write_text("ok")
        probe.unlink()
        _p(mark("ok"), f"Session store writable ({base})")
        ok += 1
    except Exception as exc:
        _p(mark("bad"), f"Cannot write session store: {exc}")
        bad += 1

    print(f"\n{ok} passed, {warn} warning(s), {bad} failed.")
    if bad:
        print("Warden is NOT fully functional on this machine. See failures above.")
        return 1
    print("Warden is ready.")
    return 0


def _live_enforcement_test() -> bool:
    """Write a secret, deny it through the platform's backend, confirm it is
    unreadable. Works for both Seatbelt (macOS) and bubblewrap (Linux)."""
    from . import backends

    # /private/tmp resolves cleanly on macOS; on Linux /tmp is fine.
    root = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    tmp = Path(tempfile.mkdtemp(prefix="warden-doctor-", dir=root))
    try:
        secret_dir = tmp / "secret"
        secret_dir.mkdir()
        secret = secret_dir / "k.txt"
        token = "WARDEN-DOCTOR-CANARY-4f2a"
        secret.write_text(token)
        if secret.read_text() != token:  # baseline: readable unsandboxed
            return False

        pol = Policy(
            name="doctor",
            filesystem=FilesystemRules(read=[str(tmp) + "/**"], write=[str(tmp) + "/**"],
                                       deny=[str(secret_dir) + "/**"]),
            network=NetworkRules(deny_all_other=False),
            process=ProcessRules(),
        )
        cat = "/bin/cat"
        cmd, cleanup, _ = backends.wrap(pol, [cat, str(secret)], None)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        finally:
            cleanup()
        return res.returncode != 0 and token not in res.stdout
    except Exception:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
