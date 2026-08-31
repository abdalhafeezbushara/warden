"""Enforcement backend selection: the right sandbox for the current OS.

Keeps the runner platform-agnostic. Each backend turns (policy, argv) into a
wrapped command that enforces the policy, or reports that enforcement is
unavailable. Enforced runs fail closed unless the caller explicitly opts into a
record-only fallback.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from .policy import Policy


class BackendUnavailable(Exception):
    pass


def selected() -> str:
    """Name of the backend for this platform, or 'none'."""
    if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists():
        return "seatbelt"
    if sys.platform.startswith("linux"):
        from . import linux
        # Require bwrap to actually work — present-but-can't-create-namespaces
        # (default Docker, hardened distros) must not be reported as enforcing.
        if linux.bubblewrap_works():
            return "bubblewrap"
    return "none"


def unavailable_reason() -> str:
    """Human explanation for why no backend is active, for a clear message."""
    if sys.platform.startswith("linux"):
        from . import linux
        if linux.bubblewrap_available() and not linux.bubblewrap_works():
            return ("bubblewrap is installed but cannot create user namespaces "
                    "(disabled on this host). Enforcement is OFF. Fixes: install the "
                    "bwrap AppArmor profile, use a setuid bwrap, or enable "
                    "kernel.unprivileged_userns_clone. See docs/LIMITATIONS.md.")
        if not linux.bubblewrap_available():
            return "bubblewrap not installed (apt/dnf/pacman install bubblewrap)."
    return f"no enforcement backend on {sys.platform}."


def wrap(policy: Policy, argv: list[str], proxy_port: int | None,
         broker_port: int | None = None):
    """Return (wrapped_argv, cleanup, backend_name).

    Raises BackendUnavailable when no enforcement backend exists here.
    """
    backend = selected()
    if backend == "seatbelt":
        from . import seatbelt
        profile = seatbelt.compile_profile(policy, proxy_port, broker_port=broker_port)
        fd, path = tempfile.mkstemp(prefix="warden-", suffix=".sb")
        os.close(fd)  # mkstemp returns an open fd; close it to avoid a leak
        pf = Path(path)
        pf.write_text(profile, encoding="utf-8")

        def cleanup():
            try:
                pf.unlink()
            except OSError:
                pass

        return ["/usr/bin/sandbox-exec", "-f", str(pf), *argv], cleanup, "seatbelt"

    if backend == "bubblewrap":
        from . import linux
        cmd = linux.bwrap_command(policy, argv, proxy_port)
        return cmd, (lambda: None), "bubblewrap"

    raise BackendUnavailable(f"no enforcement backend on {sys.platform}")
