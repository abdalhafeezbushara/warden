"""Enforcement backend selection: the right sandbox for the current OS.

Keeps the runner platform-agnostic. Each backend turns (policy, argv) into a
wrapped command that enforces the policy, or reports that enforcement is
unavailable here (so the runner degrades to record-only rather than pretending).
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
        if linux.bubblewrap_available():
            return "bubblewrap"
    return "none"


def wrap(policy: Policy, argv: list[str], proxy_port: int | None):
    """Return (wrapped_argv, cleanup, backend_name).

    Raises BackendUnavailable when no enforcement backend exists here.
    """
    backend = selected()
    if backend == "seatbelt":
        from . import seatbelt
        profile = seatbelt.compile_profile(policy, proxy_port)
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
