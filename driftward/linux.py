"""Linux enforcement backend via bubblewrap (bwrap).

Mirrors the Seatbelt model with mount namespaces, the same approach Anthropic's
own sandbox-runtime uses on Linux:

  * allow-by-default        →  --ro-bind / /   (whole host visible, read-only)
  * writable project tree   →  --bind <dir> <dir>
  * deny a credential dir   →  --tmpfs <dir>            (appears empty)
  * deny a single secret    →  --ro-bind /dev/null <file>
  * deny exec of a binary   →  --ro-bind /dev/null <path-to-binary>
  * strict writes           →  start from an empty root, bind only system dirs
                               + the project (default-deny writes by omission)

Network: the child gets HTTP(S)_PROXY pointing at Driftward's loopback proxy so
egress is recorded. Hard-pinning egress into a fresh network namespace
(--unshare-net) plus an AF_UNIX/socat bridge is the stronger v2 posture and is
noted in docs; this v1 keeps the proxy reachable and records cooperating clients,
matching the documented recording assumption.

bwrap runs unprivileged via user namespaces. Where a hardened distro disables
those (e.g. Ubuntu's AppArmor userns restriction), bwrap fails and Driftward
refuses to start an enforced child. Proxy-only fallback requires an explicit
`--allow-record-fallback` opt-in — never a silent false sense of enforcement.

This module only *generates* the command (fully unit-tested); running it is the
job of the runner on a Linux host and of CI.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .policy import Policy


def bubblewrap_available() -> bool:
    return shutil.which("bwrap") is not None


_bwrap_works_cache: bool | None = None


def bubblewrap_works() -> bool:
    """bwrap is present AND can actually create the namespaces it needs (cached).

    On default Docker and some hardened distros (Ubuntu's AppArmor restriction,
    userns sysctl off) unprivileged user namespaces are disabled and bwrap fails
    at `Creating new namespace`. Probing here lets Driftward report honestly instead
    of dying with a cryptic error mid-run."""
    global _bwrap_works_cache
    if _bwrap_works_cache is not None:
        return _bwrap_works_cache
    if not bubblewrap_available():
        _bwrap_works_cache = False
        return False
    import subprocess

    try:
        r = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-user",
                            "--unshare-net", "--", "/bin/true"],
                           capture_output=True, timeout=10)
        _bwrap_works_cache = r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        _bwrap_works_cache = False
    return _bwrap_works_cache


def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def _real(path: str) -> str:
    """Resolve the longest existing prefix so masks land on the real inode
    (credential dirs like ~/.aws are frequently symlinks)."""
    p = Path(_expand(path))
    existing = p
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    try:
        base = os.path.realpath(existing)
    except OSError:
        base = str(existing)
    if existing == p:
        return base
    return base + str(p)[len(str(existing)):]


def _deny_root(path: str) -> str:
    """The literal directory/file a glob refers to (drop trailing wildcards)."""
    for suffix in ("/**", "/*"):
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return path


def bwrap_command(policy: Policy, argv: list[str], proxy_port: int | None = None,
                  workdir: str | None = None) -> list[str]:
    """Build the bubblewrap invocation enforcing `policy` around `argv`."""
    workdir = workdir or os.getcwd()
    cmd: list[str] = ["bwrap"]

    if policy.strict_fs:
        # Default-deny writes: empty root, bind only what's needed read-only,
        # then the project read-write.
        cmd += ["--ro-bind", "/usr", "/usr", "--ro-bind-try", "/bin", "/bin",
                "--ro-bind-try", "/sbin", "/sbin", "--ro-bind-try", "/lib", "/lib",
                "--ro-bind-try", "/lib64", "/lib64", "--ro-bind-try", "/etc", "/etc"]
    else:
        # Allow-by-default: whole host read-only.
        cmd += ["--ro-bind", "/", "/"]

    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]

    # Enforce filesystem.read on Linux. In strict-fs the root starts empty, so
    # explicit read roots must be mounted. Otherwise overlay the real home with
    # an empty tmpfs, then reveal only the declared read roots beneath it.
    if policy.strict_read and not policy.strict_fs:
        cmd += ["--tmpfs", _real(os.path.expanduser("~"))]
    if policy.strict_read or policy.strict_fs:
        for readable in policy.filesystem.read:
            real = _real(_deny_root(readable))
            if os.path.exists(real):
                cmd += ["--ro-bind", real, real]

    # Writable trees.
    for w in policy.filesystem.write:
        real = _real(_deny_root(w))
        if os.path.exists(real):
            cmd += ["--bind", real, real]
    real_wd = _real(workdir)
    cmd += ["--bind", real_wd, real_wd, "--chdir", real_wd]

    # Deny credential paths:
    #   dir glob  (~/.ssh/**)  → --tmpfs  (dir appears empty)
    #   leading ** (**/.env)   → mask that filename in each writable tree
    #                            (bwrap can't glob; a mangled path with '*' would
    #                             silently no-op and leave the secret readable)
    #   literal file (~/.netrc)→ --ro-bind /dev/null over it
    writable_roots = [real_wd] + [_real(_deny_root(w)) for w in policy.filesystem.write]
    for d in policy.filesystem.deny:
        if d.endswith("/**") or d.endswith("/*"):
            cmd += ["--tmpfs", _real(_deny_root(d))]
        elif d.startswith("**/"):
            name = d[3:]
            if "*" not in name and "?" not in name:
                # Mask this filename at the root of every writable tree — the
                # realistic case (a project-level .env the agent could read/exfil).
                for root in writable_roots:
                    cmd += ["--ro-bind-try", "/dev/null", os.path.join(root, name)]
            # A glob filename (**/.env.*) can't be enumerated for bwrap; strict_fs
            # (deny-all-writes) plus the proxy are the backstop. Skip rather than
            # emit a bogus path.
        elif "*" not in d and "?" not in d:
            cmd += ["--ro-bind-try", "/dev/null", _real(d)]

    # Deny exec of named binaries by masking each on PATH. Skip PATH entries
    # containing glob metacharacters — bwrap does not expand them, so a masked
    # path with '*' would silently no-op.
    for name in policy.process.deny:
        for d in os.environ.get("PATH", "/usr/bin:/bin").split(":"):
            if not d or "*" in d or "?" in d:
                continue
            cmd += ["--ro-bind-try", "/dev/null", os.path.join(d, name)]

    # Network: route egress through the recording proxy (env-based).
    if proxy_port:
        proxy = f"http://127.0.0.1:{proxy_port}"
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
            cmd += ["--setenv", var, proxy]

    cmd += ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-uts",
            "--unshare-ipc", "--"]
    cmd += list(argv)
    return cmd
