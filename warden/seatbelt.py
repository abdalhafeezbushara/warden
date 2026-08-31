"""Compile a Warden Policy into a macOS Seatbelt (SBPL) profile.

Seatbelt is the sandbox enforced by `sandbox-exec`. It reads a profile written
in Sandbox Profile Language (SBPL), a TinyScheme dialect. We start from
`(allow default)` and carve out denials, because a coding agent legitimately
touches a huge and unpredictable set of system paths (interpreters, temp files,
caches); an allow-by-default-deny-the-dangerous model is what actually survives
real agent workloads without breaking them constantly.

Two hard-won details:
  * Later rules override earlier ones in SBPL, so all deny rules come after
    `(allow default)`.
  * Every filesystem path is canonicalized with realpath. macOS aliases
    /tmp -> /private/tmp, /etc -> /private/etc, /var -> /private/var, and a
    deny written against the alias silently matches nothing. This module
    expands ~ and $VARS, then resolves the longest existing real prefix so a
    glob under a not-yet-created dir still canonicalizes correctly.

Network note: SBPL host-based filtering is unreliable across macOS versions, so
Warden does NOT try to express per-host rules in Seatbelt. Instead the profile
permits localhost (so tools can reach the Warden egress proxy) and the proxy
enforces the host allow/deny list. `deny_all_other` here tightens Seatbelt to
localhost-only egress, which forces even direct-socket malware through nothing —
it just fails — while well-behaved tools use the proxy.
"""

from __future__ import annotations

import os
from pathlib import Path

from .policy import Policy


def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def _glob_root(path: str) -> str:
    """The literal prefix of a glob, up to the first wildcard."""
    for i, ch in enumerate(path):
        if ch in "*?[":
            return path[:i]
    return path


def canonical(path: str) -> str:
    """Expand and canonicalize a (possibly glob) path to its real location.

    We resolve the longest existing prefix so that a rule like ``~/proj/**``
    still lands on ``/Users/x/proj`` even though ``**`` is not a real dir.
    """
    expanded = _expand(path)
    root = _glob_root(expanded)
    if not root:
        return expanded
    # Walk up to the longest existing ancestor, resolve it, re-attach the tail.
    p = Path(root)
    existing = p
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    try:
        real = os.path.realpath(existing)
    except OSError:
        real = str(existing)
    tail = os.path.relpath(root, str(existing)) if str(existing) != root else ""
    resolved_root = real if not tail or tail == "." else os.path.join(real, tail)
    remainder = expanded[len(root):]
    return resolved_root + remainder


def _sbpl_subpath(path: str) -> str:
    r"""Render a canonical glob path as an SBPL filter.

    SBPL has (subpath "...") for a directory tree and (literal "...") for one
    file. We translate:
      /dir/**  -> (subpath "/dir")           whole tree
      /dir/*   -> (subpath "/dir")           one level, approximated as subtree
      **/.env  -> (regex #"/\.env$")         suffix match anywhere
      /a/b.txt -> (literal "/a/b.txt")       exact file
    """
    if path.endswith("/**") or path.endswith("/*"):
        base = path[:-3] if path.endswith("/**") else path[:-2]
        return f'(subpath {_quote(base)})'
    if "*" not in path and "?" not in path and "[" not in path:
        return f'(literal {_quote(path)})'
    if path.startswith("**/"):
        # A suffix match anywhere. Convert the glob suffix to an SBPL regex:
        # literal chars are escaped, '*' → [^/]* (so **/.env.* matches
        # .env.local), '?' → [^/]. A naive replace of '.' alone leaves '*' as a
        # regex quantifier and silently fails to match .env.local.
        return f'(regex #"/{_glob_suffix_to_regex(path[3:])}$")'
    # Fallback: match the literal prefix as a subpath.
    root = _glob_root(path).rstrip("/")
    if root:
        return f'(subpath {_quote(root)})'
    return f'(literal {_quote(path)})'


def _glob_suffix_to_regex(suffix: str) -> str:
    """Translate a filename glob suffix to an SBPL regex body.

    '*' matches within a path segment ([^/]*), '?' matches one non-slash char,
    everything else is escaped literally. So '.env.*' → '\\.env\\.[^/]*', which
    matches '.env.local' and '.env.production' (the naive '\\.env\\.*' does not).
    """
    out = []
    for ch in suffix:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch in ".^$+{}()[]|\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def compile_profile(policy: Policy, proxy_port: int | None = None,
                    broker_port: int | None = None) -> str:
    """Return an SBPL profile string enforcing `policy`."""
    lines: list[str] = [
        "(version 1)",
        ";; Generated by Warden. Do not edit by hand.",
        f";; policy: {policy.name}",
        "(allow default)",
        "",
        ";; --- filesystem denials (deny wins) ---",
    ]

    for raw in policy.filesystem.deny:
        real = canonical(raw)
        lines.append(f"(deny file-read* file-write* {_sbpl_subpath(real)}) ;; {raw}")

    # Strict filesystem mode: deny ALL writes, then re-allow only the write
    # allow-list. Later SBPL rules win, so the re-allows override the blanket
    # deny; the secret denials above still stand because they also deny reads and
    # are not re-allowed here. Common system write targets (temp, devices, caches)
    # are re-allowed so real agent workloads keep working.
    if policy.strict_fs:
        lines.append("")
        lines.append(";; --- strict filesystem: deny all writes, re-allow the allow-list ---")
        lines.append("(deny file-write*)")
        strict_allow = list(policy.filesystem.write) + [
            "/dev/null", "/dev/dtracehelper", "/dev/tty", "/private/var/folders",
            "/private/tmp", "/tmp",
        ]
        for raw in strict_allow:
            real = canonical(raw)
            lines.append(f"(allow file-write* {_sbpl_subpath(real)}) ;; {raw}")
        # Re-assert secret write denials so nothing in the allow-list re-opens them.
        for raw in policy.filesystem.deny:
            real = canonical(raw)
            lines.append(f"(deny file-write* {_sbpl_subpath(real)}) ;; strict re-deny {raw}")

    # Strict reads: confine reads under the user's home to the read allow-list.
    # System paths (/usr, /System, /Library, …) stay readable so the agent runs;
    # the user's other data (~/Documents, other repos, browser profiles) does not.
    if policy.strict_read:
        home = os.path.expanduser("~")
        lines.append("")
        lines.append(";; --- strict reads: deny home reads, re-allow the read allow-list ---")
        lines.append(f'(deny file-read* (subpath {_quote(home)}))')
        for raw in policy.filesystem.read:
            real = canonical(raw)
            # Only re-allow paths under home; system paths are already allowed.
            if real.startswith(home):
                lines.append(f"(allow file-read* {_sbpl_subpath(real)}) ;; {raw}")
        # Re-assert secret read denials last so a broad re-allow can't reopen them.
        for raw in policy.filesystem.deny:
            real = canonical(raw)
            if real.startswith(home):
                lines.append(f"(deny file-read* {_sbpl_subpath(real)}) ;; strict re-deny {raw}")

    lines.append("")
    lines.append(";; --- process denials ---")
    for name in policy.process.deny:
        # Deny exec of the named binary anywhere on PATH by basename via regex.
        esc = name.replace("\\", "\\\\").replace(".", r"\.")
        lines.append(f'(deny process-exec* (regex #"/{esc}$")) ;; {name}')

    lines.append("")
    lines.append(";; --- network ---")
    if policy.network.deny_all_other:
        # Pin egress to the Warden proxy ONLY — a single loopback port. This
        # forces all real traffic through the recording proxy and, unlike a
        # blanket localhost allow, does NOT expose other local services (a
        # Postgres on 5432, a Docker/SSH-agent unix socket, etc.). Unix-domain
        # sockets are denied outright for the same reason.
        lines.append("(deny network-outbound)")
        if proxy_port:
            lines.append(f'(allow network-outbound (remote ip "localhost:{int(proxy_port)}"))')
        else:
            lines.append('(allow network-outbound (remote ip "localhost:*"))')
        if broker_port:
            # A wrapped MCP shim reaches only this parent-owned authenticated
            # endpoint; other loopback services stay inaccessible.
            lines.append(f'(allow network-outbound (remote ip "localhost:{int(broker_port)}"))')
    else:
        lines.append("(allow network*)")

    return "\n".join(lines) + "\n"
