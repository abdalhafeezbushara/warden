"""Warden policy model and loader.

A policy is a small declarative document describing what an agent may touch:
filesystem read/write/deny globs, network allow/deny hosts, denied processes,
and what to do on a violation. To keep Warden dependency-free, policies are
written in a minimal YAML subset that the loader below parses with the standard
library only. JSON policies are also accepted.

Design choices that matter:
  * Deny always wins over allow. A path or host that matches both is denied.
  * Filesystem paths are expanded (~, $VARS) and canonicalized to real paths
    at compile time, because macOS Seatbelt evaluates the real path and /tmp,
    /var, and /etc are all symlinks. Skipping this silently defeats every rule.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


@dataclass
class FilesystemRules:
    read: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class NetworkRules:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    deny_all_other: bool = True


@dataclass
class ProcessRules:
    deny: list[str] = field(default_factory=list)


@dataclass
class Policy:
    name: str = "unnamed"
    description: str = ""
    filesystem: FilesystemRules = field(default_factory=FilesystemRules)
    network: NetworkRules = field(default_factory=NetworkRules)
    process: ProcessRules = field(default_factory=ProcessRules)
    # block+receipt | warn
    on_violation: str = "block+receipt"
    # When true, deny ALL filesystem writes except the write allow-list (instead
    # of the default allow-writes-but-deny-secrets). Stricter; opt-in because it
    # can break agents that write to unexpected caches.
    strict_fs: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# The credentials and key material a coding agent should never need to read.
# These become deny rules in every default policy; a user can override, but
# they must do so explicitly.
DEFAULT_SECRET_DENY = [
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.config/gcloud/**",
    "~/.kube/**",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "**/.env",
    "**/.env.*",
    "~/Library/Keychains/**",
]


def default_policy(workdir: str | os.PathLike[str] | None = None) -> Policy:
    """A sensible starting policy: work in the project dir, reach common
    developer hosts, never read credential stores, never spawn credential CLIs."""
    workdir = str(workdir or os.getcwd())
    return Policy(
        name="default",
        description="Warden default: project-scoped filesystem, allow-listed egress, secrets denied.",
        filesystem=FilesystemRules(
            read=[workdir + "/**", "~/.gitconfig", "~/.config/git/**"],
            write=[workdir + "/**", "/tmp/**", "/private/tmp/**"],
            deny=list(DEFAULT_SECRET_DENY),
        ),
        network=NetworkRules(
            allow=[
                "api.anthropic.com",
                "github.com",
                "*.githubusercontent.com",
                "registry.npmjs.org",
                "pypi.org",
                "files.pythonhosted.org",
            ],
            deny=[],
            deny_all_other=True,
        ),
        process=ProcessRules(deny=["ssh", "scp", "aws", "gcloud", "kubectl"]),
        on_violation="block+receipt",
    )


# --------------------------------------------------------------------------
# Minimal YAML-subset parser (stdlib only).
#
# Supported:
#   key: value
#   nested mappings by two-space indentation
#   lists as "- item" lines or inline [a, b, c]
#   booleans true/false, quoted or bare scalars, "# comments"
# This is intentionally small: policies are simple, and we refuse to add a
# third-party dependency for them. Anything more exotic should be JSON.
# --------------------------------------------------------------------------

_INLINE_LIST = re.compile(r"^\[(.*)\]$")


def _coerce(scalar: str):
    s = scalar.strip()
    if s == "":
        return ""
    if (s[0] == s[-1]) and s[0] in ("'", '"') and len(s) >= 2:
        return s[1:-1]
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~", "none"):
        return None
    m = _INLINE_LIST.match(s)
    if m:
        inner = m.group(1).strip()
        if not inner:
            return []
        return [_coerce(part) for part in _split_top(inner)]
    return s


def _split_top(inner: str) -> list[str]:
    """Split a comma list, respecting quotes."""
    out, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [p.strip() for p in out]


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _parse_mini_yaml(text: str):
    # Build a list of (indent, key, value_or_None, is_list_item) then nest.
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        # Decide: is this a list block or a mapping block?
        if pos >= len(lines):
            return {}
        indent, content = lines[pos]
        if content.startswith("- "):
            result_list = []
            while pos < len(lines):
                indent, content = lines[pos]
                if indent < min_indent or not content.startswith("- "):
                    break
                item = content[2:].strip()
                pos += 1
                result_list.append(_coerce(item))
            return result_list

        result_map = {}
        while pos < len(lines):
            indent, content = lines[pos]
            if indent < min_indent:
                break
            if ":" not in content:
                raise PolicyError(f"expected 'key: value', got: {content!r}")
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val == "":
                # nested block belongs to this key
                child_indent = lines[pos][0] if pos < len(lines) else min_indent
                if pos < len(lines) and child_indent > indent:
                    result_map[key] = parse_block(child_indent)
                else:
                    result_map[key] = None
            else:
                result_map[key] = _coerce(val)
        return result_map

    return parse_block(0)


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def loads(text: str) -> Policy:
    """Parse a policy from YAML-subset or JSON text."""
    text = text.strip()
    if not text:
        raise PolicyError("empty policy document")
    data = json.loads(text) if text[0] in "{[" else _parse_mini_yaml(text)
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping at the top level")

    fs = data.get("filesystem") or {}
    net = data.get("network") or {}
    proc = data.get("process") or {}
    if not isinstance(fs, dict) or not isinstance(net, dict) or not isinstance(proc, dict):
        raise PolicyError("filesystem/network/process must be mappings")

    on_violation = str(data.get("on_violation", "block+receipt"))
    if on_violation not in ("block+receipt", "warn", "ask"):
        raise PolicyError(
            f"invalid on_violation: {on_violation!r} (use 'block+receipt', 'warn', or 'ask')")

    deny_all = net.get("deny_all_other", True)
    return Policy(
        name=str(data.get("name", "unnamed")),
        description=str(data.get("description", "")),
        filesystem=FilesystemRules(
            read=_as_list(fs.get("read")),
            write=_as_list(fs.get("write")),
            deny=_as_list(fs.get("deny")),
        ),
        network=NetworkRules(
            allow=_as_list(net.get("allow")),
            deny=_as_list(net.get("deny")),
            deny_all_other=bool(deny_all) if isinstance(deny_all, bool) else str(deny_all).lower() != "false",
        ),
        process=ProcessRules(deny=_as_list(proc.get("deny"))),
        on_violation=on_violation,
        strict_fs=bool(data.get("strict_fs", False)) if isinstance(data.get("strict_fs", False), bool)
        else str(data.get("strict_fs")).lower() == "true",
    )


def load(path: str | os.PathLike[str]) -> Policy:
    return loads(Path(path).read_text(encoding="utf-8"))


def _yaml_list(items: list[str], indent: str) -> str:
    if not items:
        return " []"
    return "\n" + "\n".join(f"{indent}- {v}" for v in items)


def to_yaml(policy: Policy) -> str:
    """Serialize a Policy back to the YAML subset the loader accepts."""
    p = policy
    lines = [
        f"name: {p.name}",
    ]
    if p.description:
        lines.append(f"description: {p.description}")
    lines.append("")
    lines.append("filesystem:")
    lines.append("  read:" + _yaml_list(p.filesystem.read, "    "))
    lines.append("  write:" + _yaml_list(p.filesystem.write, "    "))
    lines.append("  deny:" + _yaml_list(p.filesystem.deny, "    "))
    lines.append("")
    lines.append("network:")
    lines.append("  allow:" + _yaml_list(p.network.allow, "    "))
    lines.append("  deny:" + _yaml_list(p.network.deny, "    "))
    lines.append(f"  deny_all_other: {'true' if p.network.deny_all_other else 'false'}")
    lines.append("")
    lines.append("process:")
    lines.append("  deny:" + _yaml_list(p.process.deny, "    "))
    lines.append("")
    lines.append(f"on_violation: {p.on_violation}")
    if p.strict_fs:
        lines.append("strict_fs: true")
    return "\n".join(lines) + "\n"
