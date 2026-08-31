"""Per-MCP-server confinement, identity, discovery, and config wrapping.

Wrapped servers do not start a nested Warden inside the agent sandbox. They
connect to a parent-owned broker which was given an immutable allow-list before
the agent started. The broker launches each stdio server as a sibling Warden
session, preserving Warden's private signing state while giving every server an
independent behavioral principal.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .agents import DEVELOPER_BASELINE
from .policy import DEFAULT_SECRET_DENY, FilesystemRules, NetworkRules, Policy, ProcessRules


def discovery_paths() -> tuple[Path, ...]:
    """Return known config locations using the current cwd and home."""
    return (
        Path.cwd() / ".mcp.json",
        Path.cwd() / ".vscode" / "mcp.json",
        Path.home() / ".claude.json",
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    )


@dataclass
class McpServer:
    name: str
    command: str | None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    transport: str = "streamable-http"   # or "sse" (legacy two-endpoint HTTP+SSE)
    source: str = ""
    wrapped: bool = False
    wrapped_definition: str | None = None

    @property
    def env_declared(self) -> list[str]:
        """Environment names are public behavior; values never are."""
        return sorted(self.env)

    @property
    def remote(self) -> bool:
        return self.command is None and bool(self.url)

    def launch_command(self) -> list[str]:
        return [self.command, *self.args] if self.command else []

    def definition_payload(self) -> dict:
        """Security-relevant identity, intentionally excluding secret values."""
        return {
            "transport": self.transport if self.remote else "stdio",
            "command": self.command,
            "args": list(self.args),
            "env_names": self.env_declared,
            "header_names": sorted(self.headers),
            "url": self.url,
        }

    @property
    def definition_sha256(self) -> str:
        raw = json.dumps(self.definition_payload(), sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @property
    def wrapped_valid(self) -> bool:
        return bool(self.wrapped and self.wrapped_definition
                    and self.wrapped_definition == self.definition_sha256)

    def to_grant(self) -> dict:
        """Private broker payload. Stored only below WARDEN_HOME with mode 0600."""
        return {
            "name": self.name, "command": self.command, "args": list(self.args),
            "env": dict(self.env), "headers": dict(self.headers),
            "url": self.url, "transport": self.transport, "source": self.source,
            "definition_sha256": self.definition_sha256,
        }

    @classmethod
    def from_grant(cls, value: dict) -> "McpServer":
        server = cls(
            name=str(value["name"]), command=value.get("command"),
            args=[str(a) for a in value.get("args", [])],
            env={str(k): str(v) for k, v in (value.get("env") or {}).items()},
            headers={str(k): str(v) for k, v in (value.get("headers") or {}).items()},
            url=value.get("url"), transport=str(value.get("transport") or "streamable-http"),
            source=str(value.get("source") or ""),
        )
        expected = value.get("definition_sha256")
        if not expected or expected != server.definition_sha256:
            raise ValueError("MCP broker grant definition digest does not match")
        return server


def _servers_map(doc: dict) -> dict:
    for key in ("mcpServers", "servers"):
        value = doc.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _unwrap_args(args: list[str]) -> tuple[str, list[str]] | None:
    if "--" not in args:
        return None
    tail = args[args.index("--") + 1:]
    return (tail[0], tail[1:]) if tail else None


def _wrapper_details(command, args) -> dict | None:
    """Recognize current broker shims and legacy nested-Warden wrappers."""
    args = [str(a) for a in (args or [])]
    if command != "warden":
        return None
    original = _unwrap_args(args)
    if args[:2] == ["mcp", "shim"] and len(args) >= 3 and original:
        def option(name: str) -> str | None:
            try:
                index = args.index(name)
                return args[index + 1] if index + 1 < len(args) else None
            except ValueError:
                return None
        return {
            "kind": "shim", "name": args[2], "config": option("--config"),
            "definition": option("--definition"), "original": original,
            "url": option("--url"), "transport": option("--transport"),
        }
    if "--subject" in args and original:
        return {"kind": "legacy", "definition": None, "original": original}
    return None


def _validated_spec(name: str, spec: dict, source: Path) -> McpServer:
    command = spec.get("command")
    raw_args = spec.get("args", []) or []
    raw_env = spec.get("env", {}) or {}
    raw_headers = spec.get("headers", {}) or {}
    url = spec.get("url") or spec.get("httpUrl")
    if command is not None and not isinstance(command, str):
        raise ValueError(f"MCP server '{name}' has a non-string command")
    if not isinstance(raw_args, list):
        raise ValueError(f"MCP server '{name}' has non-list args")
    if not isinstance(raw_env, dict):
        raise ValueError(f"MCP server '{name}' has a non-object env")
    if not isinstance(raw_headers, dict):
        raise ValueError(f"MCP server '{name}' has a non-object headers")
    if url is not None and not isinstance(url, str):
        raise ValueError(f"MCP server '{name}' has a non-string URL")

    transport = str(spec.get("transport") or "streamable-http")
    args = [str(a) for a in raw_args]
    details = _wrapper_details(command, args)
    wrapped = details is not None
    wrapped_definition = details.get("definition") if details else None
    if details:
        if details.get("url"):          # a wrapped remote server
            command, args, url = None, [], details["url"]
            transport = details.get("transport") or transport
        else:
            command, args = details["original"]
    env = {str(k): str(v) for k, v in raw_env.items() if v is not None}
    headers = {str(k): str(v) for k, v in raw_headers.items() if v is not None}
    return McpServer(
        name=str(name), command=command, args=args, env=env, url=url, headers=headers,
        transport=transport, source=str(source.resolve()), wrapped=wrapped,
        wrapped_definition=wrapped_definition,
    )


def parse_config(path: str | Path) -> tuple[dict, list[McpServer]]:
    """Return the raw document and validated server definitions."""
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {p}: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise ValueError("MCP config is not a JSON object")
    servers = []
    for name, spec in _servers_map(doc).items():
        if not isinstance(spec, dict):
            raise ValueError(f"MCP server '{name}' is not an object")
        servers.append(_validated_spec(str(name), spec, p))
    return doc, servers


def configured(paths=None, *, deduplicate: bool = True) -> list[McpServer]:
    """Read all valid configs. With deduplicate=False, preserve same-name entries."""
    result: list[McpServer] = []
    seen: set[str] = set()
    explicit = paths is not None
    raw_paths = list(paths) if explicit else list(discovery_paths())
    for raw in raw_paths:
        p = Path(raw)
        if not p.exists():
            continue
        try:
            _doc, servers = parse_config(p)
        except (OSError, ValueError):
            if explicit:
                raise
            continue
        for server in servers:
            if deduplicate and server.name in seen:
                continue
            seen.add(server.name)
            result.append(server)
    return result


def discover(paths=None) -> list[McpServer]:
    return configured(paths, deduplicate=True)


def find(name: str, paths=None) -> McpServer | None:
    return next((s for s in discover(paths) if s.name == name), None)


def remote_endpoints(extra_configs=None) -> list[dict]:
    """Declared remote (url/SSE) MCP servers as {name, host, url}.

    Warden cannot sandbox someone else's endpoint, but it can allow-list and
    record the ones an agent is configured to use — so they work under
    default-deny egress and a rug-pulled URL still shows up in the flight log.
    Mirrors the broker's snapshot: standard configs plus any explicitly supplied.
    """
    from urllib.parse import urlparse

    servers = configured(None, deduplicate=False)
    standard = {str(path.expanduser().resolve()) for path in discovery_paths()}
    for raw in extra_configs or []:
        candidate = Path(raw).expanduser()
        if str(candidate.resolve()) not in standard:
            servers.extend(configured([candidate], deduplicate=False))
    out, seen = [], set()
    for server in servers:
        # A wrapped remote server is confined by its bridge principal — the agent
        # never connects to it directly, so don't widen the agent's egress for it.
        if not server.remote or not server.url or server.wrapped:
            continue
        host = urlparse(server.url).hostname
        if host and (server.name, host) not in seen:
            seen.add((server.name, host))
            out.append({"name": server.name, "host": host, "url": server.url})
    return out


def subject_for(server: McpServer) -> dict:
    return {"name": server.name, "kind": "mcp",
            "definition_sha256": server.definition_sha256}


_ENV_REF = re.compile(r"^\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}$")


def resolve_env(server: McpServer, parent: dict[str, str] | None = None) -> dict[str, str]:
    """Resolve common MCP env references without logging any values."""
    parent = os.environ if parent is None else parent
    resolved = {}
    for name, raw in server.env.items():
        if name.startswith("WARDEN_"):
            raise ValueError(f"MCP server '{server.name}' declares reserved variable '{name}'")
        match = _ENV_REF.match(raw)
        if match:
            source = match.group(1)
            if source not in parent:
                raise ValueError(
                    f"MCP server '{server.name}' needs environment variable '{source}', but it is unset")
            resolved[name] = parent[source]
        else:
            resolved[name] = raw
    return resolved


def policy_for(server: McpServer, workdir: str) -> Policy:
    """Strict default for an untrusted local MCP process."""
    cache_writes = [
        "~/.cache/**", "~/.npm/**", "~/.npm-global/**", "~/.pnpm-store/**",
    ]
    return Policy(
        name=f"mcp:{server.name}",
        description=f"Strict Warden baseline for MCP server '{server.name}'.",
        filesystem=FilesystemRules(
            read=[workdir + "/**", "~/.gitconfig", "~/.cache/**",
                  "~/.local/bin/**", "~/.local/lib/**", "~/.local/share/pnpm/**",
                  "~/.npm/**", "~/.npm-global/**", "~/.nvm/**", "~/.pyenv/**"],
            write=[workdir + "/**", "/tmp/**", "/private/tmp/**", *cache_writes],
            deny=list(DEFAULT_SECRET_DENY),
        ),
        network=NetworkRules(allow=list(DEVELOPER_BASELINE), deny=[], deny_all_other=True),
        process=ProcessRules(deny=["ssh", "scp", "aws", "gcloud", "kubectl"]),
        on_violation="block+receipt", strict_fs=True, strict_read=True,
        env_allow=server.env_declared,
    )


def resolve_headers(server: McpServer, parent: dict[str, str] | None = None) -> dict[str, str]:
    """Resolve ${ENV} references in a remote server's request headers, by value."""
    parent = os.environ if parent is None else parent
    resolved = {}
    for name, raw in server.headers.items():
        match = _ENV_REF.match(raw)
        if match:
            source = match.group(1)
            if source not in parent:
                raise ValueError(
                    f"MCP server '{server.name}' header '{name}' needs environment "
                    f"variable '{source}', but it is unset")
            resolved[name] = parent[source]
        else:
            resolved[name] = raw
    return resolved


def _warden_package_root() -> str:
    import warden
    return str(Path(warden.__file__).resolve().parent.parent)


def remote_policy_for(server: McpServer, workdir: str) -> Policy:
    """A remote server as a principal: egress locked to *only* its declared host,
    so a rug-pulled URL is blocked, not just recorded. Reads include Warden's own
    package so the sandboxed bridge can import it under strict-read."""
    from urllib.parse import urlparse

    host = urlparse(server.url or "").hostname or "localhost"
    return Policy(
        name=f"mcp:{server.name}",
        description=f"Locked-egress bridge for remote MCP server '{server.name}'.",
        filesystem=FilesystemRules(
            read=[workdir + "/**", _warden_package_root() + "/**",
                  "~/.cache/**", "~/.local/**"],
            write=["/tmp/**", "/private/tmp/**"],
            deny=list(DEFAULT_SECRET_DENY),
        ),
        network=NetworkRules(allow=[host], deny=[], deny_all_other=True),
        process=ProcessRules(deny=["ssh", "scp", "aws", "gcloud", "kubectl"]),
        on_violation="block+receipt", strict_fs=True, strict_read=True,
    )


def bridge_command(server: McpServer) -> list[str]:
    """The sandboxed process that bridges stdio to the remote endpoint."""
    import sys
    return [sys.executable, "-m", "warden", "mcp", "_bridge", "--url", server.url,
            "--transport", server.transport]


def wrap_command(server: McpServer, config: str | Path | None = None) -> list[str]:
    """Build the shim command embedded in an MCP config. Remote servers carry
    their URL in a --url option and a marker tail; stdio servers carry the
    original launch after --."""
    source = str(Path(config or server.source).resolve())
    head = ["warden", "mcp", "shim", server.name, "--config", source,
            "--definition", server.definition_sha256]
    if server.remote:
        return head + ["--url", server.url, "--transport", server.transport,
                       "--", "warden-remote-bridge"]
    return head + ["--", server.command, *server.args]


def transform_config(doc: dict, *, wrap: bool,
                     config: str | Path | None = None) -> tuple[dict, list[str]]:
    """Wrap or restore stdio *and* remote definitions. A wrapped remote server
    becomes a stdio shim whose bridge is egress-locked to its declared host."""
    import copy

    out = copy.deepcopy(doc)
    changed = []
    source = Path(config or ".mcp.json").resolve()
    for map_key in ("mcpServers", "servers"):
        servers = out.get(map_key)
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            server = _validated_spec(str(name), spec, source)
            command = spec.get("command")
            args = [str(a) for a in spec.get("args", []) or []]
            if wrap:
                if server.wrapped or (not server.command and not server.remote):
                    continue  # already wrapped, or nothing launchable
                wrapped = wrap_command(server, source)
                if command == wrapped[0] and args == wrapped[1:]:
                    continue
                spec["command"], spec["args"] = wrapped[0], wrapped[1:]
                if server.remote:
                    spec.pop("url", None)
                    spec.pop("httpUrl", None)  # now presents as a stdio shim
                changed.append(str(name))
            else:
                details = _wrapper_details(command, args)
                if not details:
                    continue
                if details.get("url"):          # remote shim → restore the URL
                    spec.pop("command", None)
                    spec.pop("args", None)
                    spec["url"] = details["url"]
                else:
                    original = details.get("original")
                    if original:
                        spec["command"], spec["args"] = original
                changed.append(str(name))
    return out, changed


def write_config_atomic(path: str | Path, rendered: str) -> Path:
    """Back up and replace a config without widening its secret-bearing mode."""
    target = Path(path)
    stat = target.stat()
    backup = target.with_suffix(target.suffix + ".bak")
    shutil.copy2(target, backup)
    os.chmod(backup, stat.st_mode & 0o777)

    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        os.fchmod(fd, stat.st_mode & 0o777)
        try:
            os.fchown(fd, stat.st_uid, stat.st_gid)
        except (AttributeError, PermissionError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        try:
            dir_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return backup
