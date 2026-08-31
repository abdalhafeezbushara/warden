"""Build the child's environment from a safe allow-list.

The shell that launches an agent is usually full of secrets — AWS keys, a GitHub
token, database URLs — that the agent has no need for. Passing the whole
environment through (the old behavior) means a poisoned skill can read all of
them. Driftward instead passes only a safe base set, credentials registered for the
selected agent, and whatever the policy explicitly allow-lists. Arbitrary
commands and profiled skills get no provider credentials by default.
"""

from __future__ import annotations

import os

# System vars needed for a normal process to run. HOME is kept real because the
# sandbox denies the sensitive paths under it by path; a synthetic HOME would
# break agents that read ~/.config/<agent>.
SAFE_BASE = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TERMINFO", "TZ",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_COLLATE",
    "LC_NUMERIC", "LC_TIME", "PWD", "TMPDIR", "COLORTERM", "COLUMNS", "LINES",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
    "HOMEBREW_PREFIX", "HOMEBREW_CELLAR", "HOMEBREW_REPOSITORY", "INFOPATH",
    "MANPATH", "NODE_PATH", "NVM_DIR", "PYENV_ROOT", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "GIT_EXEC_PATH", "EDITOR", "PAGER",
}

DRIFTWARD_CONTROL_VARS = {
    "DRIFTWARD_HOME", "DRIFTWARD_SESSION", "DRIFTWARD_ACTIVE",
    "DRIFTWARD_MCP_BROKER", "DRIFTWARD_MCP_TOKEN",
}

def provider_keys_for(agent: str | None) -> set[str]:
    """Credential variables needed by one named agent.

    Unknown or arbitrary commands intentionally receive none; a policy can opt
    into additional variables explicitly through ``env_allow``.
    """
    if not agent:
        return set()
    from . import agents

    registered = agents.get(agent)
    return set(registered.env_keys) if registered else set()


def build_child_env(policy, overrides: dict[str, str], agent: str | None = None) -> dict[str, str]:
    """Return safe base + this agent's credentials + policy opt-ins + overrides."""
    allow = (set(SAFE_BASE) | provider_keys_for(agent)
             | set(getattr(policy, "env_allow", []) or []))
    env = {k: v for k, v in os.environ.items() if k in allow}
    # Never leak Driftward's own control-plane vars to the child.
    for k in DRIFTWARD_CONTROL_VARS:
        env.pop(k, None)
    env.update(overrides)
    return env


def scrubbed_names(policy, agent: str | None = None) -> list[str]:
    """The parent env var names that would be withheld (for reporting)."""
    allow = (set(SAFE_BASE) | provider_keys_for(agent)
             | set(getattr(policy, "env_allow", []) or []))
    return sorted(k for k in os.environ if k not in allow and k not in DRIFTWARD_CONTROL_VARS)
