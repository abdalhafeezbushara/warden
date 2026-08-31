"""Project policy discovery and scaffolding.

Warden looks for a project policy so a team can commit one `.warden.yaml` and
have every `warden run` in that tree use it. Discovery walks up from the working
directory (like .gitignore / .editorconfig), stopping at a git root or the home
directory so it never silently picks up a policy from outside the project.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import agents
from .policy import Policy, load

PROJECT_FILENAMES = (".warden.yaml", ".warden.yml", ".warden/policy.yaml")


def find_project_policy(start: str | os.PathLike[str] | None = None) -> Path | None:
    cur = Path(start or os.getcwd()).resolve()
    home = Path.home().resolve()
    while True:
        for name in PROJECT_FILENAMES:
            candidate = cur / name
            if candidate.is_file():
                return candidate
        if (cur / ".git").exists() or cur == home or cur == cur.parent:
            return None
        cur = cur.parent


def merge_agent_egress(policy: Policy, agent_key: str | None) -> Policy:
    """Ensure a named agent can always reach its own provider hosts.

    Prevents the footgun where a strict project policy blocks the agent's API.
    """
    if not agent_key:
        return policy
    a = agents.get(agent_key)
    if not a:
        return policy
    needed = set(a.egress) | set(agents.DEVELOPER_BASELINE)
    policy.network.allow = sorted(set(policy.network.allow) | needed)
    return policy


def load_project_policy(start: str | os.PathLike[str] | None = None) -> tuple[Policy | None, Path | None]:
    path = find_project_policy(start)
    if not path:
        return None, None
    return load(path), path
