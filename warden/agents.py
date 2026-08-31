"""Registry of known AI coding tools and their least-privilege baselines.

Each agent entry carries:
  * the command(s) that launch it (first one found on PATH wins),
  * the egress hosts it legitimately needs (its model/provider endpoints plus
    the common developer registries), and
  * notes on what it is.

These allow-lists are deliberately *tight starters*, not exhaustive. The right
workflow is: run the agent once in `warden record` mode, read the flight report,
and add any host the agent genuinely needed. That is the whole point — you end
up with a policy grounded in observed behavior, not guesswork.

Hosts marked in DEVELOPER_BASELINE are shared by every coding agent because they
all clone repos and install packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy import DEFAULT_SECRET_DENY, FilesystemRules, NetworkRules, Policy, ProcessRules

# Package registries and code hosts every coding agent touches.
DEVELOPER_BASELINE = [
    "github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "codeload.github.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "get.pnpm.io",
    "registry.yarnpkg.com",
]


@dataclass
class Agent:
    key: str
    name: str
    commands: list[str]                 # candidate launch commands, in preference order
    egress: list[str] = field(default_factory=list)  # provider hosts (baseline added automatically)
    denied_processes: list[str] = field(default_factory=lambda: ["ssh", "scp", "aws", "gcloud", "kubectl"])
    note: str = ""


REGISTRY: dict[str, Agent] = {
    "claude": Agent(
        key="claude",
        name="Claude Code",
        commands=["claude"],
        egress=["api.anthropic.com", "statsig.anthropic.com", "sentry.io"],
        note="Anthropic's official CLI coding agent.",
    ),
    "codex": Agent(
        key="codex",
        name="OpenAI Codex CLI",
        commands=["codex"],
        egress=["api.openai.com", "auth.openai.com", "chatgpt.com"],
        note="OpenAI's terminal coding agent.",
    ),
    "cursor": Agent(
        key="cursor",
        name="Cursor Agent (CLI)",
        commands=["cursor-agent", "cursor"],
        egress=["api2.cursor.sh", "api.cursor.sh", "repo42.cursor.sh",
                "api.openai.com", "api.anthropic.com"],
        note="Cursor's headless agent CLI.",
    ),
    "copilot": Agent(
        key="copilot",
        name="GitHub Copilot CLI",
        commands=["copilot", "gh"],
        egress=["api.githubcopilot.com", "copilot-proxy.githubusercontent.com",
                "api.github.com", "*.githubcopilot.com"],
        note="GitHub Copilot in the terminal (also `gh copilot`).",
    ),
    "gemini": Agent(
        key="gemini",
        name="Gemini CLI",
        commands=["gemini"],
        egress=["generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
                "oauth2.googleapis.com"],
        note="Google's Gemini command-line agent.",
    ),
    "aider": Agent(
        key="aider",
        name="aider",
        commands=["aider"],
        egress=["api.openai.com", "api.anthropic.com", "openrouter.ai",
                "generativelanguage.googleapis.com"],
        note="Open-source pair-programming agent; provider depends on config.",
    ),
    "q": Agent(
        key="q",
        name="Amazon Q Developer CLI",
        commands=["q"],
        egress=["codewhisperer.us-east-1.amazonaws.com", "q.us-east-1.amazonaws.com",
                "cognito-identity.us-east-1.amazonaws.com"],
        # Q legitimately uses AWS; do not deny the aws CLI for this agent.
        denied_processes=["ssh", "scp"],
        note="Amazon Q Developer terminal agent.",
    ),
    "opencode": Agent(
        key="opencode",
        name="opencode",
        commands=["opencode"],
        egress=["api.openai.com", "api.anthropic.com", "openrouter.ai"],
        note="Open-source terminal agent; provider-dependent.",
    ),
    "goose": Agent(
        key="goose",
        name="Goose",
        commands=["goose"],
        egress=["api.openai.com", "api.anthropic.com"],
        note="Block's open-source agent; provider-dependent.",
    ),
}


def get(key: str) -> Agent | None:
    return REGISTRY.get(key.lower())


def resolve_command(agent: Agent) -> list[str] | None:
    """Return the launch command for an agent, or None if none is on PATH."""
    import shutil

    for cmd in agent.commands:
        if shutil.which(cmd):
            # `gh` needs the copilot subcommand.
            if agent.key == "copilot" and cmd == "gh":
                return ["gh", "copilot"]
            return [cmd]
    return None


def policy_for(agent: Agent, workdir: str) -> Policy:
    """Build a least-privilege policy for a named agent."""
    return Policy(
        name=f"agent:{agent.key}",
        description=f"Warden baseline for {agent.name}. {agent.note}",
        filesystem=FilesystemRules(
            read=[workdir + "/**", "~/.gitconfig", "~/.config/git/**",
                  f"~/.{agent.key}/**", f"~/.config/{agent.key}/**"],
            write=[workdir + "/**", "/tmp/**", "/private/tmp/**",
                   f"~/.{agent.key}/**", f"~/.config/{agent.key}/**"],
            deny=list(DEFAULT_SECRET_DENY),
        ),
        network=NetworkRules(
            allow=sorted(set(agent.egress) | set(DEVELOPER_BASELINE)),
            deny=[],
            deny_all_other=True,
        ),
        process=ProcessRules(deny=list(agent.denied_processes)),
        on_violation="block+receipt",
    )


def describe_all() -> list[dict]:
    import shutil

    rows = []
    for a in REGISTRY.values():
        found = next((c for c in a.commands if shutil.which(c)), None)
        rows.append({
            "key": a.key,
            "name": a.name,
            "commands": a.commands,
            "installed": bool(found),
            "egress_count": len(set(a.egress) | set(DEVELOPER_BASELINE)),
            "note": a.note,
        })
    return rows
