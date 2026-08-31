"""Registry of known AI coding tools and their least-privilege baselines.

Each agent entry carries:
  * the command(s) that launch it (first one found on PATH wins),
  * the egress hosts it legitimately needs (its model/provider endpoints plus
    the common developer registries), and
  * the credential environment variables that specific agent may inherit,
  * notes on what it is.

These allow-lists are deliberately *tight starters*, not exhaustive. The right
workflow is: run the agent once in `driftward record` mode, read the flight report,
and add any host the agent genuinely needed. That is the whole point — you end
up with a policy grounded in observed behavior, not guesswork.

Hosts marked in DEVELOPER_BASELINE are shared by every coding agent because they
all clone repos and install packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy import (
    DEFAULT_SECRET_DENY, FilesystemRules, NetworkRules, Policy, ProcessRules,
    apply_keychain,
)

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
    env_keys: list[str] = field(default_factory=list)  # credential vars allowed for this agent
    denied_processes: list[str] = field(default_factory=lambda: ["ssh", "scp", "aws", "gcloud", "kubectl"])
    # True when the agent keeps its OWN login session in the macOS Keychain and
    # cannot authenticate if the keychain is denied (cursor-agent). Its baseline
    # then opens exactly the keychain path — the rest of the secret deny-list
    # still stands. Seal it back with `driftward run --deny-keychain`.
    keychain_auth: bool = False
    note: str = ""


REGISTRY: dict[str, Agent] = {
    "claude": Agent(
        key="claude",
        name="Claude Code",
        commands=["claude"],
        egress=["api.anthropic.com", "statsig.anthropic.com", "sentry.io"],
        env_keys=[
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
            "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
            "ANTHROPIC_VERTEX_PROJECT_ID", "CLOUD_ML_REGION",
        ],
        note="Anthropic's official CLI coding agent.",
    ),
    "codex": Agent(
        key="codex",
        name="OpenAI Codex CLI",
        commands=["codex"],
        egress=["api.openai.com", "auth.openai.com", "chatgpt.com"],
        env_keys=["OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID"],
        note="OpenAI's terminal coding agent.",
    ),
    "cursor": Agent(
        key="cursor",
        name="Cursor Agent (CLI)",
        # ONLY the headless agent CLI — NOT the `cursor` GUI editor launcher
        # (that opens the IDE and isn't an autonomous agent to sandbox).
        commands=["cursor-agent"],
        # Cursor fans out across dynamic subdomains (api2, repo42, and
        # agentn.global.api5.cursor.sh for agent inference — observed via
        # `driftward record`), so allow its own domain by wildcard rather than
        # chase every shard. Still vendor-scoped to *.cursor.sh.
        egress=["*.cursor.sh", "api2.cursor.sh", "api.cursor.sh", "repo42.cursor.sh",
                "api.openai.com", "api.anthropic.com"],
        env_keys=["CURSOR_API_KEY"],
        # `cursor-agent login` stores the session in the macOS Keychain, so the
        # baseline must open the keychain or the agent reports "Authentication
        # required". Prefer CURSOR_API_KEY + --deny-keychain to keep it sealed.
        keychain_auth=True,
        note="Cursor's headless agent CLI (authenticates via the macOS Keychain).",
    ),
    "copilot": Agent(
        key="copilot",
        name="GitHub Copilot CLI",
        commands=["copilot", "gh"],
        egress=["api.githubcopilot.com", "copilot-proxy.githubusercontent.com",
                "api.github.com", "*.githubcopilot.com"],
        env_keys=["GITHUB_TOKEN", "GH_TOKEN", "COPILOT_GITHUB_TOKEN"],
        note="GitHub Copilot in the terminal (also `gh copilot`).",
    ),
    "gemini": Agent(
        key="gemini",
        name="Gemini CLI",
        commands=["gemini"],
        egress=["generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
                "oauth2.googleapis.com"],
        env_keys=["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
                  "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION"],
        note="Google's Gemini command-line agent.",
    ),
    "aider": Agent(
        key="aider",
        name="aider",
        commands=["aider"],
        egress=["api.openai.com", "api.anthropic.com", "openrouter.ai",
                "generativelanguage.googleapis.com"],
        env_keys=[
            "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
            "OPENROUTER_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "MISTRAL_API_KEY",
            "GROQ_API_KEY", "COHERE_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY",
            "TOGETHER_API_KEY", "FIREWORKS_API_KEY",
        ],
        note="Open-source pair-programming agent; provider depends on config.",
    ),
    "q": Agent(
        key="q",
        name="Amazon Q Developer CLI",
        commands=["q"],
        egress=["codewhisperer.us-east-1.amazonaws.com", "q.us-east-1.amazonaws.com",
                "cognito-identity.us-east-1.amazonaws.com"],
        env_keys=["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID",
                  "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
        # Q legitimately uses AWS; do not deny the aws CLI for this agent.
        denied_processes=["ssh", "scp"],
        note="Amazon Q Developer terminal agent.",
    ),
    "opencode": Agent(
        key="opencode",
        name="opencode",
        commands=["opencode"],
        egress=["api.openai.com", "api.anthropic.com", "openrouter.ai"],
        env_keys=["OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY",
                  "ANTHROPIC_BASE_URL", "OPENROUTER_API_KEY"],
        note="Open-source terminal agent; provider-dependent.",
    ),
    "goose": Agent(
        key="goose",
        name="Goose",
        commands=["goose"],
        egress=["api.openai.com", "api.anthropic.com"],
        env_keys=["OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY",
                  "ANTHROPIC_BASE_URL"],
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
    policy = Policy(
        name=f"agent:{agent.key}",
        description=f"Driftward baseline for {agent.name}. {agent.note}",
        filesystem=FilesystemRules(
            read=[workdir + "/**", "~/.gitconfig", "~/.config/**", "~/.cache/**",
                  "~/.local/**", "~/.npm/**", "~/.npm-global/**", "~/.nvm/**",
                  # Agent dirs AND dotfile configs (e.g. ~/.claude.json, ~/.cursor*)
                  # — real agents keep config in a top-level dotfile, not just a dir.
                  f"~/.{agent.key}/**", f"~/.config/{agent.key}/**",
                  f"~/.{agent.key}.json", f"~/.{agent.key}*"],
            write=[workdir + "/**", "/tmp/**", "/private/tmp/**",
                   f"~/.{agent.key}/**", f"~/.config/{agent.key}/**",
                   f"~/.{agent.key}.json"],
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
    # An agent that authenticates through the macOS Keychain (cursor-agent) needs
    # that one path opened, or it can't reach its own login session. Everything
    # else in the secret deny-list stays denied.
    if agent.keychain_auth:
        policy = apply_keychain(policy, allow=True)
    return policy


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
            "env_key_count": len(a.env_keys),
            "note": a.note,
        })
    return rows
