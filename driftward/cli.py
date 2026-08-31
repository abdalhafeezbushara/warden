"""Driftward command-line interface.

  driftward run    [AGENT] [--policy F] [-- ARGS]     enforce a policy + record
  driftward record [AGENT] [--policy F] [-- ARGS]     record only, no enforcement
  driftward run    -- <command...>                    run any command under the default policy
  driftward profile [AGENT] [--out F] [-- ARGS]       detonate a skill, generate a policy
  driftward scan CORPUS [--html F] [--json F]         batch-scan a corpus → shareable finding
  driftward risk|gate [LOG]                           score / CI-gate a session
  driftward behavior [LOG]                            emit a versioned behavior manifest
  driftward baseline approve|show|verify              manage signed approved behavior
  driftward diff [LOG] [--baseline NAME]              compare with approved behavior
  driftward mcp list|run|wrap|unwrap [--config F]     confine MCP servers as principals
  driftward registry publish|trust|verify|list|install  share/adopt signed baselines
  driftward agents                                    list supported AI tools
  driftward init   [AGENT]                            scaffold a project .driftward.yaml
  driftward dashboard                                 open the local session dashboard
  driftward doctor                                    prove enforcement works here
  driftward sessions                                  list recorded sessions
  driftward report [LOG]                              show what a session did
  driftward verify [LOG] [--pubkey HEX]               check the chain + signature
  driftward key                                       print this machine's public key
  driftward policy show|sbpl [AGENT] [--policy F]     inspect the effective policy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, agents as agentmod, seatbelt
from .policy import default_policy, load
from .recorder import verify_log
from .report import build_report
from .runner import _session_dir, run


def _resolve(agent_name: str | None, policy_path: str | None, child: list[str]):
    """Return (argv, policy, agent_key, source) for a run/record invocation.

    Policy precedence: explicit --policy > project .driftward.yaml > agent baseline
    > default. When an agent is named, its provider hosts are always unioned into
    the chosen policy so a strict project file can't block the agent's own API.
    """
    import os

    from . import config

    workdir = os.getcwd()
    agent = None
    if agent_name:
        agent = agentmod.get(agent_name)
        if not agent:
            known = ", ".join(agentmod.REGISTRY)
            raise SystemExit(f"driftward: unknown agent '{agent_name}'. Known: {known}")
        cmd = agentmod.resolve_command(agent)
        if not cmd:
            raise SystemExit(
                f"driftward: '{agent.name}' is not installed (looked for: {', '.join(agent.commands)}).")
        argv = cmd + child
    else:
        argv = child

    if policy_path:
        pol, source = load(policy_path), f"--policy {policy_path}"
    else:
        proj, proj_path = config.load_project_policy(workdir)
        if proj is not None:
            pol, source = proj, f"project {proj_path.name}"
        elif agent is not None:
            pol, source = agentmod.policy_for(agent, workdir), f"{agent.key} baseline"
        else:
            pol, source = default_policy(workdir), "default"

    key = agent.key if agent else None
    pol = config.merge_agent_egress(pol, key)
    return argv, pol, key, source


def _latest_log() -> Path | None:
    logs = sorted(_session_dir().glob("*.log"))
    return logs[-1] if logs else None


def _resolve_log(arg: str | None) -> Path | None:
    """Resolve a log argument: none → latest; a path → itself; a bare session id
    → <sessions>/<id>.log."""
    if not arg:
        return _latest_log()
    p = Path(arg)
    if p.exists():
        return p
    candidate = _session_dir() / (arg if arg.endswith(".log") else arg + ".log")
    return candidate if candidate.exists() else None


def _split_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def cmd_run(args, child):
    if not args.agent and not child:
        print("driftward: specify an agent or a command.\n"
              "  driftward run claude\n  driftward run -- sh script.sh", file=sys.stderr)
        return 2
    argv, pol, key, source = _resolve(args.agent, args.policy, child)
    if not argv:
        print("driftward: nothing to run.", file=sys.stderr)
        return 2
    if getattr(args, "strict", False):
        pol.strict_fs = True
    if getattr(args, "strict_read", False):
        pol.strict_read = True
    # Keychain override: --deny-keychain re-seals it even for a keychain-auth
    # agent; --allow-keychain opens it for any run. Otherwise the agent baseline
    # decides (only cursor opens it).
    from .policy import apply_keychain, keychain_allowed
    if getattr(args, "deny_keychain", False):
        pol = apply_keychain(pol, allow=False)
    elif getattr(args, "allow_keychain", False):
        pol = apply_keychain(pol, allow=True)
    if sys.platform == "darwin" and keychain_allowed(pol):
        who = key or "this command"
        print(f"driftward: macOS Keychain is READABLE by {who} (it authenticates there). "
              "Other secrets stay denied; seal it with --deny-keychain.", file=sys.stderr)
    extra = " + strict-fs" if pol.strict_fs else ""
    if pol.strict_read:
        extra += " + strict-read"
    if getattr(args, "deep", False):
        extra += " + deep-recording"
        print("driftward: --deep needs sudo + Full Disk Access on your terminal; "
              "it is best-effort and won't break the run if unavailable.", file=sys.stderr)
    print(f"driftward: policy '{pol.name}' (from {source}), enforcing{extra}", file=sys.stderr)
    return run(argv, pol, enforce=True, agent=key, subject=_parse_subject(getattr(args, "subject", None)),
               deep=getattr(args, "deep", False), deep_files=getattr(args, "deep_files", False),
               allow_record_fallback=getattr(args, "allow_record_fallback", False),
               mcp_configs=getattr(args, "mcp_config", None))


def _parse_subject(value: str | None) -> dict | None:
    """`mcp:github` → {kind: mcp, name: github}; a bare `github` → command kind."""
    if not value:
        return None
    kind, sep, name = value.partition(":")
    if sep and (not kind.strip() or not name.strip()):
        raise ValueError("--subject must be kind:name with both parts non-empty")
    return ({"kind": kind.strip(), "name": name.strip()} if sep
            else {"kind": "command", "name": kind.strip()})


def cmd_record(args, child):
    if not args.agent and not child:
        print("driftward: specify an agent or a command.", file=sys.stderr)
        return 2
    argv, pol, key, source = _resolve(args.agent, args.policy, child)
    print(f"driftward: policy '{pol.name}' (from {source}), observe-only", file=sys.stderr)
    return run(argv, pol, enforce=False, agent=key)


def cmd_init(args, _child):
    import os
    from .policy import to_yaml

    target = Path(os.getcwd()) / ".driftward.yaml"
    if target.exists() and not args.force:
        print(f"driftward: {target} already exists (use --force to overwrite).", file=sys.stderr)
        return 1
    if args.agent:
        agent = agentmod.get(args.agent)
        if not agent:
            raise SystemExit(f"driftward: unknown agent '{args.agent}'")
        pol = agentmod.policy_for(agent, os.getcwd())
        pol.name = Path(os.getcwd()).name
    else:
        pol = default_policy(os.getcwd())
        pol.name = Path(os.getcwd()).name
    target.write_text(to_yaml(pol), encoding="utf-8")
    print(f"driftward: wrote {target}")
    print("Edit the allow-list to match your project, then: driftward run <agent>")
    return 0


def cmd_agents(_args, _child):
    rows = agentmod.describe_all()
    print(f"{'AGENT':<10} {'INSTALLED':<10} {'HOSTS':<6} NAME")
    print("-" * 60)
    for r in rows:
        mark = "yes" if r["installed"] else "no"
        print(f"{r['key']:<10} {mark:<10} {r['egress_count']:<6} {r['name']}")
    print("\nRun one with:  driftward run <agent>      (e.g. driftward run claude)")
    print("Observe first: driftward record <agent>   then  driftward report")
    return 0


def cmd_dashboard(_args, _child):
    from .dashserver import serve
    serve(open_browser=not _args.no_open)
    return 0


def cmd_doctor(_args, _child):
    from .doctor import run as run_doctor
    return run_doctor()


def cmd_profile(args, child):
    from .profiler import profile
    from .policy import to_yaml

    if not args.agent and not child:
        print("driftward: specify an agent or a command to profile.\n"
              "  driftward profile ./some-skill.sh\n  driftward profile cursor", file=sys.stderr)
        return 2
    # If the positional isn't a known agent, treat it as the command to run
    # (so `driftward profile ./skill.sh` works, not just `driftward profile -- ./skill.sh`).
    agent_name = args.agent
    if agent_name and not agentmod.get(agent_name):
        child = [agent_name] + child
        agent_name = None
    code, generated, review = profile(child, agent=agent_name, allow_egress=args.allow_egress,
                                      out_path=args.out)
    print("\n" + "=" * 62)
    print("PROFILE REVIEW — hosts this skill contacted")
    print("=" * 62)
    if review["recognized"]:
        print("Recognized developer/agent hosts:")
        for h in review["recognized"]:
            print(f"  ok   {h}")
    if review["review"]:
        print("\n\033[33mUNRECOGNIZED — review before trusting:\033[0m"
              if sys.stdout.isatty() else "\nUNRECOGNIZED — review before trusting:")
        for h in review["review"]:
            print(f"  ??   {h}   <-- not a known host; remove from allow-list if unexpected")
    if not review["recognized"] and not review["review"]:
        print("  (the skill made no network egress)")
    print("\n" + "-" * 62)
    print("Generated least-privilege policy (review the allow-list above first):")
    print("-" * 62)
    print(to_yaml(generated))
    if args.out:
        print(f"written to {args.out} — edit the allow-list, then: driftward run --policy {args.out} ...")
    else:
        print("Re-run with --out <file> to save.")
    return code


def cmd_sessions(_args, _child):
    from . import sessions as sess
    rows = sess.list_summaries()
    if not rows:
        print("No sessions yet. Run: driftward run claude")
        return 0
    print(f"{'SESSION':<20} {'AGENT/CMD':<20} {'MODE':<8} {'RISK':<12} {'BLOCK':<6} INTEGRITY")
    print("-" * 82)
    for r in rows:
        who = (r.get("agent") or (r.get("command") or "").split(" ")[0] or "-")[:18]
        blk = r.get("blocked_count", 0)
        integ = "intact" if r.get("integrity_ok") else "TAMPERED"
        risk = r.get("risk", {})
        risk_s = f"{risk.get('score', 0)} {risk.get('level', '-')}"
        print(f"{r['id']:<20} {who:<20} {r.get('mode','-'):<8} {risk_s:<12} {blk:<6} {integ}")
    return 0


def cmd_risk(args, _child):
    from . import sessions as sess
    from . import intelligence
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("driftward: no session log found.", file=sys.stderr)
        return 1
    s = sess.summarize(log.stem)
    risk = s["risk"]
    color = {"critical": "\033[41m\033[97m", "high": "\033[31m", "medium": "\033[33m",
             "low": "\033[32m", "none": "\033[32m"}.get(risk["level"], "")
    reset = "\033[0m" if sys.stdout.isatty() else ""
    if not sys.stdout.isatty():
        color = ""
    print(f"Risk: {color}{risk['score']}/100 ({risk['level'].upper()}){reset}")
    for r in risk["reasons"]:
        print(f"  - {r}")
    if s.get("host_classes"):
        print("\nHosts:")
        order = {"suspicious": 0, "unrecognized": 1, "cloud": 2, "dev-infra": 3, "provider": 4}
        for host, cls in sorted(s["host_classes"].items(), key=lambda kv: order.get(kv[1], 9)):
            _, reason = intelligence.classify_host(host)
            flag = "!!" if cls == "suspicious" else ("? " if cls == "unrecognized" else "ok")
            print(f"  {flag} {host:<45} [{cls}] {reason}")
    return 0


def _summary_for_log(log_arg: str | None):
    from . import sessions as sess
    log = _resolve_log(log_arg)
    if not log or not log.exists():
        raise FileNotFoundError("no session log found")
    return sess.summarize(log.stem)


def _print_manifest(manifest: dict) -> None:
    print(f"Behavior: {manifest['subject']['key']}")
    print(f"Session : {manifest['session']['id']}")
    print(f"Digest  : {manifest['fingerprint']}")
    coverage = manifest.get("coverage", {})
    print("Coverage: network={}, deep={}, credentials={}".format(
        coverage.get("network", "unknown"),
        "yes" if coverage.get("deep") else "no",
        "yes" if coverage.get("credentials") else "no"))
    for category, capabilities in manifest.get("capabilities", {}).items():
        print(f"\n{category.title()} ({len(capabilities)})")
        if not capabilities:
            print("  —")
        for cap in capabilities:
            port = f":{cap['port']}" if cap.get("port") else ""
            print(f"  {cap.get('action', '?'):<10} {cap.get('resource', '?')}{port}")


def cmd_behavior(args, _child):
    import json
    from . import behavior

    manifest = behavior.build_manifest(_summary_for_log(args.log))
    if args.out:
        behavior.write_manifest(manifest, args.out)
        print(f"driftward: behavior manifest written to {args.out}", file=sys.stderr)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        _print_manifest(manifest)
    return 0


def cmd_baseline(args, _child):
    import json
    from . import behavior

    if args.baseline_cmd == "list":
        rows = behavior.list_baselines()
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
            return 0
        if not rows:
            print("No approved baselines. Start with: driftward baseline approve [session]")
            return 0
        print(f"{'BASELINE':<28} {'CAPS':<6} {'SIGNED':<8} SOURCE")
        print("-" * 76)
        for row in rows:
            source = ", ".join(str(s) for s in row.get("source_sessions", [])) or "—"
            print(f"{row['name'][:27]:<28} {row.get('capability_count', 0):<6} "
                  f"{('yes' if row.get('valid') else 'INVALID'):<8} {source}")
        return 0

    if args.baseline_cmd == "approve":
        manifest = behavior.build_manifest(_summary_for_log(args.log))
        baseline, path = behavior.approve(manifest, args.name, force=args.force)
        print(f"APPROVED  {baseline['name']}")
        print(f"signed by {baseline['signature']['public_key'][:16]}…")
        print(f"stored at {path}")
        return 0

    baseline = behavior.load_baseline(args.name, require_valid=False)
    if args.baseline_cmd == "verify":
        ok, message = behavior.verify_baseline(baseline, args.pubkey)
        print(("VERIFIED  " if ok else "FAILED    ") + message)
        return 0 if ok else 3
    if args.json:
        print(json.dumps(baseline, indent=2, sort_keys=True))
    else:
        ok, message = behavior.verify_baseline(baseline)
        print(f"Baseline: {baseline.get('name')}")
        print(f"State   : {baseline.get('state')}")
        print(f"Trust   : {message}")
        print(f"Source  : {', '.join(baseline.get('source_sessions', []))}")
        for category, capabilities in baseline.get("capabilities", {}).items():
            print(f"  {category:<11} {len(capabilities)} approved")
        return 0 if ok else 3
    return 0


def _print_diff(result: dict) -> None:
    status = result["status"].upper()
    if not result.get("session_integrity_ok", True):
        print("!! session receipt NOT intact — this diff is computed from a tampered "
              "log and cannot be trusted")
    print(f"{status}  {result['subject']} against '{result['baseline']}'")
    print(f"{result['new_count']} new · {result['removed_count']} absent · "
          f"highest severity {result['highest_severity']}")
    if not result["findings"] and not result["identity_changes"]:
        print("  No capabilities outside the approved baseline.")
    for finding in result["identity_changes"]:
        print(f"  {finding['severity'].upper():<8} identity   {finding['reason']}")
    for finding in result["findings"]:
        cap = finding["capability"]
        port = f":{cap['port']}" if cap.get("port") else ""
        print(f"  {finding['severity'].upper():<8} {finding['category']:<10} "
              f"{cap.get('action')} {cap.get('resource')}{port}")
        print(f"           {finding['reason']}")


def cmd_diff(args, _child):
    import json
    from . import behavior

    manifest = behavior.build_manifest(_summary_for_log(args.log))
    baseline = (behavior.load_baseline(args.baseline) if args.baseline
                else behavior.baseline_for_manifest(manifest))
    if baseline is None:
        raise behavior.BehaviorError(
            f"no approved baseline for '{manifest['subject']['key']}'; "
            "run: driftward baseline approve " + str(manifest["session"]["id"]))
    result = behavior.diff(manifest, baseline)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_diff(result)
    # Fail --exit-code on drift OR on a non-intact observation: a "stable" verdict
    # read from a tampered log is not a pass.
    untrustworthy = not result.get("session_integrity_ok", True)
    return 1 if args.exit_code and (result["status"] == "drift" or untrustworthy) else 0


def _bridge_env(server) -> dict:
    """Environment for the sandboxed remote bridge: Driftward's own package on the
    path so `-m driftward` imports under the scrubbed child env, plus the endpoint
    URL and any resolved request headers passed by value through private vars
    (never argv, never the log — the URL may carry query tokens or credentials)."""
    import json as _json
    from . import mcp
    env = {"PYTHONPATH": mcp._driftward_package_root(), "DRIFTWARD_MCP_URL": server.url}
    if server.headers:
        env["DRIFTWARD_MCP_HEADERS"] = _json.dumps(mcp.resolve_headers(server))
    return env


def cmd_mcp(args, child):
    import json
    import os
    from . import mcp
    from .policy import load

    if args.mcp_cmd == "_bridge":
        from . import mcp_remote
        url = os.environ.get("DRIFTWARD_MCP_URL") or args.url
        if not url:
            raise ValueError("remote bridge has no URL (expected DRIFTWARD_MCP_URL)")
        raw = os.environ.get("DRIFTWARD_MCP_HEADERS")
        headers = json.loads(raw) if raw else {}
        return mcp_remote.bridge(url, headers, transport=args.transport)

    if args.mcp_cmd == "list":
        servers = mcp.discover([args.config] if args.config else None)
        if args.json:
            print(json.dumps([{"name": s.name, "command": s.command, "args": s.args,
                               "env_names": s.env_declared, "url": s.url,
                               "source": s.source, "wrapped": s.wrapped,
                               "wrapped_valid": s.wrapped_valid,
                               "definition_sha256": s.definition_sha256}
                              for s in servers], indent=2))
            return 0
        if not servers:
            print("No MCP servers found. Looked in project .mcp.json, ~/.claude.json, "
                  "~/.cursor/mcp.json, and VS Code configs.\n"
                  "Point at one with: driftward mcp list --config path/to/mcp.json", file=sys.stderr)
            return 0
        print(f"{'MCP SERVER':<24} {'KIND':<7} {'WRAPPED':<8} LAUNCH")
        print("-" * 74)
        for s in servers:
            kind = "remote" if s.remote else "stdio"
            launch = s.url if s.remote else " ".join(s.launch_command())
            print(f"{s.name[:23]:<24} {kind:<7} {('yes' if s.wrapped else 'no'):<8} {launch[:34]}")
        print("\nRun one as its own principal:  driftward mcp run <name>")
        print("Wrap them all into your config: driftward mcp wrap --config <file>")
        return 0

    if args.mcp_cmd == "shim":
        from . import mcp_broker

        if os.environ.get(mcp_broker.BROKER_ENV):
            return mcp_broker.run_shim(args.name, args.config, args.definition)
        if os.environ.get("DRIFTWARD_ACTIVE"):
            raise RuntimeError(
                "this wrapped config was not registered by the parent Driftward; "
                "pass `--mcp-config " + args.config + "` to `driftward run`")
        server = mcp.find(args.name, [args.config])
        if not server or (server.command is None and not server.remote):
            raise ValueError(f"no launchable MCP server '{args.name}' in {args.config}")
        if server.definition_sha256 != args.definition:
            raise ValueError("MCP definition changed after wrapping; run `driftward mcp wrap --write` again")
        if server.remote:
            return run(mcp.bridge_command(server), mcp.remote_policy_for(server, os.getcwd()),
                       enforce=True, subject=mcp.subject_for(server),
                       env_overrides=_bridge_env(server), enable_mcp_broker=False)
        pol = mcp.policy_for(server, os.getcwd())
        return run(server.launch_command(), pol, enforce=True,
                   subject=mcp.subject_for(server), env_overrides=mcp.resolve_env(server),
                   enable_mcp_broker=False)

    if args.mcp_cmd == "_serve":
        import stat
        from .runner import _driftward_home

        grant = Path(args.grant)
        grants_root = (_driftward_home() / "mcp-grants").resolve()
        resolved = grant.resolve()
        if resolved.parent != grants_root or grant.is_symlink():
            raise ValueError("invalid MCP broker grant path")
        mode = grant.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("MCP broker grant is not a private regular file")
        server = mcp.McpServer.from_grant(json.loads(grant.read_text(encoding="utf-8")))
        if server.remote:
            return run(mcp.bridge_command(server), mcp.remote_policy_for(server, os.getcwd()),
                       enforce=True, subject=mcp.subject_for(server),
                       env_overrides=_bridge_env(server), enable_mcp_broker=False)
        if not server.command:
            raise ValueError("broker grants must describe a launchable server")
        pol = mcp.policy_for(server, os.getcwd())
        return run(server.launch_command(), pol, enforce=True,
                   subject=mcp.subject_for(server), env_overrides=mcp.resolve_env(server),
                   enable_mcp_broker=False)

    if args.mcp_cmd == "run":
        server = mcp.find(args.name, [args.config] if args.config else None)
        if not server:
            raise SystemExit(f"driftward: no MCP server '{args.name}' in the discovered configs "
                             "(try: driftward mcp list).")
        if server.remote:
            pol = load(args.policy) if args.policy else mcp.remote_policy_for(server, os.getcwd())
            from urllib.parse import urlparse
            print(f"driftward: remote MCP '{server.name}' as principal 'mcp:{server.name}', "
                  f"egress locked to {urlparse(server.url).hostname}, enforcing", file=sys.stderr)
            return run(mcp.bridge_command(server), pol, enforce=True,
                       subject=mcp.subject_for(server), env_overrides=_bridge_env(server),
                       enable_mcp_broker=False)
        if child:
            from dataclasses import replace
            server = replace(server, args=server.args + child)
        pol = load(args.policy) if args.policy else mcp.policy_for(server, os.getcwd())
        if args.policy:
            from dataclasses import replace
            pol = replace(pol, env_allow=sorted(set(pol.env_allow) | set(server.env_declared)))
        argv = server.launch_command()
        print(f"driftward: MCP server '{server.name}' as principal 'mcp:{server.name}', "
              f"policy '{pol.name}', enforcing", file=sys.stderr)
        return run(argv, pol, enforce=True, subject=mcp.subject_for(server),
                   env_overrides=mcp.resolve_env(server), enable_mcp_broker=False)

    # wrap / unwrap
    if not args.config:
        raise SystemExit("driftward: --config <file> is required for wrap/unwrap.")
    doc, _servers = mcp.parse_config(args.config)
    new_doc, changed = mcp.transform_config(
        doc, wrap=(args.mcp_cmd == "wrap"), config=args.config)
    verb = "wrapped" if args.mcp_cmd == "wrap" else "unwrapped"
    if not changed:
        print(f"driftward: nothing to {args.mcp_cmd} in {args.config} "
              f"(stdio servers already {verb}, or none present).", file=sys.stderr)
        return 0
    rendered = json.dumps(new_doc, indent=2) + "\n"
    if args.write:
        backup = mcp.write_config_atomic(args.config, rendered)
        print(f"driftward: {verb} {len(changed)} server(s) in {args.config} "
              f"({', '.join(changed)}). Backup: {backup.name}", file=sys.stderr)
    else:
        print(rendered, end="")
        print(f"driftward: would {args.mcp_cmd} {len(changed)} server(s): {', '.join(changed)}. "
              "Re-run with --write to apply (a .bak backup is kept).", file=sys.stderr)
    return 0


def cmd_registry(args, _child):
    import json
    import re
    from . import behavior, registry

    if args.registry_cmd == "trust":
        if args.list:
            keys = registry.trusted_keys()
            if not keys:
                print("No trusted registry keys. Add one with: driftward registry trust <pubkey>")
                return 0
            for k in keys:
                print(f"{k['public_key']}  {k.get('label','') or '—'}")
            return 0
        if not args.key:
            print("driftward: provide a public key to trust, or --list.", file=sys.stderr)
            return 2
        if args.remove:
            removed = registry.untrust_key(args.key)
            print("removed" if removed else "not found")
            return 0 if removed else 1
        record = registry.trust_key(args.key, args.label or "")
        print(f"TRUSTED  {record['public_key']}  {record.get('label','') or '—'}")
        print("Entries signed by this key can now be installed.")
        return 0

    if args.registry_cmd == "publish":
        baseline = behavior.load_baseline(args.name)
        provenance = {"reviewer": args.reviewer or "", "source": args.source or "",
                      "notes": args.notes or ""}
        policy = None
        if args.policy:
            from .policy import load as load_policy
            policy = load_policy(args.policy).to_dict()
        entry = registry.entry_from_baseline(baseline, provenance, policy=policy)
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", entry["subject"]["name"]).strip("-.") or "entry"
        out = Path(args.out) if args.out else registry.entries_dir() / f"{slug}.json"
        registry.publish(entry, out)
        print(f"PUBLISHED  {entry['subject']['kind']}:{entry['subject']['name']}")
        print(f"signed by {entry['signature']['public_key']}")
        print(f"written to {out}")
        print("Share this file (e.g. open a PR to a registry repo); others trust your key to use it.")
        return 0

    if args.registry_cmd in ("verify", "list"):
        entries = registry.load_entries(args.paths or None)
        if not entries:
            print("No registry entries found.", file=sys.stderr)
            return 1
        if args.registry_cmd == "list" and args.json:
            print(json.dumps([{k: v for k, v in e.items() if k != "signature"} for e in entries],
                             indent=2, sort_keys=True))
            return 0
        print(f"{'SUBJECT':<30} {'CAPS':<5} {'SIGNER':<16} STATUS")
        print("-" * 78)
        bad = 0
        for e in entries:
            subj = e.get("subject", {})
            ok, reason, signer = registry.entry_trust(e)
            if not ok and "not trusted" not in reason and "trusted" not in reason:
                bad += 1
            caps = sum(len(e.get("capabilities", {}).get(c, [])) for c in registry.CATEGORIES)
            status = "trusted" if ok else ("UNTRUSTED" if signer else "INVALID")
            name = f"{subj.get('kind','?')}:{subj.get('name','?')}"
            print(f"{name[:29]:<30} {caps:<5} {(signer[:14] + '…') if signer else '—':<16} {status}")
        return 1 if bad else 0

    if args.registry_cmd == "install":
        entry = registry.find_entry(args.name, kind=args.kind, paths=args.source or None)
        if not entry:
            raise SystemExit(f"driftward: no registry entry named '{args.name}' in the given source(s).")
        baseline, path = registry.install(entry, force=args.force)
        print(f"INSTALLED  {baseline['name']}  (state: registry)")
        print(f"provenance: signer {baseline['provenance']['registry_signer'][:12]}…"
              f" reviewer '{baseline['provenance'].get('reviewer','')}'")
        print(f"stored at {path}")
        print("Drift for this subject now compares against the community baseline.")
        if args.policy_out:
            if not entry.get("policy"):
                print("driftward: this entry carries no reviewed policy.", file=sys.stderr)
                return 1
            Path(args.policy_out).write_text(json.dumps(entry["policy"], indent=2), encoding="utf-8")
            print(f"reviewed policy written to {args.policy_out} — use: driftward run --policy {args.policy_out}")
        return 0
    return 0


def cmd_scan(args, _child):
    from . import scanner, scan_report

    try:
        targets = scanner.load_corpus(args.corpus)
    except (NotADirectoryError, OSError) as exc:
        print(f"driftward: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print(f"driftward: no skills found under {args.corpus} "
              "(each skill is a subdirectory).", file=sys.stderr)
        return 1

    mode = "static-only (no code executed)" if args.static_only else "static + detonation"
    print(f"driftward scan: {len(targets)} skill(s) under {args.corpus} — {mode}\n", file=sys.stderr)
    results = scanner.scan_corpus(targets, allow_egress=args.allow_egress,
                                  static_only=args.static_only,
                                  log=lambda m: print("  " + m, file=sys.stderr))
    agg = scanner.aggregate(results)

    print("\n" + "=" * 62)
    print(f"DRIFTWARD SCAN — {agg['total']} skills ({agg['detonated']} detonated, "
          f"{agg['static_only']} static-only)")
    print("=" * 62)
    print(f"  {agg['pct_contacting_undisclosed']:>5}%  contacted an UNDISCLOSED host")
    print(f"  {agg['pct_contacting_suspicious']:>5}%  reached SUSPICIOUS infrastructure")
    print(f"  {agg['pct_credential_refs']:>5}%  reference credential paths (static)")
    print(f"  {agg['pct_injection_patterns']:>5}%  contain injection patterns (static)")
    if agg["top_suspicious"]:
        print("\n  Suspicious hosts contacted:")
        for h, n in agg["top_suspicious"][:8]:
            print(f"    !! {h}  ({n})")
    if agg["worst_offenders"]:
        print("\n  Highest-risk skills:")
        for o in agg["worst_offenders"][:8]:
            extra = ", ".join(o["undisclosed"][:3] + o["injection"][:2])
            print(f"    {o['risk']:>3} {o['level']:<8} {o['name']}  {extra}")

    if args.json:
        Path(args.json).write_text(scan_report.render_json(agg, results), encoding="utf-8")
        print(f"\ndriftward: JSON written to {args.json}", file=sys.stderr)
    if args.html:
        Path(args.html).write_text(scan_report.render_html(agg, title=args.title),
                                   encoding="utf-8")
        print(f"driftward: HTML finding written to {args.html}", file=sys.stderr)
    if not args.json and not args.html:
        print("\n  (add --html report.html or --json report.json to save the finding)")
    return 0


def cmd_gate(args, _child):
    """CI gate: exit non-zero if a session's risk or egress fails policy."""
    from . import sessions as sess
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("driftward: no session log found.", file=sys.stderr)
        return 1
    s = sess.summarize(log.stem)
    risk = s["risk"]
    failures = []
    if risk["score"] > args.max_risk:
        failures.append(f"risk {risk['score']} exceeds max {args.max_risk} ({risk['level']})")
    if args.fail_on_blocked and s["blocked_count"] > 0:
        failures.append(f"{s['blocked_count']} egress destination(s) were blocked")
    if not s["integrity_ok"]:
        failures.append("session log integrity check failed")
    behavior_diff = None
    if args.baseline or args.fail_on_new is not None:
        from . import behavior
        manifest = behavior.build_manifest(s)
        reference = args.baseline or behavior.default_baseline_name(manifest)
        baseline = behavior.load_baseline(reference)
        behavior_diff = behavior.diff(manifest, baseline)
        requested = args.fail_on_new
        if requested is not None:
            categories = set(behavior.CATEGORIES) if requested == "all" else {
                part.strip() for part in requested.split(",") if part.strip()
            }
            unknown = categories - set(behavior.CATEGORIES)
            if unknown:
                raise behavior.BehaviorError(
                    "unknown capability category: " + ", ".join(sorted(unknown)))
            count = sum(len(behavior_diff["new"].get(category, [])) for category in categories)
            if count:
                failures.append(
                    f"{count} new behavior capability(s) in {', '.join(sorted(categories))}")
            if behavior_diff["identity_changes"]:
                failures.append(f"{len(behavior_diff['identity_changes'])} runtime/policy identity change(s)")
    print(f"driftward gate: risk {risk['score']}/100 ({risk['level']}), "
          f"{s['blocked_count']} blocked, {s.get('warned_count', 0)} warned")
    for r in risk["reasons"]:
        print(f"  - {r}")
    if behavior_diff is not None:
        print(f"driftward gate: behavior {behavior_diff['status']}, "
              f"{behavior_diff['new_count']} new, "
              f"severity {behavior_diff['highest_severity']}")
    if failures:
        print("GATE FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  ✗ {f}", file=sys.stderr)
        return 1
    print("GATE PASSED")
    return 0


def cmd_report(args, _child):
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("driftward: no session log found.", file=sys.stderr)
        return 1
    print(build_report(log))
    return 0


def cmd_verify(args, _child):
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("driftward: no session log found.", file=sys.stderr)
        return 1
    ok, msg = verify_log(log, expect_pubkey=args.pubkey)
    print(("VERIFIED  " if ok else "FAILED    ") + msg)
    return 0 if ok else 3


def cmd_key(_args, _child):
    from . import crypto
    print(crypto.public_key_hex())
    print("\nShare this public key so others can verify your session receipts with:",
          file=sys.stderr)
    print("  driftward verify <log> --pubkey <this-key>", file=sys.stderr)
    return 0


def cmd_policy(args, _child):
    import json
    import os

    if args.agent:
        agent = agentmod.get(args.agent)
        if not agent:
            raise SystemExit(f"driftward: unknown agent '{args.agent}'")
        pol = load(args.policy) if args.policy else agentmod.policy_for(agent, os.getcwd())
    else:
        pol = load(args.policy) if args.policy else default_policy()
    if args.what == "sbpl":
        print(seatbelt.compile_profile(pol, 0))
    else:
        print(json.dumps(pol.to_dict(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="driftward",
                                description="Least privilege and a flight recorder for AI coding agents.")
    p.add_argument("--version", action="version", version=f"driftward {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="enforce a policy and record")
    r.add_argument("agent", nargs="?", help="a known agent (claude, codex, cursor, …)")
    r.add_argument("--policy", help="policy file; overrides the agent/default policy")
    r.add_argument("--strict", action="store_true",
                   help="strict filesystem: deny all writes outside the allow-list")
    r.add_argument("--strict-read", action="store_true",
                   help="confine reads: deny the user's home except the read allow-list "
                        "(project + agent config); system paths stay readable")
    r.add_argument("--deep", action="store_true",
                   help="comprehensive file/process recording via eslogger (needs sudo + Full Disk Access)")
    r.add_argument("--deep-files", action="store_true",
                   help="with --deep, also record every file open (high volume)")
    r.add_argument("--allow-record-fallback", action="store_true",
                   help="if OS enforcement is unavailable, explicitly fall back to proxy-only recording")
    r.add_argument("--subject",
                   help="behavioral principal for this run (e.g. mcp:github), so its baseline "
                        "and drift are tracked apart from the launching agent")
    r.add_argument("--mcp-config", action="append", default=[],
                   help="pre-register an additional wrapped MCP config with the parent broker "
                        "(repeatable; standard config locations are automatic)")
    kc = r.add_mutually_exclusive_group()
    kc.add_argument("--allow-keychain", action="store_true",
                    help="let the run read the macOS Keychain (needed by agents that log in there)")
    kc.add_argument("--deny-keychain", action="store_true",
                    help="seal the macOS Keychain even for an agent that authenticates through it")
    r.set_defaults(func=cmd_run)

    rec = sub.add_parser("record", help="record only, no enforcement")
    rec.add_argument("agent", nargs="?", help="a known agent")
    rec.add_argument("--policy", help="policy file for the egress allow-list")
    rec.set_defaults(func=cmd_record)

    ag = sub.add_parser("agents", help="list supported AI tools")
    ag.set_defaults(func=cmd_agents)

    ini = sub.add_parser("init", help="scaffold a project .driftward.yaml policy")
    ini.add_argument("agent", nargs="?", help="base the policy on this agent")
    ini.add_argument("--force", action="store_true", help="overwrite an existing file")
    ini.set_defaults(func=cmd_init)

    dash = sub.add_parser("dashboard", help="open the local session dashboard")
    dash.add_argument("--no-open", action="store_true", help="do not open a browser")
    dash.set_defaults(func=cmd_dashboard)

    doc = sub.add_parser("doctor", help="verify Driftward actually works on this machine")
    doc.set_defaults(func=cmd_doctor)

    prof = sub.add_parser("profile", help="detonate a skill and generate a least-privilege policy")
    prof.add_argument("agent", nargs="?", help="a known agent, or omit and pass a command after --")
    prof.add_argument("--out", help="write the generated policy to this file")
    prof.add_argument("--allow-egress", action="store_true",
                      help="let connections through (fuller profile; only for semi-trusted skills)")
    prof.set_defaults(func=cmd_profile)

    ses = sub.add_parser("sessions", help="list recorded sessions")
    ses.set_defaults(func=cmd_sessions)

    rk = sub.add_parser("risk", help="score a session's risk and classify its hosts")
    rk.add_argument("log", nargs="?")
    rk.set_defaults(func=cmd_risk)

    beh = sub.add_parser("behavior", help="emit a versioned capability manifest for a session")
    beh.add_argument("log", nargs="?", help="session log/path/id; defaults to latest")
    beh.add_argument("--json", action="store_true", help="print machine-readable JSON")
    beh.add_argument("--out", help="write the JSON manifest to a file")
    beh.set_defaults(func=cmd_behavior)

    base = sub.add_parser("baseline", help="manage explicitly approved, signed behavior")
    base_sub = base.add_subparsers(dest="baseline_cmd", required=True)
    base_list = base_sub.add_parser("list", help="list approved baselines")
    base_list.add_argument("--json", action="store_true")
    base_list.set_defaults(func=cmd_baseline)
    base_approve = base_sub.add_parser("approve", help="approve a session as trusted behavior")
    base_approve.add_argument("log", nargs="?", help="session log/path/id; defaults to latest")
    base_approve.add_argument("--name", help="stable baseline name; defaults to agent/command identity")
    base_approve.add_argument("--force", action="store_true",
                              help="replace an existing baseline with this signed approval")
    base_approve.set_defaults(func=cmd_baseline)
    base_show = base_sub.add_parser("show", help="inspect an approved baseline")
    base_show.add_argument("name", help="baseline name or JSON path")
    base_show.add_argument("--json", action="store_true")
    base_show.set_defaults(func=cmd_baseline)
    base_verify = base_sub.add_parser("verify", help="verify a baseline's signature")
    base_verify.add_argument("name", help="baseline name or JSON path")
    base_verify.add_argument("--pubkey", help="require this Ed25519 public key")
    base_verify.set_defaults(func=cmd_baseline)

    dif = sub.add_parser("diff", help="compare a session with approved behavior")
    dif.add_argument("log", nargs="?", help="session log/path/id; defaults to latest")
    dif.add_argument("--baseline", help="baseline name/path; defaults to the session identity")
    dif.add_argument("--json", action="store_true", help="print machine-readable JSON")
    dif.add_argument("--exit-code", action="store_true", help="exit 1 when drift is present")
    dif.set_defaults(func=cmd_diff)

    mc = sub.add_parser("mcp", help="run each MCP server as its own confined, baselined principal")
    mcp_sub = mc.add_subparsers(dest="mcp_cmd", required=True)
    mcp_list = mcp_sub.add_parser("list", help="discover configured MCP servers")
    mcp_list.add_argument("--config", help="an explicit MCP config file to read")
    mcp_list.add_argument("--json", action="store_true", help="print machine-readable JSON")
    mcp_list.set_defaults(func=cmd_mcp)
    mcp_run = mcp_sub.add_parser("run", help="run one MCP server as principal mcp:<name>")
    mcp_run.add_argument("name", help="the configured server name")
    mcp_run.add_argument("--config", help="an explicit MCP config file to read")
    mcp_run.add_argument("--policy", help="policy file; overrides the MCP baseline")
    mcp_run.set_defaults(func=cmd_mcp)
    mcp_shim = mcp_sub.add_parser("shim", help="internal stdio bridge used by wrapped configs")
    mcp_shim.add_argument("name")
    mcp_shim.add_argument("--config", required=True)
    mcp_shim.add_argument("--definition", required=True)
    mcp_shim.set_defaults(func=cmd_mcp)
    mcp_serve = mcp_sub.add_parser("_serve", help="internal parent-broker launcher")
    mcp_serve.add_argument("--grant", required=True)
    mcp_serve.set_defaults(func=cmd_mcp)
    mcp_bridge = mcp_sub.add_parser("_bridge", help="internal stdio-to-remote MCP bridge")
    mcp_bridge.add_argument("--url", help="(URL normally arrives via DRIFTWARD_MCP_URL, off argv)")
    mcp_bridge.add_argument("--transport", default="streamable-http",
                            choices=["streamable-http", "sse"])
    mcp_bridge.set_defaults(func=cmd_mcp)

    reg = sub.add_parser("registry",
                         help="share/adopt signed, reviewed behavior baselines for MCP servers & skills")
    reg_sub = reg.add_subparsers(dest="registry_cmd", required=True)
    reg_trust = reg_sub.add_parser("trust", help="trust a publisher key (or --list / --remove)")
    reg_trust.add_argument("key", nargs="?", help="64-hex Ed25519 public key")
    reg_trust.add_argument("--label", help="a human label for this key")
    reg_trust.add_argument("--list", action="store_true", help="list trusted keys")
    reg_trust.add_argument("--remove", action="store_true", help="stop trusting this key")
    reg_trust.set_defaults(func=cmd_registry)
    reg_pub = reg_sub.add_parser("publish", help="sign a reviewed local baseline as a shareable entry")
    reg_pub.add_argument("name", help="an approved baseline name (see: driftward baseline list)")
    reg_pub.add_argument("--out", help="write the entry here (default: local registry)")
    reg_pub.add_argument("--reviewer", help="who reviewed this")
    reg_pub.add_argument("--source", help="URL/reference for the review")
    reg_pub.add_argument("--notes", help="review notes")
    reg_pub.add_argument("--policy", help="include a reviewed least-privilege policy file")
    reg_pub.set_defaults(func=cmd_registry)
    reg_verify = reg_sub.add_parser("verify", help="verify entries' signatures and trust status")
    reg_verify.add_argument("paths", nargs="*", help="entry files/dirs (default: local registry)")
    reg_verify.set_defaults(func=cmd_registry)
    reg_list = reg_sub.add_parser("list", help="list registry entries")
    reg_list.add_argument("paths", nargs="*", help="entry files/dirs (default: local registry)")
    reg_list.add_argument("--json", action="store_true")
    reg_list.set_defaults(func=cmd_registry)
    reg_install = reg_sub.add_parser("install", help="adopt a trusted entry as a local baseline")
    reg_install.add_argument("name", help="the subject name to install")
    reg_install.add_argument("--kind", help="disambiguate by kind (mcp, skill, agent, command)")
    reg_install.add_argument("--from", dest="source", action="append",
                             help="entry file/dir to install from (repeatable)")
    reg_install.add_argument("--policy-out", help="also write the entry's reviewed policy here")
    reg_install.add_argument("--force", action="store_true", help="replace an existing baseline")
    reg_install.set_defaults(func=cmd_registry)
    mcp_wrap = mcp_sub.add_parser("wrap", help="rewrite a config so each server launches through Driftward")
    mcp_wrap.add_argument("--config", required=True, help="the MCP config file to rewrite")
    mcp_wrap.add_argument("--write", action="store_true", help="apply in place (keeps a .bak backup)")
    mcp_wrap.set_defaults(func=cmd_mcp)
    mcp_unwrap = mcp_sub.add_parser("unwrap", help="revert a wrapped config to direct launches")
    mcp_unwrap.add_argument("--config", required=True, help="the MCP config file to restore")
    mcp_unwrap.add_argument("--write", action="store_true", help="apply in place (keeps a .bak backup)")
    mcp_unwrap.set_defaults(func=cmd_mcp)

    sc = sub.add_parser("scan", help="batch-scan a corpus of skills; produce a shareable finding")
    sc.add_argument("corpus", help="a directory whose subdirectories are skills")
    sc.add_argument("--html", help="write a shareable HTML finding to this path")
    sc.add_argument("--json", help="write the full results as JSON to this path")
    sc.add_argument("--title", default="AI Agent Skill Behavior Scan", help="report title")
    sc.add_argument("--allow-egress", action="store_true",
                    help="let detonated skills reach the network (fuller behavior; less safe)")
    sc.add_argument("--static-only", action="store_true",
                    help="never execute anything — safe to run on a large untrusted corpus")
    sc.set_defaults(func=cmd_scan)

    g = sub.add_parser("gate", help="CI gate: fail if a session's risk/egress is too high")
    g.add_argument("log", nargs="?")
    g.add_argument("--max-risk", type=int, default=40, help="fail if risk exceeds this (default 40)")
    g.add_argument("--fail-on-blocked", action="store_true", help="also fail if any egress was blocked")
    g.add_argument("--baseline", help="approved behavior name/path to compare")
    g.add_argument("--fail-on-new", nargs="?", const="all",
                   metavar="CATEGORIES",
                   help="fail on new behavior (all, or comma-separated network,process,"
                        "filesystem,ipc,credential)")
    g.set_defaults(func=cmd_gate)

    rep = sub.add_parser("report", help="show what a session did")
    rep.add_argument("log", nargs="?")
    rep.set_defaults(func=cmd_report)

    v = sub.add_parser("verify", help="check a session's tamper-evident chain and signature")
    v.add_argument("log", nargs="?")
    v.add_argument("--pubkey", help="require the seal to be signed by this Ed25519 public key (hex)")
    v.set_defaults(func=cmd_verify)

    k = sub.add_parser("key", help="print this machine's Driftward public key")
    k.set_defaults(func=cmd_key)

    pol = sub.add_parser("policy", help="inspect the effective policy")
    pol.add_argument("what", choices=["show", "sbpl"])
    pol.add_argument("agent", nargs="?", help="show an agent's policy")
    pol.add_argument("--policy")
    pol.set_defaults(func=cmd_policy)
    return p


def main(argv: list[str] | None = None) -> int:
    from .policy import PolicyError
    from .behavior import BehaviorError

    argv = list(sys.argv[1:] if argv is None else argv)
    driftward_args, child = _split_cmd(argv)
    parser = build_parser()
    args = parser.parse_args(driftward_args)
    try:
        return args.func(args, child)
    except PolicyError as exc:
        print(f"driftward: invalid policy — {exc}", file=sys.stderr)
        print("  (policies use a minimal YAML subset; use block style, not "
              "inline {..} maps. See examples/demo.policy.yaml)", file=sys.stderr)
        return 2
    except BehaviorError as exc:
        print(f"driftward: behavior error — {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"driftward: file not found — {exc}", file=sys.stderr)
        return 2
    except (ValueError, RuntimeError) as exc:
        print(f"driftward: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
