"""Warden command-line interface.

  warden run    [AGENT] [--policy F] [-- ARGS]     enforce a policy + record
  warden record [AGENT] [--policy F] [-- ARGS]     record only, no enforcement
  warden run    -- <command...>                    run any command under the default policy
  warden profile [AGENT] [--out F] [-- ARGS]       detonate a skill, generate a policy
  warden scan CORPUS [--html F] [--json F]         batch-scan a corpus → shareable finding
  warden risk|gate [LOG]                           score / CI-gate a session
  warden agents                                    list supported AI tools
  warden init   [AGENT]                            scaffold a project .warden.yaml
  warden dashboard                                 open the local session dashboard
  warden doctor                                    prove enforcement works here
  warden sessions                                  list recorded sessions
  warden report [LOG]                              show what a session did
  warden verify [LOG] [--pubkey HEX]               check the chain + signature
  warden key                                       print this machine's public key
  warden policy show|sbpl [AGENT] [--policy F]     inspect the effective policy
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

    Policy precedence: explicit --policy > project .warden.yaml > agent baseline
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
            raise SystemExit(f"warden: unknown agent '{agent_name}'. Known: {known}")
        cmd = agentmod.resolve_command(agent)
        if not cmd:
            raise SystemExit(
                f"warden: '{agent.name}' is not installed (looked for: {', '.join(agent.commands)}).")
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
        print("warden: specify an agent or a command.\n"
              "  warden run claude\n  warden run -- sh script.sh", file=sys.stderr)
        return 2
    argv, pol, key, source = _resolve(args.agent, args.policy, child)
    if not argv:
        print("warden: nothing to run.", file=sys.stderr)
        return 2
    if getattr(args, "strict", False):
        pol.strict_fs = True
    extra = " + strict-fs" if pol.strict_fs else ""
    if getattr(args, "deep", False):
        extra += " + deep-recording"
        print("warden: --deep needs sudo + Full Disk Access on your terminal; "
              "it is best-effort and won't break the run if unavailable.", file=sys.stderr)
    print(f"warden: policy '{pol.name}' (from {source}), enforcing{extra}", file=sys.stderr)
    return run(argv, pol, enforce=True, agent=key,
               deep=getattr(args, "deep", False), deep_files=getattr(args, "deep_files", False))


def cmd_record(args, child):
    if not args.agent and not child:
        print("warden: specify an agent or a command.", file=sys.stderr)
        return 2
    argv, pol, key, source = _resolve(args.agent, args.policy, child)
    print(f"warden: policy '{pol.name}' (from {source}), observe-only", file=sys.stderr)
    return run(argv, pol, enforce=False, agent=key)


def cmd_init(args, _child):
    import os
    from .policy import to_yaml

    target = Path(os.getcwd()) / ".warden.yaml"
    if target.exists() and not args.force:
        print(f"warden: {target} already exists (use --force to overwrite).", file=sys.stderr)
        return 1
    if args.agent:
        agent = agentmod.get(args.agent)
        if not agent:
            raise SystemExit(f"warden: unknown agent '{args.agent}'")
        pol = agentmod.policy_for(agent, os.getcwd())
        pol.name = Path(os.getcwd()).name
    else:
        pol = default_policy(os.getcwd())
        pol.name = Path(os.getcwd()).name
    target.write_text(to_yaml(pol), encoding="utf-8")
    print(f"warden: wrote {target}")
    print("Edit the allow-list to match your project, then: warden run <agent>")
    return 0


def cmd_agents(_args, _child):
    rows = agentmod.describe_all()
    print(f"{'AGENT':<10} {'INSTALLED':<10} {'HOSTS':<6} NAME")
    print("-" * 60)
    for r in rows:
        mark = "yes" if r["installed"] else "no"
        print(f"{r['key']:<10} {mark:<10} {r['egress_count']:<6} {r['name']}")
    print("\nRun one with:  warden run <agent>      (e.g. warden run claude)")
    print("Observe first: warden record <agent>   then  warden report")
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
        print("warden: specify an agent or a command to profile.\n"
              "  warden profile ./some-skill.sh\n  warden profile cursor", file=sys.stderr)
        return 2
    code, generated, review = profile(child, agent=args.agent, allow_egress=args.allow_egress,
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
        print(f"written to {args.out} — edit the allow-list, then: warden run --policy {args.out} ...")
    else:
        print("Re-run with --out <file> to save.")
    return code


def cmd_sessions(_args, _child):
    from . import sessions as sess
    rows = sess.list_summaries()
    if not rows:
        print("No sessions yet. Run: warden run claude")
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
        print("warden: no session log found.", file=sys.stderr)
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


def cmd_scan(args, _child):
    from . import scanner, scan_report

    try:
        targets = scanner.load_corpus(args.corpus)
    except (NotADirectoryError, OSError) as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print(f"warden: no skills found under {args.corpus} "
              "(each skill is a subdirectory).", file=sys.stderr)
        return 1

    mode = "static-only (no code executed)" if args.static_only else "static + detonation"
    print(f"warden scan: {len(targets)} skill(s) under {args.corpus} — {mode}\n", file=sys.stderr)
    results = scanner.scan_corpus(targets, allow_egress=args.allow_egress,
                                  static_only=args.static_only,
                                  log=lambda m: print("  " + m, file=sys.stderr))
    agg = scanner.aggregate(results)

    print("\n" + "=" * 62)
    print(f"WARDEN SCAN — {agg['total']} skills ({agg['detonated']} detonated, "
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
        print(f"\nwarden: JSON written to {args.json}", file=sys.stderr)
    if args.html:
        Path(args.html).write_text(scan_report.render_html(agg, title=args.title),
                                   encoding="utf-8")
        print(f"warden: HTML finding written to {args.html}", file=sys.stderr)
    if not args.json and not args.html:
        print("\n  (add --html report.html or --json report.json to save the finding)")
    return 0


def cmd_gate(args, _child):
    """CI gate: exit non-zero if a session's risk or egress fails policy."""
    from . import sessions as sess
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("warden: no session log found.", file=sys.stderr)
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
    print(f"warden gate: risk {risk['score']}/100 ({risk['level']}), "
          f"{s['blocked_count']} blocked, {s.get('warned_count', 0)} warned")
    for r in risk["reasons"]:
        print(f"  - {r}")
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
        print("warden: no session log found.", file=sys.stderr)
        return 1
    print(build_report(log))
    return 0


def cmd_verify(args, _child):
    log = _resolve_log(args.log)
    if not log or not log.exists():
        print("warden: no session log found.", file=sys.stderr)
        return 1
    ok, msg = verify_log(log, expect_pubkey=args.pubkey)
    print(("VERIFIED  " if ok else "FAILED    ") + msg)
    return 0 if ok else 3


def cmd_key(_args, _child):
    from . import crypto
    print(crypto.public_key_hex())
    print("\nShare this public key so others can verify your session receipts with:",
          file=sys.stderr)
    print("  warden verify <log> --pubkey <this-key>", file=sys.stderr)
    return 0


def cmd_policy(args, _child):
    import json
    import os

    if args.agent:
        agent = agentmod.get(args.agent)
        if not agent:
            raise SystemExit(f"warden: unknown agent '{args.agent}'")
        pol = load(args.policy) if args.policy else agentmod.policy_for(agent, os.getcwd())
    else:
        pol = load(args.policy) if args.policy else default_policy()
    if args.what == "sbpl":
        print(seatbelt.compile_profile(pol, 0))
    else:
        print(json.dumps(pol.to_dict(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden",
                                description="Least privilege and a flight recorder for AI coding agents.")
    p.add_argument("--version", action="version", version=f"warden {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="enforce a policy and record")
    r.add_argument("agent", nargs="?", help="a known agent (claude, codex, cursor, …)")
    r.add_argument("--policy", help="policy file; overrides the agent/default policy")
    r.add_argument("--strict", action="store_true",
                   help="strict filesystem: deny all writes outside the allow-list")
    r.add_argument("--deep", action="store_true",
                   help="comprehensive file/process recording via eslogger (needs sudo + Full Disk Access)")
    r.add_argument("--deep-files", action="store_true",
                   help="with --deep, also record every file open (high volume)")
    r.set_defaults(func=cmd_run)

    rec = sub.add_parser("record", help="record only, no enforcement")
    rec.add_argument("agent", nargs="?", help="a known agent")
    rec.add_argument("--policy", help="policy file for the egress allow-list")
    rec.set_defaults(func=cmd_record)

    ag = sub.add_parser("agents", help="list supported AI tools")
    ag.set_defaults(func=cmd_agents)

    ini = sub.add_parser("init", help="scaffold a project .warden.yaml policy")
    ini.add_argument("agent", nargs="?", help="base the policy on this agent")
    ini.add_argument("--force", action="store_true", help="overwrite an existing file")
    ini.set_defaults(func=cmd_init)

    dash = sub.add_parser("dashboard", help="open the local session dashboard")
    dash.add_argument("--no-open", action="store_true", help="do not open a browser")
    dash.set_defaults(func=cmd_dashboard)

    doc = sub.add_parser("doctor", help="verify Warden actually works on this machine")
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
    g.set_defaults(func=cmd_gate)

    rep = sub.add_parser("report", help="show what a session did")
    rep.add_argument("log", nargs="?")
    rep.set_defaults(func=cmd_report)

    v = sub.add_parser("verify", help="check a session's tamper-evident chain and signature")
    v.add_argument("log", nargs="?")
    v.add_argument("--pubkey", help="require the seal to be signed by this Ed25519 public key (hex)")
    v.set_defaults(func=cmd_verify)

    k = sub.add_parser("key", help="print this machine's Warden public key")
    k.set_defaults(func=cmd_key)

    pol = sub.add_parser("policy", help="inspect the effective policy")
    pol.add_argument("what", choices=["show", "sbpl"])
    pol.add_argument("agent", nargs="?", help="show an agent's policy")
    pol.add_argument("--policy")
    pol.set_defaults(func=cmd_policy)
    return p


def main(argv: list[str] | None = None) -> int:
    from .policy import PolicyError

    argv = list(sys.argv[1:] if argv is None else argv)
    warden_args, child = _split_cmd(argv)
    parser = build_parser()
    args = parser.parse_args(warden_args)
    try:
        return args.func(args, child)
    except PolicyError as exc:
        print(f"warden: invalid policy — {exc}", file=sys.stderr)
        print("  (policies use a minimal YAML subset; use block style, not "
              "inline {..} maps. See examples/demo.policy.yaml)", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"warden: file not found — {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
