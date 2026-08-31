"""Per-MCP identity, broker isolation, env, wrapping, and drift regressions."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import behavior, mcp, mcp_broker
from driftward.policy import DEFAULT_SECRET_DENY


class McpDiscovery(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="driftward-mcp-"))
        self.cfg = self.d / ".mcp.json"
        self.cfg.write_text(json.dumps({"mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                       "env": {"GITHUB_TOKEN": "configured-secret", "FROM_PARENT": "${PARENT_KEY}"}},
            "remote-thing": {"url": "https://example.com/sse"},
        }}), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_discovers_stdio_remote_and_env_values(self):
        servers = {s.name: s for s in mcp.discover([self.cfg])}
        self.assertEqual(servers["github"].launch_command(),
                         ["npx", "-y", "@modelcontextprotocol/server-github"])
        self.assertEqual(servers["github"].env_declared, ["FROM_PARENT", "GITHUB_TOKEN"])
        self.assertEqual(servers["github"].env["GITHUB_TOKEN"], "configured-secret")
        self.assertEqual(mcp.resolve_env(servers["github"], {"PARENT_KEY": "resolved"}),
                         {"GITHUB_TOKEN": "configured-secret", "FROM_PARENT": "resolved"})
        self.assertFalse(servers["github"].remote)
        self.assertTrue(servers["remote-thing"].remote)

    def test_remote_endpoints_are_reported_for_allowlisting(self):
        # Remote servers can't be sandboxed, but their declared host must be
        # discoverable so the agent can reach (and Driftward can record) it.
        remotes = mcp.remote_endpoints([self.cfg])
        self.assertIn("example.com", {r["host"] for r in remotes})
        self.assertTrue(any(r["name"] == "remote-thing" for r in remotes))

    def test_policy_is_strict_and_denies_secrets_and_unknown_egress(self):
        server = mcp.find("github", [self.cfg])
        pol = mcp.policy_for(server, "/tmp/proj")
        self.assertEqual(pol.name, "mcp:github")
        for secret in DEFAULT_SECRET_DENY:
            self.assertIn(secret, pol.filesystem.deny)
        self.assertTrue(pol.network.deny_all_other)
        self.assertTrue(pol.strict_fs)
        self.assertTrue(pol.strict_read)
        self.assertIn("GITHUB_TOKEN", pol.env_allow)

    def test_wrap_uses_broker_shim_then_unwraps_exactly(self):
        doc, _ = mcp.parse_config(self.cfg)
        wrapped, changed = mcp.transform_config(doc, wrap=True, config=self.cfg)
        # Both the stdio server AND the remote server are now wrapped.
        self.assertEqual(changed, ["github", "remote-thing"])
        spec = wrapped["mcpServers"]["github"]
        self.assertEqual(spec["command"], "driftward")
        self.assertEqual(spec["args"][:3], ["mcp", "shim", "github"])
        self.assertIn("--definition", spec["args"])
        self.assertNotIn("--subject", spec["args"])  # never a nested Driftward run
        # The remote server becomes a stdio shim carrying its URL; the raw url key
        # is gone so it presents as a local process to the agent.
        remote = wrapped["mcpServers"]["remote-thing"]
        self.assertEqual(remote["command"], "driftward")
        self.assertIn("--url", remote["args"])
        self.assertNotIn("url", remote)

        parsed_path = self.d / "wrapped.json"
        parsed_path.write_text(json.dumps(wrapped), encoding="utf-8")
        _raw, parsed = mcp.parse_config(parsed_path)
        local = next(s for s in parsed if s.name == "github")
        self.assertEqual(local.launch_command(),
                         ["npx", "-y", "@modelcontextprotocol/server-github"])
        self.assertTrue(local.wrapped_valid)
        remote_parsed = next(s for s in parsed if s.name == "remote-thing")
        self.assertTrue(remote_parsed.remote)
        self.assertEqual(remote_parsed.url, "https://example.com/sse")
        self.assertTrue(remote_parsed.wrapped_valid)

        _, again = mcp.transform_config(wrapped, wrap=True, config=self.cfg)
        self.assertEqual(again, [])
        restored, unchanged = mcp.transform_config(wrapped, wrap=False, config=self.cfg)
        self.assertEqual(unchanged, ["github", "remote-thing"])
        self.assertEqual(restored["mcpServers"]["github"]["command"], "npx")
        self.assertEqual(restored["mcpServers"]["github"]["args"],
                         ["-y", "@modelcontextprotocol/server-github"])
        # The remote server is restored to a plain url spec.
        self.assertEqual(restored["mcpServers"]["remote-thing"]["url"], "https://example.com/sse")
        self.assertNotIn("command", restored["mcpServers"]["remote-thing"])

    def test_wrap_command_contains_exact_definition_and_source(self):
        server = mcp.find("github", [self.cfg])
        command = mcp.wrap_command(server, self.cfg)
        self.assertEqual(command[:4], ["driftward", "mcp", "shim", "github"])
        self.assertEqual(command[command.index("--config") + 1], str(self.cfg.resolve()))
        self.assertEqual(command[command.index("--definition") + 1], server.definition_sha256)
        self.assertEqual(command[command.index("--") + 1:], server.launch_command())

    def test_atomic_write_preserves_private_modes_for_config_and_backup(self):
        os.chmod(self.cfg, 0o600)
        backup = mcp.write_config_atomic(self.cfg, '{"mcpServers": {}}\n')
        self.assertEqual(stat.S_IMODE(self.cfg.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertIn("github", backup.read_text(encoding="utf-8"))

    def test_malformed_config_is_rejected(self):
        self.cfg.write_text(json.dumps({"mcpServers": {
            "bad": {"command": "node", "args": "not-a-list"}
        }}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "non-list args"):
            mcp.parse_config(self.cfg)


class McpBrokerBridge(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="driftward-mcp-broker-"))
        self.old_home = os.environ.get("DRIFTWARD_HOME")
        os.environ["DRIFTWARD_HOME"] = str(self.root / "driftward-home")
        self.source = self.root / ".mcp.json"
        self.server = mcp.McpServer(
            name="echo", command="/bin/cat", env={"PRIVATE_VALUE": "never-on-command-line"},
            source=str(self.source.resolve()), wrapped=True,
        )
        self.server.wrapped_definition = self.server.definition_sha256
        self.broker = mcp_broker.McpBroker(
            [self.server], command_factory=lambda _server, _grant: ["/bin/cat"])
        self.broker.start()

    def tearDown(self):
        self.broker.close()
        if self.old_home is None:
            os.environ.pop("DRIFTWARD_HOME", None)
        else:
            os.environ["DRIFTWARD_HOME"] = self.old_home
        shutil.rmtree(self.root, ignore_errors=True)

    def _shim(self, token: str, definition: str | None = None):
        env = dict(os.environ)
        env[mcp_broker.BROKER_ENV] = self.broker.address
        env[mcp_broker.TOKEN_ENV] = token
        code = (
            "from driftward.mcp_broker import run_shim; "
            f"raise SystemExit(run_shim('echo', {str(self.source)!r}, "
            f"{(definition or self.server.definition_sha256)!r}))"
        )
        return subprocess.run([sys.executable, "-c", code], input=b"hello broker\n",
                              capture_output=True, env=env, timeout=10)

    def test_authenticated_shim_bridges_stdio_to_registered_definition(self):
        result = self._shim(self.broker.token)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"hello broker\n")
        grants = list((Path(os.environ["DRIFTWARD_HOME"]) / "mcp-grants").glob("*.json"))
        self.assertEqual(grants, [])

    def test_broker_rejects_bad_token_and_unregistered_definition(self):
        bad_token = self._shim("wrong-token")
        self.assertNotEqual(bad_token.returncode, 0)
        self.assertIn(b"authentication failed", bad_token.stderr)
        bad_definition = self._shim(self.broker.token, "0" * 64)
        self.assertNotEqual(bad_definition.returncode, 0)
        self.assertIn(b"not registered", bad_definition.stderr)

    def test_serve_rejects_grant_outside_the_private_dir(self):
        # The inner launcher must never treat an arbitrary path as a grant, or the
        # agent could point it at any file it can name. It fails closed (exit 2).
        import io, contextlib
        from driftward.cli import main
        outside = self.root / "evil-grant.json"
        outside.write_text("{}", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["mcp", "_serve", "--grant", str(outside)])
        self.assertEqual(code, 2)
        self.assertIn("invalid MCP broker grant path", err.getvalue())

    def test_serve_rejects_a_world_readable_grant(self):
        import io, contextlib
        from driftward.cli import main
        grants = Path(os.environ["DRIFTWARD_HOME"]) / "mcp-grants"
        grants.mkdir(parents=True, exist_ok=True)
        loose = grants / "loose.json"
        loose.write_text("{}", encoding="utf-8")
        os.chmod(loose, 0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["mcp", "_serve", "--grant", str(loose)])
        self.assertEqual(code, 2)
        self.assertIn("not a private regular file", err.getvalue())


@unittest.skipUnless(sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists(),
                     "requires macOS Seatbelt")
@unittest.skipIf(os.environ.get("GITHUB_ACTIONS") or os.environ.get("DRIFTWARD_SKIP_SANDBOX_E2E"),
                 "full agent→loopback-broker→inner-sandbox chain is unreliable on hosted macOS "
                 "CI runners (VM/TCC restrictions); runs on real Macs. The broker's auth, "
                 "registration, and stdio bridging are covered on CI by McpBrokerBridge.")
class McpParentRunIntegration(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="driftward-mcp-parent-"))
        self.old_home = os.environ.get("DRIFTWARD_HOME")
        os.environ["DRIFTWARD_HOME"] = str(self.root / "driftward-home")

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("DRIFTWARD_HOME", None)
        else:
            os.environ["DRIFTWARD_HOME"] = self.old_home
        shutil.rmtree(self.root, ignore_errors=True)

    def test_outer_sandbox_launches_separate_mcp_session_with_config_env(self):
        from driftward import runner, sessions
        from driftward.policy import default_policy

        cfg = self.root / "custom-mcp.json"
        server_code = (
            "import os,sys; data=sys.stdin.buffer.readline(); "
            "sys.stdout.buffer.write(os.environ.get('DEMO_TOKEN','MISSING').encode()+b':' + data)"
        )
        doc = {"mcpServers": {"demo": {
            "command": sys.executable, "args": ["-c", server_code],
            "env": {"DEMO_TOKEN": "configured-secret"},
        }}}
        wrapped, _ = mcp.transform_config(doc, wrap=True, config=cfg)
        cfg.write_text(json.dumps(wrapped), encoding="utf-8")
        spec = wrapped["mcpServers"]["demo"]
        agent_code = (
            "import subprocess,sys; "
            f"r=subprocess.run({[spec['command'], *spec['args']]!r}, input=b'ping\\n', "
            "capture_output=True, timeout=15); "
            "raise SystemExit(0 if r.returncode == 0 and "
            "r.stdout == b'configured-secret:ping\\n' else 9)"
        )
        code = runner.run([sys.executable, "-c", agent_code], default_policy(os.getcwd()),
                          enforce=True, session="mcp-parent-e2e", quiet=True,
                          mcp_configs=[str(cfg)])
        self.assertEqual(code, 0)
        self.assertTrue(sessions.summarize("mcp-parent-e2e")["integrity_ok"])
        mcp_summaries = [sessions.summarize(sid) for sid in sessions.list_session_ids()
                         if sid != "mcp-parent-e2e"]
        self.assertEqual(len(mcp_summaries), 1)
        self.assertTrue(mcp_summaries[0]["integrity_ok"])
        self.assertEqual(mcp_summaries[0]["subject"]["kind"], "mcp")
        self.assertEqual(mcp_summaries[0]["subject"]["name"], "demo")
        self.assertIn("DEMO_TOKEN", mcp_summaries[0]["env_allowed"])


class McpBehavioralSubject(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="driftward-mcp-home-"))
        os.environ["DRIFTWARD_HOME"] = str(self.home)

    def tearDown(self):
        os.environ.pop("DRIFTWARD_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def _summary(self, subject, host):
        return {
            "id": "s1", "ts": 1, "agent": "claude", "argv": ["npx", "server-x"],
            "subject": subject, "command": "npx server-x", "cwd": "/tmp/project",
            "policy": "mcp:x", "mode": "enforce", "backend": "seatbelt", "platform": "darwin",
            "integrity_ok": True, "allowed": [{"host": host, "port": 443, "verdict": "allow"}],
            "warned": [], "blocked": [], "deep_events": [], "env_allowed": [],
        }

    def test_mcp_server_gets_its_own_principal_not_the_agent(self):
        m1 = behavior.build_manifest(self._summary(
            {"name": "github", "kind": "mcp", "definition_sha256": "a" * 64},
            "api.github.com"))
        m2 = behavior.build_manifest(self._summary(
            {"name": "search", "kind": "mcp", "definition_sha256": "b" * 64},
            "api.search.example"))
        self.assertEqual(m1["subject"]["key"], "mcp:github")
        self.assertEqual(m2["subject"]["key"], "mcp:search")
        self.assertNotEqual(m1["subject"]["key"], m2["subject"]["key"])

    def test_package_or_argument_swap_is_high_severity_identity_drift(self):
        original_server = mcp.McpServer("github", "npx", ["package-a@1"])
        changed_server = mcp.McpServer("github", "npx", ["package-b@9"])
        baseline_manifest = behavior.build_manifest(self._summary(
            mcp.subject_for(original_server), "api.github.com"))
        baseline, _ = behavior.approve(baseline_manifest)
        changed_manifest = behavior.build_manifest(self._summary(
            mcp.subject_for(changed_server), "api.github.com"))
        result = behavior.diff(changed_manifest, baseline)
        self.assertEqual(result["status"], "drift")
        finding = next(item for item in result["identity_changes"]
                       if item["field"] == "definition_sha256")
        self.assertEqual(finding["severity"], "high")


class McpRemoteBridge(unittest.TestCase):
    def test_remote_policy_locks_egress_to_only_the_declared_host(self):
        server = mcp.McpServer("hosted", None, url="https://mcp.acme.com/sse")
        pol = mcp.remote_policy_for(server, "/tmp/proj")
        self.assertEqual(pol.network.allow, ["mcp.acme.com"])
        self.assertTrue(pol.network.deny_all_other)
        self.assertTrue(pol.strict_read)
        for secret in DEFAULT_SECRET_DENY:
            self.assertIn(secret, pol.filesystem.deny)

    def test_sse_messages_parses_data_events_and_joins_multiline(self):
        from driftward import mcp_remote
        stream = [b"event: message\n", b"data: {\"a\":1}\n", b"\n",
                  b": comment\n", b"data: line1\n", b"data: line2\n", b"\n"]
        self.assertEqual(list(mcp_remote._sse_messages(iter(stream))),
                         ['{"a":1}', "line1\nline2"])

    def test_bridge_relays_stdio_over_streamable_http(self):
        import json as _json
        import subprocess as _sp
        import threading as _th
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = _json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                rid = msg.get("id")
                if rid is None:
                    self.send_response(202); self.end_headers(); return
                if msg.get("method") == "initialize":
                    body = _json.dumps({"jsonrpc": "2.0", "id": rid,
                                        "result": {"serverInfo": {"name": "mock"},
                                                   "protocolVersion": "2025-06-18"}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Mcp-Session-Id", "S1")
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body); return
                # a tool call answered over SSE, echoing the session AND the
                # negotiated protocol version the client sent back.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream"); self.end_headers()
                result = _json.dumps({"jsonrpc": "2.0", "id": rid,
                                      "result": {"session": self.headers.get("Mcp-Session-Id"),
                                                 "proto": self.headers.get("MCP-Protocol-Version")}})
                self.wfile.write(f"data: {result}\n\n".encode()); self.wfile.flush()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        _th.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            requests = "\n".join(_json.dumps(m) for m in [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
            ]) + "\n"
            proc = _sp.run(
                [sys.executable, "-c",
                 f"import sys;from driftward.mcp_remote import bridge;sys.exit(bridge('http://127.0.0.1:{port}/mcp'))"],
                input=requests.encode(), capture_output=True, timeout=30,
                env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent)})
            by_id = {}
            for line in proc.stdout.decode().splitlines():
                if line.strip():
                    obj = _json.loads(line); by_id[obj.get("id")] = obj
            self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "mock")
            # the session established at initialize was echoed on the later call
            self.assertEqual(by_id[2]["result"]["session"], "S1")
            # the negotiated protocol version is echoed on post-init requests
            self.assertEqual(by_id[2]["result"]["proto"], "2025-06-18")
        finally:
            srv.shutdown()

    def test_bridge_recovers_from_an_expired_session_with_404(self):
        import json as _json
        import subprocess as _sp
        import threading as _th
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        state = {"inits": 0}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                msg = _json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                rid = msg.get("id")
                if rid is None:
                    self.send_response(202); self.end_headers(); return
                if msg.get("method") == "initialize":
                    state["inits"] += 1
                    body = _json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Mcp-Session-Id", f"S{state['inits']}")
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body); return
                # First tool call: pretend the session expired (404). After the
                # bridge re-initializes (session S2), succeed.
                if self.headers.get("Mcp-Session-Id") == "S1":
                    self.send_response(404); self.end_headers(); return
                body = _json.dumps({"jsonrpc": "2.0", "id": rid,
                                    "result": {"ok": True, "session": self.headers.get("Mcp-Session-Id")}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        _th.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            requests = "\n".join(_json.dumps(m) for m in [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
            ]) + "\n"
            proc = _sp.run(
                [sys.executable, "-c",
                 f"import sys;from driftward.mcp_remote import bridge;sys.exit(bridge('http://127.0.0.1:{port}/mcp'))"],
                input=requests.encode(), capture_output=True, timeout=30,
                env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent)})
            by_id = {_json.loads(l)["id"]: _json.loads(l)
                     for l in proc.stdout.decode().splitlines() if l.strip()}
            # the tool call succeeded after a transparent re-initialize on S2
            self.assertTrue(by_id[2]["result"]["ok"])
            self.assertEqual(by_id[2]["result"]["session"], "S2")
            self.assertEqual(state["inits"], 2)
        finally:
            srv.shutdown()

    def test_legacy_sse_bridge_relays_over_two_endpoints(self):
        import json as _json
        import queue as _queue
        import subprocess as _sp
        import threading as _th
        import time as _time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        outbox = _queue.Queue()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream"); self.end_headers()
                self.wfile.write(b"event: endpoint\ndata: /messages?sid=1\n\n"); self.wfile.flush()
                end = _time.time() + 6
                while _time.time() < end:
                    try:
                        msg = outbox.get(timeout=0.2)
                    except _queue.Empty:
                        continue
                    self.wfile.write(f"data: {msg}\n\n".encode()); self.wfile.flush()

            def do_POST(self):
                body = _json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                self.send_response(202); self.end_headers()
                if body.get("id") is not None:
                    outbox.put(_json.dumps({"jsonrpc": "2.0", "id": body["id"],
                                            "result": {"echo": body.get("method")}}))

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        _th.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            proc = _sp.run(
                [sys.executable, "-c",
                 f"import sys;from driftward.mcp_remote import bridge;"
                 f"sys.exit(bridge('http://127.0.0.1:{port}/sse', transport='sse'))"],
                input=(_json.dumps({"jsonrpc": "2.0", "id": 7, "method": "initialize"}) + "\n").encode(),
                capture_output=True, timeout=30,
                env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent)})
            lines = [l for l in proc.stdout.decode().splitlines() if l.strip()]
            self.assertTrue(lines, proc.stderr.decode())
            self.assertEqual(_json.loads(lines[0])["result"]["echo"], "initialize")
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
