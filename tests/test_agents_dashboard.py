"""Tests for the agent registry, session summaries, and dashboard API."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warden import agents


class AgentRegistry(unittest.TestCase):
    def test_known_agents_present(self):
        for key in ("claude", "codex", "cursor", "copilot", "gemini", "aider"):
            self.assertIn(key, agents.REGISTRY)

    def test_policy_for_merges_baseline(self):
        a = agents.get("claude")
        pol = agents.policy_for(a, "/tmp/proj")
        # provider host + developer baseline both present
        self.assertIn("api.anthropic.com", pol.network.allow)
        self.assertIn("github.com", pol.network.allow)
        self.assertIn("registry.npmjs.org", pol.network.allow)
        # secrets still denied
        self.assertIn("~/.ssh/**", pol.filesystem.deny)
        self.assertTrue(pol.network.deny_all_other)

    def test_q_does_not_deny_aws(self):
        # Amazon Q legitimately needs AWS; it must not be denied for that agent.
        a = agents.get("q")
        self.assertNotIn("aws", a.denied_processes)

    def test_describe_all_shape(self):
        rows = agents.describe_all()
        self.assertTrue(all("installed" in r and "egress_count" in r and
                            "env_key_count" in r for r in rows))


class SessionsAndDashboard(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="warden-home-"))
        os.environ["WARDEN_HOME"] = str(self.home)
        # Import after setting WARDEN_HOME so sessions_dir points here.
        import importlib
        from warden import sessions as sess
        importlib.reload(sess)
        self.sess = sess
        from warden.recorder import Recorder
        log = self.home / "sessions" / "20260101-000000.log"
        rec = Recorder(log)
        rec.start({"argv": ["sh", "x.sh"], "agent": "claude", "policy": "demo", "enforce": True})
        rec.emit("policy.compiled", {"backend": "seatbelt"})
        rec.emit("env.scrubbed", {"count": 3, "names": ["GITHUB_TOKEN", "DB_PASSWORD", "AWS_PROFILE"]})
        rec.emit("net.connect", {"host": "example.com", "port": 443, "verdict": "allow"})
        rec.emit("net.connect", {"host": "evil.example.com", "port": 443, "verdict": "deny"})
        rec.emit("child.exit", {"code": 0, "duration_s": 0.1})
        rec.seal({"exit_code": 0})

    def tearDown(self):
        os.environ.pop("WARDEN_HOME", None)
        import shutil
        shutil.rmtree(self.home, ignore_errors=True)

    def test_summary(self):
        s = self.sess.summarize("20260101-000000")
        self.assertEqual(s["agent"], "claude")
        self.assertEqual(s["allowed_count"], 1)
        self.assertEqual(s["blocked_count"], 1)
        self.assertEqual([b["host"] for b in s["blocked"]], ["evil.example.com"])
        self.assertEqual(s["status"], "completed")
        self.assertEqual(s["backend"], "seatbelt")
        self.assertEqual(s["env_scrubbed"]["count"], 3)
        self.assertTrue(s["integrity_ok"])

    def test_overview(self):
        o = self.sess.overview()
        self.assertEqual(o["sessions"], 1)
        self.assertEqual(o["blocked_total"], 1)
        self.assertEqual(o["agents"], {"claude": 1})
        self.assertEqual(o["top_blocked"][0][0], "evil.example.com")
        self.assertEqual(o["degraded_sessions"], 0)
        self.assertEqual(o["recent"][0]["status"], "completed")

    def test_dashboard_security_headers_and_host_guard(self):
        from warden.dashserver import DashboardServer

        server = DashboardServer()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(server.url + "api/capabilities") as response:
                payload = json.load(response)
                self.assertIn("backend", payload)
                self.assertTrue(payload["behavioral_integrity"])
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")

            with urllib.request.urlopen(server.url + "api/behavior") as response:
                behavior = json.load(response)
                self.assertEqual(behavior["coverage"]["subjects"], 1)
                self.assertEqual(behavior["coverage"]["unapproved"], 1)

            with urllib.request.urlopen(server.url + "api/session/20260101-000000") as response:
                detail = json.load(response)
                self.assertEqual(detail["behavior"]["schema"], "warden.behavior/v1")
                self.assertIsNone(detail["behavior_diff"])

            spoofed = urllib.request.Request(server.url, headers={"Host": "attacker.example"})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(spoofed)
            self.assertEqual(raised.exception.code, 421)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
