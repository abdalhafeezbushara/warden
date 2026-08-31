"""Tests for the CI gate command logic (via session summaries)."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward.recorder import Recorder
from driftward import intelligence


class GateLogic(unittest.TestCase):
    """The gate decision is a thin wrapper over session_risk; verify the
    threshold logic directly against representative summaries."""

    def _summary(self, hosts_blocked=(), hosts_allowed=(), integrity=True):
        mk = lambda hs: [{"host": h} for h in hs]
        return {"allowed": mk(hosts_allowed), "blocked": mk(hosts_blocked),
                "warned": [], "integrity_ok": integrity}

    def test_clean_passes_default_threshold(self):
        r = intelligence.session_risk(self._summary(hosts_allowed=["api.anthropic.com"]))
        self.assertLessEqual(r["score"], 40)

    def test_exfil_exceeds_threshold(self):
        r = intelligence.session_risk(self._summary(hosts_blocked=["abc.ngrok.io"]))
        self.assertGreater(r["score"], 40)

    def test_tampered_always_fails(self):
        r = intelligence.session_risk(self._summary(hosts_allowed=["github.com"], integrity=False))
        self.assertGreater(r["score"], 40)


class GateEndToEnd(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="driftward-gate-"))
        os.environ["DRIFTWARD_HOME"] = str(self.home)
        import importlib
        from driftward import sessions
        importlib.reload(sessions)
        self.sessions = sessions

    def tearDown(self):
        os.environ.pop("DRIFTWARD_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def _make(self, sid, hosts, verdict="deny"):
        rec = Recorder(self.home / "sessions" / f"{sid}.log")
        rec.start({"argv": ["x"], "enforce": True})
        for h in hosts:
            rec.emit("net.connect", {"host": h, "verdict": verdict})
        rec.emit("child.exit", {"code": 0, "duration_s": 0.1})
        rec.seal({"exit_code": 0})

    def test_summary_risk_available_for_gate(self):
        self._make("s1", ["evil.ngrok.io"])
        s = self.sessions.summarize("s1")
        self.assertGreater(s["risk"]["score"], 40)
        self.assertEqual(s["blocked_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
