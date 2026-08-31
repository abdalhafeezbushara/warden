"""End-to-end integration: the whole pipeline composing together.

Exercises runner → recorder → crypto signing → sessions summary → intelligence
risk → verify, using record mode (no sandbox) so it runs on any platform.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class FullPipeline(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="warden-e2e-"))
        os.environ["WARDEN_HOME"] = str(self.home)
        import importlib
        # Reload modules that cache WARDEN_HOME-derived paths.
        from warden import runner, sessions, recorder
        importlib.reload(recorder)
        importlib.reload(runner)
        importlib.reload(sessions)
        self.runner = runner
        self.sessions = sessions

    def tearDown(self):
        os.environ.pop("WARDEN_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def test_record_run_produces_signed_verifiable_scored_session(self):
        from warden.policy import default_policy

        pol = default_policy(str(self.home))
        # A trivial command that exits cleanly and makes no network calls.
        code = self.runner.run(["/usr/bin/true"], pol, enforce=False, session="e2e-1")
        self.assertEqual(code, 0)

        # Session is summarized with all the expected fields.
        s = self.sessions.summarize("e2e-1")
        self.assertEqual(s["mode"], "observe")
        self.assertEqual(s["exit"], 0)
        self.assertIn("risk", s)
        self.assertIn("host_classes", s)
        self.assertTrue(s["integrity_ok"])

        # Clean session → low risk.
        self.assertLessEqual(s["risk"]["score"], 25)

        # The signed log verifies, and against the machine key.
        from warden.recorder import verify_log
        from warden import crypto
        log = self.home / "sessions" / "e2e-1.log"
        ok, msg = verify_log(log)
        self.assertTrue(ok, msg)
        self.assertIn("signed", msg)
        ok2, _ = verify_log(log, expect_pubkey=crypto.public_key_hex())
        self.assertTrue(ok2)

    def test_overview_and_drift_compose(self):
        from warden.policy import default_policy
        pol = default_policy(str(self.home))
        for i in range(2):
            self.runner.run(["/usr/bin/true"], pol, enforce=False, session=f"e2e-multi-{i}")
        ov = self.sessions.overview()
        self.assertEqual(ov["sessions"], 2)
        self.assertIn("drift", ov)


if __name__ == "__main__":
    unittest.main(verbosity=2)
