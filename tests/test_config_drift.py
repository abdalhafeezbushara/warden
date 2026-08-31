"""Tests for project policy discovery, agent-egress merge, and drift detection."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import config
from driftward.policy import Policy, NetworkRules, to_yaml, default_policy


class ProjectDiscovery(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="driftward-proj-"))
        (self.root / ".git").mkdir()  # marks a project boundary
        (self.root / ".driftward.yaml").write_text(to_yaml(default_policy(str(self.root))))
        self.sub = self.root / "a" / "b"
        self.sub.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_discovery_walks_up(self):
        found = config.find_project_policy(self.sub)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, ".driftward.yaml")

    def test_stops_at_git_root(self):
        # A directory above the git root must not see the project's policy.
        parent = self.root.parent
        found = config.find_project_policy(parent)
        # parent is a temp dir without a .driftward.yaml; should be None or unrelated
        if found is not None:
            self.assertNotEqual(found.resolve(), (self.root / ".driftward.yaml").resolve())

    def test_agent_egress_merged(self):
        pol = Policy(name="strict", network=NetworkRules(allow=["intranet.local"], deny_all_other=True))
        merged = config.merge_agent_egress(pol, "claude")
        self.assertIn("intranet.local", merged.network.allow)
        self.assertIn("api.anthropic.com", merged.network.allow)  # agent host added

    def test_no_merge_without_agent(self):
        pol = Policy(name="x", network=NetworkRules(allow=["only.example"]))
        merged = config.merge_agent_egress(pol, None)
        self.assertEqual(merged.network.allow, ["only.example"])


class DriftDetection(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="driftward-drift-"))
        os.environ["DRIFTWARD_HOME"] = str(self.home)
        from driftward import sessions as sess
        importlib.reload(sess)
        self.sess = sess
        from driftward.recorder import Recorder
        self._make("20260101-000001", ["a.com"])
        self._make("20260101-000002", ["a.com"])
        self._make("20260101-000003", ["a.com", "newhost.evil"])  # drift here

    def _make(self, sid, hosts, argv=("sh", "skill.sh")):
        from driftward.recorder import Recorder
        rec = Recorder(self.home / "sessions" / f"{sid}.log")
        rec.start({"argv": list(argv), "policy": "p", "enforce": True})
        for h in hosts:
            rec.emit("net.connect", {"host": h, "verdict": "allow"})
        rec.emit("child.exit", {"code": 0, "duration_s": 0.1})
        rec.seal({"exit_code": 0})

    def tearDown(self):
        os.environ.pop("DRIFTWARD_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def test_drift_flags_new_host(self):
        findings = self.sess.drift()
        self.assertEqual(len(findings), 1)
        self.assertIn("newhost.evil", findings[0]["new_hosts"])
        self.assertEqual(findings[0]["run_index"], 3)

    def test_no_drift_when_stable(self):
        # A different command with only a single run must not be flagged.
        self._make("20260101-000004", ["single.com"], argv=("sh", "other.sh"))
        findings = [f for f in self.sess.drift() if "single.com" in f.get("new_hosts", [])]
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
