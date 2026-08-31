"""Behavior manifests, explicit approvals, signed baselines, and drift gates."""

from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class BehavioralIntegrity(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="warden-behavior-"))
        os.environ["WARDEN_HOME"] = str(self.home)
        from warden import behavior
        self.behavior = behavior

    def tearDown(self):
        os.environ.pop("WARDEN_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def _summary(self, *, session="s1", hosts=("api.anthropic.com",), deep=(),
                 env=("ANTHROPIC_API_KEY",), digest="a" * 64, policy="b" * 64):
        entries = [{"host": host, "port": 443, "verdict": "allow"} for host in hosts]
        return {
            "id": session, "ts": 1, "agent": "claude", "argv": ["claude"],
            "command": "claude", "cwd": "/tmp/project", "policy": "default",
            "policy_sha256": policy, "mode": "enforce", "backend": "seatbelt",
            "platform": "darwin", "executable_sha256": digest,
            "integrity_ok": True, "allowed": entries, "warned": [], "blocked": [],
            "deep_events": list(deep), "env_allowed": list(env),
        }

    def test_manifest_is_portable_deduplicated_and_security_scoped(self):
        summary = self._summary(
            hosts=("Example.COM", "example.com"),
            deep=(
                {"kind": "proc.exec", "path": "/usr/bin/curl"},
                {"kind": "fs.open", "path": "/tmp/project/main.py"},
                {"kind": "fs.open", "path": str(Path.home() / ".ssh" / "id_ed25519")},
                {"kind": "fs.create", "path": "/tmp/output.txt"},
            ),
        )
        manifest = self.behavior.build_manifest(summary)
        self.assertEqual(manifest["schema"], "warden.behavior/v1")
        self.assertEqual(manifest["subject"]["key"], "claude")
        self.assertEqual(len(manifest["capabilities"]["network"]), 1)
        resources = {cap["resource"] for cap in manifest["capabilities"]["filesystem"]}
        self.assertIn("project/**", resources)
        self.assertIn("home/.ssh/**", resources)
        self.assertIn("temp/**", resources)
        self.assertNotIn(str(Path.home()), str(manifest["capabilities"]))

    def test_approval_is_signed_and_tampering_is_rejected(self):
        manifest = self.behavior.build_manifest(self._summary())
        baseline, path = self.behavior.approve(manifest)
        self.assertTrue(path.exists())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        ok, _ = self.behavior.verify_baseline(baseline)
        self.assertTrue(ok)

        altered = copy.deepcopy(baseline)
        altered["capabilities"]["network"].append(
            {"action": "connect", "resource": "attacker.example", "port": 443})
        ok, reason = self.behavior.verify_baseline(altered)
        self.assertFalse(ok)
        self.assertIn("digest mismatch", reason)

    def test_first_observation_is_not_a_baseline(self):
        manifest = self.behavior.build_manifest(self._summary())
        self.assertIsNone(self.behavior.baseline_for_manifest(manifest))
        state = self.behavior.dashboard_state([self._summary()])
        self.assertEqual(state["coverage"]["unapproved"], 1)
        self.assertEqual(state["baselines"], [])

    def test_diff_explains_new_capability_without_learning_it(self):
        original = self.behavior.build_manifest(self._summary())
        baseline, _ = self.behavior.approve(original)
        changed = self.behavior.build_manifest(self._summary(
            session="s2", hosts=("api.anthropic.com", "abc.ngrok.io"),
            deep=({"kind": "proc.exec", "path": "/usr/bin/ssh"},),
        ))
        result = self.behavior.diff(changed, baseline)
        self.assertEqual(result["status"], "drift")
        self.assertEqual(result["highest_severity"], "critical")
        self.assertEqual(result["new_count"], 2)
        self.assertEqual(len(baseline["capabilities"]["network"]), 1)
        self.assertTrue(any(f["category"] == "process" for f in result["findings"]))

    def test_digest_and_policy_changes_are_explicit_identity_drift(self):
        baseline, _ = self.behavior.approve(
            self.behavior.build_manifest(self._summary()))
        changed = self.behavior.build_manifest(
            self._summary(session="s2", digest="c" * 64, policy="d" * 64))
        result = self.behavior.diff(changed, baseline)
        self.assertEqual(len(result["identity_changes"]), 2)
        self.assertEqual(result["status"], "drift")

    def test_replacing_baseline_requires_force(self):
        manifest = self.behavior.build_manifest(self._summary())
        self.behavior.approve(manifest)
        with self.assertRaises(self.behavior.BehaviorError):
            self.behavior.approve(manifest)
        replaced, _ = self.behavior.approve(manifest, force=True)
        self.assertEqual(replaced["name"], "claude@project")

    def test_invalid_baseline_is_a_dashboard_finding_not_a_crash(self):
        manifest = self.behavior.build_manifest(self._summary())
        baseline, path = self.behavior.approve(manifest)
        baseline["capabilities"]["network"].append(
            {"action": "connect", "resource": "tampered.example", "port": 443})
        path.write_text(json.dumps(baseline), encoding="utf-8")
        state = self.behavior.dashboard_state([self._summary()])
        self.assertEqual(state["coverage"]["approved"], 0)
        self.assertTrue(state["findings"][0]["invalid_baseline"])
        self.assertIn("refusing untrusted baseline", state["findings"][0]["error"])

    def test_tampered_receipt_cannot_be_approved(self):
        manifest = self.behavior.build_manifest({**self._summary(), "integrity_ok": False})
        with self.assertRaises(self.behavior.BehaviorError):
            self.behavior.approve(manifest)

    def test_network_capability_dedupes_port_variants(self):
        # The same host seen with a concrete port and again port-less (a
        # net.connect + a net.request) is ONE reach, not two.
        summary = self._summary()
        summary["allowed"] = [
            {"host": "api.github.com", "port": 443, "verdict": "allow"},
            {"host": "api.github.com", "verdict": "allow"},  # no port
        ]
        manifest = self.behavior.build_manifest(summary)
        net = manifest["capabilities"]["network"]
        self.assertEqual(len(net), 1)
        self.assertEqual(net[0], {"action": "connect", "resource": "api.github.com", "port": 443})

    def test_diff_flags_a_tampered_observation(self):
        # A "stable" verdict computed from a non-intact log must be marked
        # untrustworthy, not silently trusted (anti-poisoning symmetry with approve).
        baseline, _ = self.behavior.approve(self.behavior.build_manifest(self._summary()))
        tampered = self.behavior.build_manifest(
            {**self._summary(session="s2"), "integrity_ok": False})
        result = self.behavior.diff(tampered, baseline)
        self.assertFalse(result["session_integrity_ok"])

    def test_cli_gate_fails_on_new_approved_behavior(self):
        from warden.cli import main
        from warden.recorder import Recorder

        def record(sid, hosts):
            rec = Recorder(self.home / "sessions" / f"{sid}.log")
            rec.start({"argv": ["claude"], "agent": "claude", "cwd": "/tmp/project",
                       "policy": "p", "enforce": True})
            for host in hosts:
                rec.emit("net.connect", {"host": host, "port": 443, "verdict": "allow"})
            rec.emit("child.exit", {"code": 0, "duration_s": 0.1})
            rec.seal({"exit_code": 0})

        record("s1", ["api.anthropic.com"])
        record("s2", ["api.anthropic.com", "new.example"])
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["baseline", "approve", "s1"]), 0)
            code = main(["gate", "s2", "--max-risk", "100", "--fail-on-new", "network"])
        self.assertEqual(code, 1)
        self.assertIn("new behavior capability", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
