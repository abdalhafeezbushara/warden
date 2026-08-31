"""Signed community registry: entry signing, trust gating, and adoption."""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import behavior, crypto, registry


class SignedRegistry(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="driftward-registry-"))
        self._old = os.environ.get("DRIFTWARD_HOME")
        os.environ["DRIFTWARD_HOME"] = str(self.home)

    def tearDown(self):
        if self._old is None:
            os.environ.pop("DRIFTWARD_HOME", None)
        else:
            os.environ["DRIFTWARD_HOME"] = self._old
        shutil.rmtree(self.home, ignore_errors=True)

    def _entry(self):
        subject = {"name": "github", "kind": "mcp", "definition_sha256": "d" * 64}
        # Ports match how build_manifest records real egress (https → 443).
        caps = {"network": [{"action": "connect", "resource": "api.github.com", "port": 443}],
                "process": [], "filesystem": [], "ipc": [], "credential": []}
        return registry.build_entry(subject=subject, capabilities=caps,
                                    coverage={"network": "hard"},
                                    provenance={"reviewer": "me", "source": "https://x"})

    def test_entry_is_signed_and_survives_disk_roundtrip(self):
        entry = self._entry()
        ok, _reason, signer = registry.verify_entry(entry)
        self.assertTrue(ok)
        self.assertEqual(signer, crypto.public_key_hex())
        # Loading from disk (which annotates _path) must not break verification.
        out = registry.publish(entry, self.home / "e.json")
        loaded = registry.load_entries([out])
        self.assertEqual(len(loaded), 1)
        self.assertTrue(registry.verify_entry(loaded[0])[0])

    def test_tampering_breaks_the_signature(self):
        entry = self._entry()
        bad = copy.deepcopy(entry)
        bad["capabilities"]["network"].append({"action": "connect", "resource": "evil.example"})
        ok, reason, _ = registry.verify_entry(bad)
        self.assertFalse(ok)
        self.assertIn("digest mismatch", reason)

    def test_untrusted_signer_is_rejected_until_trusted(self):
        entry = self._entry()
        ok, reason, signer = registry.entry_trust(entry)
        self.assertFalse(ok)
        self.assertIn("not trusted", reason)
        with self.assertRaises(registry.RegistryError):
            registry.install(entry)
        # Trust the signer, then it installs.
        registry.trust_key(signer, "self")
        self.assertTrue(registry.entry_trust(entry)[0])

    def test_trust_store_add_list_remove(self):
        key = "a" * 64
        registry.trust_key(key, "friend")
        self.assertTrue(registry.is_trusted(key))
        self.assertEqual(registry.trusted_keys()[0]["label"], "friend")
        self.assertTrue(registry.untrust_key(key))
        self.assertFalse(registry.is_trusted(key))

    def test_trust_rejects_a_non_hex_key(self):
        with self.assertRaises(registry.RegistryError):
            registry.trust_key("not-a-key")

    def test_install_adopts_a_verifiable_local_baseline_with_provenance(self):
        entry = self._entry()
        registry.trust_key(registry.verify_entry(entry)[2], "self")
        baseline, path = registry.install(entry)
        self.assertEqual(baseline["name"], "mcp:github")
        self.assertEqual(baseline["state"], "registry")
        self.assertEqual(baseline["provenance"]["reviewer"], "me")
        # The adopted baseline is a first-class, signature-valid behavior baseline.
        self.assertTrue(behavior.verify_baseline(baseline)[0])
        self.assertTrue(path.exists())

    def test_installed_baseline_drives_drift_across_workspaces(self):
        entry = self._entry()
        registry.trust_key(registry.verify_entry(entry)[2], "self")
        registry.install(entry)
        # A session for the same subject in ANY workspace compares to it.
        summary = {
            "id": "s1", "ts": 1, "subject": {"name": "github", "kind": "mcp"},
            "argv": ["x"], "cwd": "/tmp/some-other-project", "policy": "p",
            "mode": "enforce", "backend": "seatbelt", "platform": "darwin",
            "integrity_ok": True, "env_allowed": [], "deep_events": [], "warned": [], "blocked": [],
            "allowed": [{"host": "api.github.com", "port": 443, "verdict": "allow"},
                        {"host": "telemetry.evil.example", "port": 443, "verdict": "allow"}],
        }
        result = behavior.session_diff(summary)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "drift")
        drifted = {f["capability"]["resource"] for f in result["findings"]}
        self.assertIn("telemetry.evil.example", drifted)
        self.assertNotIn("api.github.com", drifted)  # already in the community baseline

    def test_entry_can_carry_a_signed_reviewed_policy(self):
        subject = {"name": "github", "kind": "mcp"}
        caps = {c: [] for c in registry.CATEGORIES}
        policy = {"name": "mcp:github", "network": {"allow": ["api.github.com"],
                                                    "deny_all_other": True}}
        entry = registry.build_entry(subject=subject, capabilities=caps, coverage={},
                                     provenance={"reviewer": "me"}, policy=policy)
        self.assertEqual(entry["policy"], policy)
        # The policy is inside the signed payload — tampering with it is caught.
        ok, _r, _s = registry.verify_entry(entry)
        self.assertTrue(ok)
        bad = copy.deepcopy(entry)
        bad["policy"]["network"]["allow"].append("evil.example")
        self.assertFalse(registry.verify_entry(bad)[0])

    def test_find_entry_by_name_and_kind(self):
        registry.publish(self._entry(), registry.entries_dir() / "github.json")
        self.assertIsNotNone(registry.find_entry("github", kind="mcp"))
        self.assertIsNone(registry.find_entry("github", kind="skill"))
        self.assertIsNone(registry.find_entry("nonesuch"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
