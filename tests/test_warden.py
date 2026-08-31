"""Driftward unit + integration tests. Stdlib unittest only.

The integration tests shell out to `sandbox-exec` and are macOS-specific; they
skip cleanly elsewhere. They assert the two claims that matter: a denied path is
actually unreadable, and a non-allow-listed host is actually unreachable — while
the allow-listed host and normal work still succeed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import policy as P
from driftward import seatbelt
from driftward.recorder import Recorder, verify_log
from driftward.proxy import host_matches


class PolicyParsing(unittest.TestCase):
    def test_mini_yaml_roundtrip(self):
        text = """
        name: t
        filesystem:
          read:
            - /a/**
            - ~/.gitconfig
          deny:
            - ~/.ssh/**
        network:
          allow: [github.com, "*.example.com"]
          deny_all_other: true
        process:
          deny:
            - ssh
        on_violation: block+receipt
        """
        pol = P.loads(text)
        self.assertEqual(pol.name, "t")
        self.assertIn("/a/**", pol.filesystem.read)
        self.assertIn("~/.gitconfig", pol.filesystem.read)
        self.assertIn("~/.ssh/**", pol.filesystem.deny)
        self.assertIn("github.com", pol.network.allow)
        self.assertIn("*.example.com", pol.network.allow)
        self.assertTrue(pol.network.deny_all_other)
        self.assertEqual(pol.process.deny, ["ssh"])

    def test_json_policy(self):
        pol = P.loads('{"name":"j","network":{"allow":["x.com"]}}')
        self.assertEqual(pol.name, "j")
        self.assertEqual(pol.network.allow, ["x.com"])

    def test_invalid_on_violation(self):
        with self.assertRaises(P.PolicyError):
            P.loads("name: x\non_violation: nonsense")

    def test_default_policy_denies_secrets(self):
        pol = P.default_policy("/tmp/proj")
        self.assertIn("~/.ssh/**", pol.filesystem.deny)
        self.assertIn("~/.aws/**", pol.filesystem.deny)
        self.assertTrue(pol.network.deny_all_other)


class HostMatching(unittest.TestCase):
    def test_exact_and_wildcard(self):
        self.assertTrue(host_matches("github.com", ["github.com"]))
        self.assertTrue(host_matches("raw.githubusercontent.com", ["*.githubusercontent.com"]))
        self.assertFalse(host_matches("evil.com", ["github.com", "*.example.com"]))

    def test_case_insensitive(self):
        self.assertTrue(host_matches("GitHub.com", ["github.com"]))


class Verdicts(unittest.TestCase):
    def _decision(self, allow, on_violation):
        from driftward.proxy import _Decision
        pol = P.Policy(name="t", network=P.NetworkRules(allow=allow, deny_all_other=True),
                       on_violation=on_violation)
        return _Decision(pol)

    def test_block_mode_denies_unlisted(self):
        d = self._decision(["example.com"], "block+receipt")
        self.assertEqual(d.verdict("example.com"), "allow")
        self.assertEqual(d.verdict("evil.com"), "deny")
        self.assertFalse(d.passes("deny"))
        self.assertTrue(d.passes("allow"))

    def test_warn_mode_lets_through_but_flags(self):
        d = self._decision(["example.com"], "warn")
        self.assertEqual(d.verdict("example.com"), "allow")
        self.assertEqual(d.verdict("evil.com"), "warn")
        self.assertTrue(d.passes("warn"))  # traffic flows

    def test_explicit_deny_beats_allow(self):
        from driftward.proxy import _Decision
        pol = P.Policy(name="t", network=P.NetworkRules(
            allow=["example.com"], deny=["example.com"], deny_all_other=True))
        self.assertEqual(_Decision(pol).verdict("example.com"), "deny")


class Canonicalization(unittest.TestCase):
    def test_tmp_symlink_resolved(self):
        # /tmp is a symlink to /private/tmp on macOS; canonical() must resolve it.
        real = seatbelt.canonical("/tmp/driftward-x/**")
        if sys.platform == "darwin":
            self.assertTrue(real.startswith("/private/tmp/driftward-x"))
        self.assertIn("driftward-x", real)

    def test_home_expansion(self):
        real = seatbelt.canonical("~/.ssh/**")
        self.assertIn("/.ssh", real)
        self.assertNotIn("~", real)


class RecorderChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="driftward-rec-"))
        self.log = self.tmp / "s.log"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chain_verifies(self):
        rec = Recorder(self.log)
        rec.start({"argv": ["x"]})
        rec.emit("net.connect", {"host": "a.com", "verdict": "allow"})
        rec.emit("net.connect", {"host": "b.com", "verdict": "deny"})
        rec.seal({"exit_code": 0})
        ok, msg = verify_log(self.log)
        self.assertTrue(ok, msg)

    def test_tamper_detected(self):
        rec = Recorder(self.log)
        rec.start({"argv": ["x"]})
        rec.emit("net.connect", {"host": "b.com", "verdict": "deny"})
        rec.seal({"exit_code": 0})
        # Flip a verdict without recomputing hashes.
        lines = self.log.read_text().splitlines()
        recs = [json.loads(l) for l in lines]
        for r in recs:
            if "event" in r and r["event"]["data"].get("verdict") == "deny":
                r["event"]["data"]["verdict"] = "allow"
        self.log.write_text("\n".join(json.dumps(r, sort_keys=True) for r in recs) + "\n")
        ok, msg = verify_log(self.log)
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("sandbox-exec"),
                     "requires macOS sandbox-exec")
class SeatbeltEnforcement(unittest.TestCase):
    def setUp(self):
        self.tmp = Path("/private/tmp/driftward-selftest")
        (self.tmp / "secrets").mkdir(parents=True, exist_ok=True)
        self.secret = self.tmp / "secrets" / "k.txt"
        self.secret.write_text("TOPSECRET")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_under(self, profile: str, argv: list[str]):
        f = Path(tempfile.mkstemp(prefix="w-", suffix=".sb")[1])
        f.write_text(profile)
        try:
            return subprocess.run(["/usr/bin/sandbox-exec", "-f", str(f), *argv],
                                  capture_output=True, text=True)
        finally:
            f.unlink()

    def test_denied_path_is_unreadable(self):
        pol = P.Policy(name="t", filesystem=P.FilesystemRules(
            deny=[str(self.tmp / "secrets") + "/**"]))
        prof = seatbelt.compile_profile(pol, 0)
        # Baseline: readable without sandbox.
        self.assertEqual(self.secret.read_text(), "TOPSECRET")
        # Under Driftward: blocked.
        res = self._run_under(prof, ["/bin/cat", str(self.secret)])
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn("TOPSECRET", res.stdout)

    def test_allowed_path_still_readable(self):
        pol = P.Policy(name="t", filesystem=P.FilesystemRules(
            deny=[str(self.tmp / "secrets") + "/**"]))
        prof = seatbelt.compile_profile(pol, 0)
        ok_file = self.tmp / "ok.txt"
        ok_file.write_text("FINE")
        res = self._run_under(prof, ["/bin/cat", str(ok_file)])
        self.assertEqual(res.returncode, 0)
        self.assertIn("FINE", res.stdout)

    def test_strict_fs_blocks_writes_outside_allowlist(self):
        proj = self.tmp / "proj"; proj.mkdir()
        pol = P.Policy(name="t", strict_fs=True, filesystem=P.FilesystemRules(
            read=[str(proj) + "/**"], write=[str(proj) + "/**"]))
        prof = seatbelt.compile_profile(pol, 0)
        # Write inside the project: allowed.
        inside = self._run_under(prof, ["/usr/bin/touch", str(proj / "a.txt")])
        self.assertEqual(inside.returncode, 0, inside.stderr)
        # Write outside: blocked.
        outside = self._run_under(prof, ["/usr/bin/touch", str(self.tmp / "escape.txt")])
        self.assertNotEqual(outside.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
