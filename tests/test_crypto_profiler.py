"""Tests for Ed25519 signing, signed receipts, policy serialization, profiler."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warden import crypto, policy as P, profiler


class Ed25519Vectors(unittest.TestCase):
    """RFC 8032 Section 7.1 test vectors — exact match proves correctness."""

    def test_vector_2(self):
        sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk = crypto.publickey(sk)
        self.assertEqual(pk.hex(), "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig = crypto.sign(bytes.fromhex("72"), sk, pk)
        self.assertEqual(sig.hex(), "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb37"
                                    "62223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2"
                                    "eaeb4302aeeb00d291612bb0c00")

    def test_vector_3(self):
        sk = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        pk = crypto.publickey(sk)
        self.assertEqual(pk.hex(), "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        sig = crypto.sign(bytes.fromhex("af82"), sk, pk)
        self.assertEqual(sig.hex(), "6291d657deec24024827e69c3abe01a30ce548a284743a445e36"
                                    "80d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e"
                                    "9716ed28dc027beceea1ec40a")

    def test_verify_rejects_tamper(self):
        sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk = crypto.publickey(sk)
        sig = crypto.sign(bytes.fromhex("72"), sk, pk)
        self.assertTrue(crypto.verify(sig, bytes.fromhex("72"), pk))
        self.assertFalse(crypto.verify(sig, bytes.fromhex("73"), pk))
        bad = bytearray(sig); bad[0] ^= 1
        self.assertFalse(crypto.verify(bytes(bad), bytes.fromhex("72"), pk))


class KeyManagement(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="warden-key-"))
        os.environ["WARDEN_HOME"] = str(self.home)

    def tearDown(self):
        os.environ.pop("WARDEN_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def test_key_is_stable_and_private(self):
        seed1, pk1 = crypto.ensure_key()
        seed2, pk2 = crypto.ensure_key()
        self.assertEqual(pk1, pk2)  # stable across calls
        mode = (self.home / "signing.key").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)  # private

    def test_sign_verify_hex(self):
        sig, pk = crypto.sign_hex(b"hello")
        self.assertTrue(crypto.verify_hex(b"hello", sig, pk))
        self.assertFalse(crypto.verify_hex(b"world", sig, pk))


class PolicySerialization(unittest.TestCase):
    def test_yaml_roundtrip(self):
        pol = P.default_policy("/tmp/proj")
        pol.strict_fs = True
        pol.strict_read = True
        pol.env_allow = ["MY_PROJECT_TOKEN"]
        pol.network.allow_private = True
        text = P.to_yaml(pol)
        back = P.loads(text)
        self.assertEqual(back.network.allow, pol.network.allow)
        self.assertEqual(back.filesystem.deny, pol.filesystem.deny)
        self.assertEqual(back.process.deny, pol.process.deny)
        self.assertEqual(back.network.deny_all_other, pol.network.deny_all_other)
        self.assertEqual(back.network.allow_private, pol.network.allow_private)
        self.assertEqual(back.strict_fs, pol.strict_fs)
        self.assertEqual(back.strict_read, pol.strict_read)
        self.assertEqual(back.env_allow, pol.env_allow)


class ProfilerClassification(unittest.TestCase):
    def test_known_vs_unknown(self):
        recognized, review = profiler.classify_hosts(
            ["api.anthropic.com", "raw.githubusercontent.com", "evil.attacker.example"])
        self.assertIn("api.anthropic.com", recognized)
        self.assertIn("raw.githubusercontent.com", recognized)
        self.assertIn("evil.attacker.example", review)

    def test_subdomain_of_known_is_recognized(self):
        recognized, review = profiler.classify_hosts(["objects.githubusercontent.com"])
        self.assertIn("objects.githubusercontent.com", recognized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
