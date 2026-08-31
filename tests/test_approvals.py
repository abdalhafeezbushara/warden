"""Tests for the live-approval decision engine (on_violation: ask)."""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warden import approvals
from warden.proxy import _Decision
from warden.policy import Policy, NetworkRules


class DecisionCacheTests(unittest.TestCase):
    def test_allow_once_and_caches(self):
        calls = []
        def decider(host):
            calls.append(host)
            return approvals.ALLOW_ONCE
        cache = approvals.DecisionCache(decider)
        self.assertEqual(cache.resolve("x.com"), "allow")
        self.assertEqual(cache.resolve("x.com"), "allow")   # cached
        self.assertEqual(len(calls), 1)                      # decided once
        self.assertEqual(cache.learned, set())               # once ≠ learned

    def test_allow_always_is_learned(self):
        cache = approvals.DecisionCache(lambda h: approvals.ALLOW_ALWAYS)
        self.assertEqual(cache.resolve("keep.com"), "allow")
        self.assertIn("keep.com", cache.learned)

    def test_deny(self):
        cache = approvals.DecisionCache(approvals.auto_decider(approvals.DENY))
        self.assertEqual(cache.resolve("evil.com"), "deny")

    def test_invalid_decider_result_denies(self):
        cache = approvals.DecisionCache(lambda h: "garbage")
        self.assertEqual(cache.resolve("x.com"), "deny")


class TtyDeciderTests(unittest.TestCase):
    def _decide(self, keystroke):
        d = approvals.tty_decider(stream=io.StringIO(keystroke + "\n"), out=io.StringIO())
        return d("host.com")

    def test_keys(self):
        self.assertEqual(self._decide("o"), approvals.ALLOW_ONCE)
        self.assertEqual(self._decide("a"), approvals.ALLOW_ALWAYS)
        self.assertEqual(self._decide("d"), approvals.DENY)
        self.assertEqual(self._decide(""), approvals.DENY)      # default
        self.assertEqual(self._decide("xyz"), approvals.DENY)   # unknown → deny


class AskModeVerdict(unittest.TestCase):
    def _decision(self, decision):
        pol = Policy(name="t", network=NetworkRules(allow=["ok.com"], deny=["bad.com"],
                     deny_all_other=True), on_violation="ask")
        cache = approvals.DecisionCache(lambda h: decision)
        return _Decision(pol, cache=cache)

    def test_allowlisted_never_asks(self):
        d = self._decision(approvals.DENY)  # decider would deny, but allow-list wins
        self.assertEqual(d.verdict("ok.com"), "allow")

    def test_denylisted_never_asks(self):
        d = self._decision(approvals.ALLOW_ALWAYS)  # decider would allow, but deny is firm
        self.assertEqual(d.verdict("bad.com"), "deny")

    def test_unlisted_consults_decider(self):
        self.assertEqual(self._decision(approvals.ALLOW_ONCE).verdict("new.com"), "allow")
        self.assertEqual(self._decision(approvals.DENY).verdict("new.com"), "deny")


if __name__ == "__main__":
    unittest.main(verbosity=2)
