"""Tests for host classification, risk scoring, and behavioral baselines."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import intelligence as intel


class HostClassification(unittest.TestCase):
    def test_provider_hosts(self):
        self.assertEqual(intel.classify_host("api.anthropic.com")[0], "provider")
        self.assertEqual(intel.classify_host("api.openai.com")[0], "provider")

    def test_dev_infra(self):
        self.assertEqual(intel.classify_host("github.com")[0], "dev-infra")
        self.assertEqual(intel.classify_host("registry.npmjs.org")[0], "dev-infra")

    def test_exfil_infrastructure_is_suspicious(self):
        for h in ["webhook.site", "abc.ngrok.io", "x.oast.fun",
                  "attacker.burpcollaborator.net", "pastebin.com",
                  "evil.trycloudflare.com", "api.telegram.org"]:
            self.assertEqual(intel.classify_host(h)[0], "suspicious", h)

    def test_raw_ip_is_suspicious(self):
        self.assertEqual(intel.classify_host("13.37.13.37")[0], "suspicious")
        self.assertEqual(intel.classify_host("192.168.1.1")[0], "suspicious")

    def test_punycode_is_suspicious(self):
        self.assertEqual(intel.classify_host("xn--pple-43d.com")[0], "suspicious")

    def test_high_entropy_subdomain_is_suspicious(self):
        self.assertEqual(intel.classify_host("a8f3k2xq9zwp4r7m.example.com")[0], "suspicious")

    def test_unrecognized(self):
        cls, _ = intel.classify_host("some-random-site.com")
        self.assertEqual(cls, "unrecognized")

    def test_chat_webhook_hosts_suspicious(self):
        # Regression: discord/slack/telegram webhook hosts must classify suspicious.
        for h in ["discord.com", "canary.discord.com", "discordapp.com",
                  "hooks.slack.com", "api.telegram.org"]:
            self.assertEqual(intel.classify_host(h)[0], "suspicious", h)

    def test_cloudfront_hash_host_not_flagged_by_entropy(self):
        # Regression: a content-hash CDN host is 'cloud', not 'suspicious'.
        self.assertEqual(intel.classify_host("abcdef0123456789.cloudfront.net")[0], "cloud")

    def test_non_dotted_ip_encodings_suspicious(self):
        for h in ["2130706433", "0x7f000001", "[::1]"]:
            self.assertEqual(intel.classify_host(h)[0], "suspicious", h)

    def test_entropy_checks_all_labels(self):
        # A DGA label anywhere in the host, not just leftmost, is caught.
        self.assertEqual(intel.classify_host("cdn.a8f3k2xq9zwp4r7m.evil.example")[0], "suspicious")

    def test_abused_tld(self):
        cls, reason = intel.classify_host("freebie.tk")
        self.assertEqual(cls, "unrecognized")
        self.assertIn(".tk", reason)


class RiskScoring(unittest.TestCase):
    def _summary(self, allowed=(), blocked=(), warned=(), integrity=True):
        mk = lambda hs: [{"host": h} for h in hs]
        return {"allowed": mk(allowed), "blocked": mk(blocked), "warned": mk(warned),
                "integrity_ok": integrity}

    def test_clean_session_low_risk(self):
        r = intel.session_risk(self._summary(allowed=["api.anthropic.com", "github.com"]))
        self.assertEqual(r["level"], "none")
        self.assertEqual(r["score"], 0)

    def test_suspicious_host_high_risk(self):
        r = intel.session_risk(self._summary(blocked=["evil.ngrok.io"]))
        self.assertGreaterEqual(r["score"], 50)
        self.assertIn(r["level"], ("high", "critical"))

    def test_single_allowlisted_exfil_is_high(self):
        # A confirmed exfil host that was allowed (not blocked) still scores high.
        r = intel.session_risk(self._summary(allowed=["x.oast.fun"]))
        self.assertGreaterEqual(r["score"], 50)
        self.assertIn(r["level"], ("high", "critical"))

    def test_tampered_is_critical(self):
        r = intel.session_risk(self._summary(allowed=["github.com"], integrity=False))
        self.assertGreaterEqual(r["score"], 50)

    def test_warned_suspicious_worse_than_blocked(self):
        # A suspicious host LET THROUGH (monitor mode) should score high.
        r = intel.session_risk(self._summary(warned=["x.oast.fun"]))
        self.assertGreaterEqual(r["score"], 50)


class Baselines(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="driftward-base-"))
        os.environ["DRIFTWARD_HOME"] = str(self.home)

    def tearDown(self):
        os.environ.pop("DRIFTWARD_HOME", None)
        shutil.rmtree(self.home, ignore_errors=True)

    def _s(self, agent, hosts):
        return {"agent": agent, "allowed": [{"host": h} for h in hosts],
                "blocked": [], "warned": []}

    def test_build_and_compare(self):
        summaries = [self._s("claude", ["api.anthropic.com", "github.com"]),
                     self._s("claude", ["api.anthropic.com"]),
                     self._s("cursor", ["api.cursor.sh"])]
        base = intel.build_baseline("claude", summaries)
        self.assertEqual(base["sessions"], 2)
        self.assertIn("api.anthropic.com", base["hosts"])
        self.assertNotIn("api.cursor.sh", base["hosts"])  # different agent

        intel.save_baseline(base)
        loaded = intel.load_baseline("claude")
        self.assertEqual(loaded["hosts"], base["hosts"])

        # A session reaching a never-before-seen host is anomalous.
        cmp = intel.compare_to_baseline(self._s("claude", ["api.anthropic.com", "newhost.io"]), base)
        self.assertIn("newhost.io", cmp["new_hosts"])
        self.assertTrue(cmp["anomalous"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
