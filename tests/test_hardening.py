"""Regression tests for the security-hardening release (audit P0 fixes)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warden import childenv, proxy, seatbelt
from warden.policy import Policy, NetworkRules, FilesystemRules


class EnvironmentScrubbing(unittest.TestCase):
    def setUp(self):
        self._saved = dict(os.environ)
        os.environ["AWS_SECRET_ACCESS_KEY"] = "leak"
        os.environ["GITHUB_TOKEN"] = "ghp_leak"
        os.environ["MY_DB_PASSWORD"] = "leak"
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-keep"
        os.environ["PATH"] = os.environ.get("PATH", "/usr/bin")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def test_shell_secrets_are_scrubbed(self):
        env = childenv.build_child_env(Policy(name="t"), {})
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("MY_DB_PASSWORD", env)

    def test_safe_and_provider_vars_pass(self):
        env = childenv.build_child_env(Policy(name="t"), {}, agent="claude")
        self.assertIn("PATH", env)
        self.assertIn("ANTHROPIC_API_KEY", env)  # agent's own key survives
        self.assertNotIn("OPENAI_API_KEY", env)

    def test_arbitrary_commands_get_no_provider_keys(self):
        os.environ["OPENAI_API_KEY"] = "sk-openai"
        env = childenv.build_child_env(Policy(name="t"), {}, agent=None)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("OPENAI_API_KEY", env)

    def test_policy_env_allow_passes_extra(self):
        env = childenv.build_child_env(Policy(name="t", env_allow=["MY_DB_PASSWORD"]), {})
        self.assertEqual(env.get("MY_DB_PASSWORD"), "leak")

    def test_warden_control_vars_never_leak(self):
        os.environ["WARDEN_HOME"] = "/x"
        os.environ["WARDEN_MCP_TOKEN"] = "broker-secret"
        env = childenv.build_child_env(
            Policy(name="t", env_allow=["WARDEN_HOME", "WARDEN_MCP_TOKEN"]), {})
        self.assertNotIn("WARDEN_HOME", env)
        self.assertNotIn("WARDEN_MCP_TOKEN", env)

    def test_overrides_applied(self):
        env = childenv.build_child_env(Policy(name="t"), {"HTTP_PROXY": "http://127.0.0.1:9"})
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:9")

    def test_scrubbed_names_reports_secrets(self):
        names = childenv.scrubbed_names(Policy(name="t"), agent="claude")
        # Claude can legitimately use AWS credentials for Bedrock; unrelated
        # credentials must still be withheld and reported.
        self.assertIn("GITHUB_TOKEN", names)
        self.assertNotIn("PATH", names)


class NetworkHardening(unittest.TestCase):
    def _profile(self, proxy_port):
        pol = Policy(name="t", network=NetworkRules(allow=["x.com"], deny_all_other=True))
        return seatbelt.compile_profile(pol, proxy_port)

    def test_no_unix_sockets_allowed(self):
        prof = self._profile(5555)
        self.assertNotIn("unix-socket", prof)

    def test_loopback_pinned_to_proxy_port(self):
        prof = self._profile(5555)
        self.assertIn('(allow network-outbound (remote ip "localhost:5555"))', prof)
        # NOT a blanket localhost:* that would expose other local services
        self.assertNotIn('localhost:*', prof)

    def test_deny_all_other_still_denies(self):
        prof = self._profile(5555)
        self.assertIn("(deny network-outbound)", prof)

    def test_parent_mcp_broker_gets_one_additional_exact_loopback_port(self):
        pol = Policy(name="t", network=NetworkRules(deny_all_other=True))
        prof = seatbelt.compile_profile(pol, 5555, broker_port=6666)
        self.assertIn('localhost:5555', prof)
        self.assertIn('localhost:6666', prof)
        self.assertNotIn('localhost:*', prof)

    def test_proxy_rejects_private_destinations_by_default(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"):
            self.assertFalse(proxy._address_allowed(address, allow_private=False))
        self.assertTrue(proxy._address_allowed("93.184.216.34", allow_private=False))
        self.assertTrue(proxy._address_allowed("127.0.0.1", allow_private=True))


class ControlPlaneDeny(unittest.TestCase):
    def test_warden_home_denied_when_injected(self):
        # runner.run injects the warden home into deny; simulate that and confirm
        # the compiler emits a denial covering it.
        home = "/Users/x/.warden"
        pol = Policy(name="t", filesystem=FilesystemRules(deny=[home + "/**"]))
        prof = seatbelt.compile_profile(pol, 0)
        self.assertIn("/.warden", prof)


class ProfilePolicy(unittest.TestCase):
    def test_profiling_policy_confines_writes(self):
        from warden.profiler import _profiling_policy
        pol = _profiling_policy("/tmp/proj", allow_egress=False)
        self.assertTrue(pol.strict_fs)  # writes confined to the allow-list
        self.assertTrue(pol.strict_read)
        self.assertEqual(pol.network.allow, [])


class FailClosedEnforcement(unittest.TestCase):
    def test_run_does_not_start_child_when_backend_is_unavailable(self):
        from warden import backends, report, runner, sessions

        root = Path(tempfile.mkdtemp(prefix="warden-fail-closed-"))
        marker = root / "child-ran"
        old_home = os.environ.get("WARDEN_HOME")
        os.environ["WARDEN_HOME"] = str(root / "home")
        try:
            with mock.patch.object(backends, "wrap", side_effect=backends.BackendUnavailable()), \
                 mock.patch.object(backends, "unavailable_reason", return_value="test backend missing"):
                code = runner.run([sys.executable, "-c",
                                   f"from pathlib import Path; Path({str(marker)!r}).touch()"],
                                  Policy(name="t"), enforce=True, quiet=True)
            self.assertEqual(code, 125)
            self.assertFalse(marker.exists())
            log = next((root / "home" / "sessions").glob("*.log"))
            summary = sessions.summarize(log.stem)
            self.assertTrue(summary["not_started"])
            self.assertIn("requested enforcement was unavailable; child was not started",
                          summary["risk"]["reasons"])
            self.assertIn("failed closed", report.build_report(log))
        finally:
            if old_home is None:
                os.environ.pop("WARDEN_HOME", None)
            else:
                os.environ["WARDEN_HOME"] = old_home
            import shutil
            shutil.rmtree(root, ignore_errors=True)


class KeychainAccess(unittest.TestCase):
    """cursor-agent stores its login session in the macOS Keychain; its baseline
    must open exactly that path or it can't authenticate (real dogfood finding)."""

    def test_cursor_baseline_opens_keychain(self):
        from warden import agents
        from warden.policy import KEYCHAIN_GLOB, keychain_allowed
        pol = agents.policy_for(agents.get("cursor"), "/tmp/proj")
        self.assertTrue(keychain_allowed(pol))
        self.assertNotIn(KEYCHAIN_GLOB, pol.filesystem.deny)
        self.assertIn(KEYCHAIN_GLOB, pol.filesystem.read)

    def test_non_keychain_agent_still_denies_keychain(self):
        from warden import agents
        from warden.policy import KEYCHAIN_GLOB, keychain_allowed
        pol = agents.policy_for(agents.get("claude"), "/tmp/proj")
        self.assertFalse(keychain_allowed(pol))
        self.assertIn(KEYCHAIN_GLOB, pol.filesystem.deny)

    def test_default_policy_denies_keychain(self):
        from warden.policy import default_policy, keychain_allowed
        self.assertFalse(keychain_allowed(default_policy("/tmp/proj")))

    def test_apply_keychain_toggles_and_is_idempotent(self):
        from warden.policy import (Policy, FilesystemRules, KEYCHAIN_GLOB,
                                   DEFAULT_SECRET_DENY, apply_keychain, keychain_allowed)
        base = Policy(name="t", filesystem=FilesystemRules(deny=list(DEFAULT_SECRET_DENY)))
        opened = apply_keychain(apply_keychain(base, True), True)  # idempotent
        self.assertTrue(keychain_allowed(opened))
        self.assertEqual(opened.filesystem.read.count(KEYCHAIN_GLOB), 1)
        # opening then sealing leaves the other secrets intact and keychain denied
        sealed = apply_keychain(opened, False)
        self.assertFalse(keychain_allowed(sealed))
        self.assertIn("~/.ssh/**", sealed.filesystem.deny)
        self.assertNotIn(KEYCHAIN_GLOB, sealed.filesystem.read)

    def test_keychain_readable_under_strict_read(self):
        # A keychain-auth agent must still reach the keychain when --strict-read
        # confines home reads: the path is re-allowed, not left denied.
        from warden import agents, seatbelt
        pol = agents.policy_for(agents.get("cursor"), os.path.expanduser("~/proj"))
        pol.strict_read = True
        prof = seatbelt.compile_profile(pol, 0)
        self.assertIn("Keychains", prof)
        self.assertIn("(allow file-read* (subpath", prof)


class StrictReadCompilation(unittest.TestCase):
    def test_strict_read_denies_home_and_reallows_list(self):
        home = os.path.expanduser("~")
        pol = Policy(name="t", strict_read=True,
                     filesystem=FilesystemRules(read=[home + "/proj/**", "~/.gitconfig"]))
        prof = seatbelt.compile_profile(pol, 0)
        # denies the whole home for reads
        self.assertIn(f'(deny file-read* (subpath "{home}"))', prof)
        # re-allows the read allow-list under home
        self.assertIn("/proj", prof)
        self.assertIn("/.gitconfig", prof)

    def test_strict_read_off_by_default(self):
        pol = Policy(name="t", filesystem=FilesystemRules(read=["~/x/**"]))
        prof = seatbelt.compile_profile(pol, 0)
        self.assertNotIn("strict reads", prof)


if __name__ == "__main__":
    unittest.main(verbosity=2)
