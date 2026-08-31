"""Tests for the Linux (bubblewrap) command generation.

These verify the generated bwrap invocation encodes the policy correctly. They
run on any OS (pure string generation); live bwrap enforcement is exercised by
CI on Linux and by `driftward doctor` there.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from driftward import linux
from driftward.policy import Policy, FilesystemRules, NetworkRules, ProcessRules


def _cmd(**kw):
    pol = Policy(
        name="t",
        filesystem=FilesystemRules(
            read=["/proj/**"], write=["/proj/**"],
            deny=["~/.ssh/**", "~/.netrc", "**/.env", "**/.env.*"]),
        network=NetworkRules(deny_all_other=True),
        process=ProcessRules(deny=["ssh"]),
        **kw,
    )
    return linux.bwrap_command(pol, ["echo", "hi"], proxy_port=8080, workdir="/proj")


class BwrapGeneration(unittest.TestCase):
    def test_allow_by_default_binds_root_readonly(self):
        cmd = _cmd()
        self.assertIn("bwrap", cmd[0])
        joined = " ".join(cmd)
        self.assertIn("--ro-bind / /", joined)

    def test_project_is_writable(self):
        cmd = _cmd()
        # --bind /proj /proj somewhere
        pairs = list(zip(cmd, cmd[1:], cmd[2:]))
        self.assertTrue(any(a == "--bind" and b == "/proj" and c == "/proj" for a, b, c in pairs))
        self.assertIn("--chdir", cmd)

    def test_secret_dir_masked_with_tmpfs(self):
        cmd = _cmd()
        # ~/.ssh/** → --tmpfs <realpath ending in /.ssh>
        idx = [i for i, x in enumerate(cmd) if x == "--tmpfs"]
        tmpfs_targets = [cmd[i + 1] for i in idx]
        self.assertTrue(any(t.endswith("/.ssh") for t in tmpfs_targets), tmpfs_targets)

    def test_secret_file_masked_with_devnull(self):
        cmd = _cmd()
        # ~/.netrc (a file) → --ro-bind-try /dev/null <.../.netrc>
        pairs = list(zip(cmd, cmd[1:], cmd[2:]))
        self.assertTrue(any(a == "--ro-bind-try" and b == "/dev/null" and c.endswith("/.netrc")
                            for a, b, c in pairs))

    def test_denied_binary_masked(self):
        cmd = _cmd()
        joined = " ".join(cmd)
        # ssh masked on PATH somewhere
        self.assertIn("/dev/null", joined)
        self.assertTrue(any(x.endswith("/ssh") for x in cmd))

    def test_proxy_env_set(self):
        cmd = _cmd()
        joined = " ".join(cmd)
        self.assertIn("HTTPS_PROXY", joined)
        self.assertIn("http://127.0.0.1:8080", joined)

    def test_network_isolation_flags(self):
        cmd = _cmd()
        self.assertIn("--die-with-parent", cmd)
        self.assertIn("--unshare-pid", cmd)

    def test_strict_fs_starts_from_empty_root(self):
        cmd = _cmd(strict_fs=True)
        joined = " ".join(cmd)
        # strict mode binds /usr read-only rather than the whole root
        self.assertIn("--ro-bind /usr /usr", joined)
        self.assertNotIn("--ro-bind / /", joined)

    def test_strict_read_hides_home(self):
        cmd = _cmd(strict_read=True)
        tmpfs_targets = [cmd[i + 1] for i, item in enumerate(cmd[:-1]) if item == "--tmpfs"]
        self.assertIn(os.path.realpath(os.path.expanduser("~")), tmpfs_targets)

    def test_command_ends_with_argv(self):
        cmd = _cmd()
        self.assertEqual(cmd[-2:], ["echo", "hi"])
        self.assertIn("--", cmd)

    def test_no_glob_paths_leak_to_bwrap(self):
        # bwrap does not glob; a path containing '*' would silently no-op and
        # leave the secret exposed. No bind/mask target may contain a wildcard.
        cmd = _cmd()
        for i, tok in enumerate(cmd):
            if tok in ("--tmpfs", "--bind", "--ro-bind", "--ro-bind-try") and i + 1 < len(cmd):
                # the path arg(s) after the flag must not contain a glob
                for arg in cmd[i + 1:i + 3]:
                    if arg.startswith("/") or arg.startswith("~"):
                        self.assertNotIn("*", arg, f"glob leaked: {arg}")

    def test_leading_glob_env_masked_in_project(self):
        # **/.env → mask /proj/.env with /dev/null (the realistic exfil case).
        cmd = _cmd()
        pairs = list(zip(cmd, cmd[1:], cmd[2:]))
        self.assertTrue(
            any(a == "--ro-bind-try" and b == "/dev/null" and c == "/proj/.env"
                for a, b, c in pairs),
            "project .env not masked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
