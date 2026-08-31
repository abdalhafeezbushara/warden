"""Tests for the eslogger-based comprehensive recorder.

Synthetic events use the exact Endpoint Security field paths (process.audit_token
.pid, event.exec.target.executable.path, etc.), so the parser and subtree tracker
are verified against the real schema even though live capture (sudo + Full Disk
Access) cannot run in the test environment.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warden import deep
from warden.recorder import Recorder, read_log


def proc(pid, ppid=None, path="/bin/zsh", pidver=1):
    p = {"audit_token": {"pid": pid, "pidversion": pidver},
         "executable": {"path": path, "path_truncated": False}}
    if ppid is not None:
        p["ppid"] = ppid
        p["original_ppid"] = ppid
    return p


def exec_event(actor_pid, target_pid, path, args=None, parent_pid=None,
               actor_ver=1, target_ver=1):
    return {
        "time": "2026-08-31 04:00:00 +0000",
        "event": {"exec": {
            "target": {"audit_token": {"pid": target_pid, "pidversion": target_ver},
                       "parent_audit_token": {"pid": parent_pid or actor_pid},
                       "ppid": parent_pid or actor_pid,
                       "executable": {"path": path, "path_truncated": False}},
            "args": args or [path],
            "cwd": {"path": "/x"}}},
        "process": proc(actor_pid, pidver=actor_ver),
    }


def fork_event(parent_pid, child_pid, parent_ver=1, child_ver=1):
    return {
        "time": "2026-08-31 04:00:00 +0000",
        "event": {"fork": {"child": {"audit_token": {"pid": child_pid, "pidversion": child_ver},
                                     "ppid": parent_pid,
                                     "executable": {"path": "/bin/zsh"}}}},
        "process": proc(parent_pid, pidver=parent_ver),
    }


def exit_event(pid, pidver=1):
    return {"time": "t", "event": {"exit": {"stat": 0}}, "process": proc(pid, pidver=pidver)}


def open_event(pid, path, pidver=1):
    return {"time": "t", "event": {"open": {"fflag": 1, "file": {"path": path}}},
            "process": proc(pid, path="/bin/cat", pidver=pidver)}


def create_event(pid, dir_path, filename):
    return {"time": "t", "event": {"create": {"destination_type": 0, "destination": {
        "new_path": {"dir": {"path": dir_path}, "filename": filename, "mode": 33188}}}},
        "process": proc(pid)}


def uipc_event(pid, sock):
    return {"time": "t", "event": {"uipc_connect": {"file": {"path": sock},
            "domain": 1, "type": 1, "protocol": 0}}, "process": proc(pid)}


class ParseEvent(unittest.TestCase):
    def test_exec(self):
        e = deep.parse_event(exec_event(100, 200, "/usr/bin/curl", ["curl", "x.com"]))
        self.assertEqual(e["kind"], "proc.exec")
        self.assertEqual(e["pid"], 200)
        self.assertEqual(e["path"], "/usr/bin/curl")
        self.assertEqual(e["args"], ["curl", "x.com"])
        self.assertEqual(e["actor_pid"], 100)

    def test_fork(self):
        e = deep.parse_event(fork_event(100, 201))
        self.assertEqual(e["kind"], "proc.fork")
        self.assertEqual(e["pid"], 201)
        self.assertEqual(e["ppid"], 100)

    def test_open(self):
        e = deep.parse_event(open_event(200, "/Users/x/.ssh/id_rsa"))
        self.assertEqual(e["kind"], "fs.open")
        self.assertEqual(e["path"], "/Users/x/.ssh/id_rsa")
        self.assertEqual(e["pid"], 200)

    def test_create_new_path(self):
        e = deep.parse_event(create_event(200, "/Users/x/LaunchAgents", "evil.plist"))
        self.assertEqual(e["kind"], "fs.create")
        self.assertEqual(e["path"], "/Users/x/LaunchAgents/evil.plist")

    def test_uipc_connect(self):
        e = deep.parse_event(uipc_event(200, "/var/run/mDNSResponder"))
        self.assertEqual(e["kind"], "ipc.connect")
        self.assertEqual(e["path"], "/var/run/mDNSResponder")

    def test_unknown_event_ignored(self):
        self.assertIsNone(deep.parse_event({"event": {"stat": {}}, "process": proc(1)}))
        self.assertIsNone(deep.parse_event({"event": {}}))


class SubtreeCorrelation(unittest.TestCase):
    def test_tracks_forked_and_exec_descendants(self):
        t = deep.SubtreeTracker(root_pid=100)
        # root forks 200
        self.assertTrue(t.observe(deep.parse_event(fork_event(100, 200))))
        # 200 execs curl (still same pid subtree)
        self.assertTrue(t.observe(deep.parse_event(exec_event(200, 200, "/usr/bin/curl"))))
        # 200 forks 300
        self.assertTrue(t.observe(deep.parse_event(fork_event(200, 300))))
        # an OPEN by 300 (a descendant) is in-subtree
        self.assertTrue(t.observe(deep.parse_event(open_event(300, "/etc/hosts"))))
        # an OPEN by an UNRELATED pid 999 is NOT in-subtree
        self.assertFalse(t.observe(deep.parse_event(open_event(999, "/etc/passwd"))))

    def test_unrelated_process_excluded(self):
        t = deep.SubtreeTracker(root_pid=100)
        # exec by an unrelated tree
        self.assertFalse(t.observe(deep.parse_event(exec_event(500, 600, "/bin/ls"))))
        self.assertNotIn(600, t.pids)

    def test_pid_reuse_after_exit_is_not_attributed(self):
        # The exact review scenario: a descendant exits, an unrelated process
        # reuses its pid, and must NOT be attributed to the agent.
        t = deep.SubtreeTracker(root_pid=100)
        t.observe(deep.parse_event(fork_event(100, 200, child_ver=1)))     # child 200 v1 joins
        self.assertTrue(t.observe(deep.parse_event(open_event(200, "/x", pidver=1))))
        t.observe(deep.parse_event(exit_event(200, pidver=1)))             # 200 exits
        # Unrelated process reuses pid 200 with a NEW pidversion, reads a secret.
        stranger = deep.parse_event(open_event(200, "/Users/x/.ssh/id_rsa", pidver=7))
        self.assertFalse(t.observe(stranger))   # must be excluded

    def test_root_pid_matches_any_pidversion(self):
        # The root is alive all session; match it by bare pid regardless of ver.
        t = deep.SubtreeTracker(root_pid=100)
        self.assertTrue(t.observe(deep.parse_event(open_event(100, "/etc/hosts", pidver=3))))


class DeepRecorderIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="warden-deep-"))
        self.log = self.tmp / "s.log"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_records_only_subtree_events(self):
        rec = Recorder(self.log)
        rec.start({"argv": ["agent"]})
        dr = deep.DeepRecorder(rec, root_pid=100)
        # Build a stream: root forks 200, 200 execs curl, 200 opens a secret,
        # plus noise from unrelated pid 999.
        for raw in [
            fork_event(100, 200),
            exec_event(200, 200, "/usr/bin/curl", ["curl", "https://x"]),
            open_event(200, "/Users/x/.ssh/id_rsa"),
            open_event(999, "/Users/x/.ssh/id_rsa"),   # unrelated — must be excluded
            create_event(200, "/tmp", "dropped.sh"),
        ]:
            dr.feed_raw(raw)
        rec.seal({"exit_code": 0})

        kinds = [r["event"]["kind"] for r in read_log(self.log)]
        self.assertIn("proc.exec", kinds)
        self.assertIn("fs.open", kinds)
        self.assertIn("fs.create", kinds)
        # Exactly one fs.open (the subtree one); the unrelated 999 open excluded.
        self.assertEqual(kinds.count("fs.open"), 1)
        self.assertEqual(dr.summary()["events"]["fs.open"], 1)

    def test_feed_line_tolerates_garbage(self):
        rec = Recorder(self.log)
        rec.start({"argv": ["a"]})
        dr = deep.DeepRecorder(rec, root_pid=1)
        dr.feed_line("not json")
        dr.feed_line("")
        dr.feed_line("{}")
        self.assertEqual(dr.summary()["events"], {})


class DeepStreamBuffering(unittest.TestCase):
    """The startup-race fix: events captured BEFORE the child pid is known are
    buffered, then replayed once attach() seeds the subtree tracker."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="warden-stream-"))
        self.log = self.tmp / "s.log"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_prelaunch_events_replayed_after_attach(self):
        import json as _json
        rec = Recorder(self.log)
        rec.start({"argv": ["agent"]})
        stream = deep.DeepStream(rec, deep.DEEP_EVENTS)
        # Simulate eslogger lines arriving BEFORE the child pid is known.
        stream._ingest(_json.dumps(fork_event(100, 200)))       # root 100 forks 200
        stream._ingest(_json.dumps(exec_event(200, 200, "/usr/bin/curl")))
        stream._ingest(_json.dumps(open_event(999, "/etc/passwd")))  # unrelated
        # Now the child pid (100) becomes known.
        stream.attach(root_pid=100)
        summ = stream.finish()
        # The buffered subtree events were replayed and recorded.
        kinds = [r["event"]["kind"] for r in read_log(self.log)]
        self.assertIn("proc.fork", kinds)
        self.assertIn("proc.exec", kinds)
        self.assertGreaterEqual(summ["events"].get("proc.exec", 0), 1)

    def test_buffer_capped(self):
        rec = Recorder(self.log)
        rec.start({"argv": ["a"]})
        stream = deep.DeepStream(rec, deep.DEEP_EVENTS)
        stream.MAX_BUFFER = 5
        for _ in range(20):
            stream._ingest("{}")
        self.assertLessEqual(len(stream._buffer), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
