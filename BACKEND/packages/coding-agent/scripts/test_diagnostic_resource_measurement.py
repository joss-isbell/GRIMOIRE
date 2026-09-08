"""Unprivileged checks for admission observers; never starts a service or fault."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from diagnostic_resource_measurement import JournalAnalysis, ProcessObserver, stream_command, verify_disk_root


def journal_line(index, message=None):
    return json.dumps({"__CURSOR": f"cursor-{index}", "__REALTIME_TIMESTAMP": str(1000000 + index),
                       "MESSAGE": message or json.dumps({"event": "process_exit"})}).encode() + b"\n"


class MeasurementTests(unittest.TestCase):
    def test_stream_exceeds_old_capture_limit_without_retaining_rows(self):
        analysis = JournalAnalysis()
        line = journal_line(1, "x" * 65536)
        expected = hashlib.sha256()
        for _ in range(1025):
            analysis.accept(line)
            expected.update(line)
        result = analysis.finish()
        self.assertGreater(result["bytes"], 64 * 1024 ** 2)
        self.assertEqual(result["records"], 1025)
        self.assertEqual(result["sha256"], expected.hexdigest())
        self.assertEqual(len(result["types"]), 1)
        self.assertLess(len(json.dumps(result)), 4096)

    def test_fragmentation_hash_highwater_and_suppression(self):
        raw = journal_line(1) + journal_line(2, "Suppressed 123 messages from fixture.service")
        analysis = JournalAnalysis()
        for index in range(0, len(raw), 7):
            analysis.accept(raw[index:index+7])
        result = analysis.finish()
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["lastCursor"], "cursor-2")
        self.assertEqual(result["suppressedMessages"], 123)
        self.assertEqual(result["records"], 2)

    def test_oversized_and_unterminated_rows_fail_with_partial_identity(self):
        analysis = JournalAnalysis(max_line_bytes=32)
        with self.assertRaisesRegex(ValueError, "line_limit"):
            analysis.accept(b"x" * 33)
        self.assertEqual(analysis.snapshot()["bytes"], 33)
        self.assertFalse(analysis.snapshot()["complete"])
        other = JournalAnalysis()
        other.accept(journal_line(1)[:-1])
        with self.assertRaisesRegex(ValueError, "unterminated"):
            other.finish()

    def test_warning_examples_are_bounded_without_losing_counts(self):
        analysis = JournalAnalysis(max_warning_examples=2)
        for index in range(20):
            analysis.accept(journal_line(index, "Suppressed 7 messages from fixture.service"))
        result = analysis.finish()
        self.assertEqual(result["suppressedMessages"], 140)
        self.assertEqual(result["warningCount"], 20)
        self.assertEqual(len(result["warningExamples"]), 2)
        self.assertTrue(result["warningExamplesTruncated"])

    def test_command_deadline_terminates_owned_reader(self):
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            stream_command([sys.executable, "-c", "import time; time.sleep(10)"], lambda _: None, timeout=.1)

    def test_command_drains_stderr_without_unbounded_storage(self):
        result = stream_command([sys.executable, "-c", "import sys; sys.stderr.write('x'*100000); print('ok')"], lambda _: None)
        self.assertEqual(result["bytes"], 3)
        self.assertEqual(result["stderrBytes"], 100000)
        self.assertLessEqual(len(result["stderrTail"]), 4096)
        self.assertTrue(result["stderrTruncated"])

    def test_deadline_cancels_owned_descendant_holding_pipe_after_leader_exit(self):
        script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'])"
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            stream_command([sys.executable, "-c", script], lambda _: None, timeout=.2)
        self.assertLess(time.monotonic()-started, 3)

    def test_distinct_types_are_bounded(self):
        analysis = JournalAnalysis()
        with self.assertRaisesRegex(ValueError, "type_limit"):
            for index in range(129):
                analysis.accept(journal_line(index, json.dumps({"event": str(index)})))
        self.assertEqual(len(analysis.snapshot()["types"]), 128)

    def test_tmpfs_and_wrong_short_roots_rejected_before_creation(self):
        with self.assertRaisesRegex(ValueError, "root_path"):
            verify_disk_root(Path("/tmp/pad-0123456789abcdef"), "0123456789abcdef")
        root = Path("/var/tmp/0123456789abcdef")
        with patch("diagnostic_resource_measurement.command_json", return_value={"filesystems": [{"fstype": "tmpfs", "source": "tmpfs", "target": "/var/tmp"}]}):
            with self.assertRaisesRegex(ValueError, "disk_filesystem"):
                verify_disk_root(root, "0123456789abcdef")

    def test_actual_disk_preflight_is_read_only(self):
        root = Path("/var/tmp/0123456789abcdef")
        result = verify_disk_root(root, "0123456789abcdef")
        self.assertEqual(result["fileSystem"], "ext4")
        self.assertFalse(root.exists())

    def test_actual_child_identity_and_exit_status_are_generation_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            events = []
            child = subprocess.Popen([sys.executable, "-c", "input()"], stdin=subprocess.PIPE)
            observer = ProcessObserver(Path(directory), events.append)
            try:
                identity = observer.observe_pid(child.pid)
                observer.sample_memory()
                self.assertEqual(events[-1]["event"], "process_memory_sample")
                child.stdin.write(b"\n")
                child.stdin.close()
                child.wait(timeout=5)
                observer.direct_exit(child, "fixture")
                self.assertEqual(identity["pid"], child.pid)
                self.assertTrue(identity["startTicks"].isdigit())
                self.assertEqual(events[-1]["returnCode"], 0)
                self.assertEqual(events[-1]["identity"], identity)
            finally:
                observer.close()

    def test_pidfd_exit_preserves_zombie_wait_status_when_available(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            (group / "cgroup.procs").write_text("")
            events = []
            child = subprocess.Popen([sys.executable, "-c", "input(); raise SystemExit(7)"], stdin=subprocess.PIPE)
            observer = ProcessObserver(group, events.append)
            try:
                identity = observer.observe_pid(child.pid)
                child.stdin.write(b"\n")
                child.stdin.close()
                os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
                observer.scan()
                exit_event = events[-1]
                self.assertEqual(exit_event["identity"], identity)
                self.assertEqual(exit_event["evidence"], "pidfd_ready")
                self.assertEqual(os.waitstatus_to_exitcode(exit_event["waitStatus"]), 7)
                self.assertEqual(child.wait(timeout=5), 7)
            finally:
                observer.close()


if __name__ == "__main__":
    unittest.main()
