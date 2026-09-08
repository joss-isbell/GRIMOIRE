"""Explicit Linux-only native probe check; always runs in private namespaces."""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--mode", choices=["rename", "restart"], default="rename")
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--health-seconds", type=int, default=0)
    options = parser.parse_args()
    if not options.inside:
        assert sys.platform == "linux"
        command = ["sudo", "-n", "/usr/bin/unshare", "--pid", "--fork", "--mount-proc",
                   "--net", "--mount", "--kill-child=SIGKILL", "/usr/bin/python3",
                   str(Path(__file__).resolve()), "--inside", "--uid", str(options.uid),
                   "--probe", str(options.probe.resolve()), "--evidence",
                   str(options.evidence.resolve()), "--mode", options.mode]
        if options.health_seconds:
            assert 20 <= options.health_seconds <= 23
            command.extend(["--health-seconds", str(options.health_seconds)])
        if options.baseline:
            command.append("--baseline")
        return subprocess.call(command, timeout=60)
    assert os.getpid() == 1, "refusing native checks outside a fresh PID namespace"
    assert socket.if_nameindex() == [(1, "lo")], "expected an empty private network namespace"
    options.evidence.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="causal-probe-"))
    os.chown(scratch, options.uid, -1)
    fixture = Path(__file__).resolve().parent.parent / "test/fixtures/diagnostic-causal-process.py"

    def isolate_fixture():
        os.setsid()
        os.setgid(options.uid)
        os.setuid(options.uid)

    child = subprocess.Popen(["/usr/bin/python3", str(fixture), options.mode, str(scratch)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, preexec_fn=isolate_fixture)
    initial = json.loads(child.stdout.readline())
    assert initial["ready"] == child.pid
    stdout = open(options.evidence / "probe.stdout", "w")
    stderr = open(options.evidence / "probe.stderr", "w")
    arguments = [str(child.pid)] if options.baseline else [str(options.uid), str(child.pid)]
    probe = subprocess.Popen(["/usr/bin/bpftrace", "-B", "line", str(options.probe), *arguments],
                             stdout=subprocess.PIPE, stderr=stderr, text=True)
    selection = selectors.DefaultSelector()
    selection.register(probe.stdout, selectors.EVENT_READ, "probe")
    selection.register(child.stdout, selectors.EVENT_READ, "child")
    started = False
    completed = False
    output = []
    fixture_rows = [initial]
    deadline = time.monotonic() + 35
    try:
        while time.monotonic() < deadline:
            if options.baseline and not started and "Attached" in (options.evidence / "probe.stderr").read_text():
                child.stdin.write("go\n")
                child.stdin.flush()
                started = True
            for key, _ in selection.select(0.2):
                line = key.fileobj.readline()
                if not line:
                    selection.unregister(key.fileobj)
                    continue
                if key.data == "probe":
                    stdout.write(line)
                    stdout.flush()
                    output.append(line)
                    ready = "probe_ready" in line or (options.baseline and "Attaching" in line)
                    if ready and not started:
                        time.sleep(0.1)
                        child.stdin.write("go\n")
                        child.stdin.flush()
                        started = True
                else:
                    row = json.loads(line)
                    fixture_rows.append(row)
                    if "external_signal_target" in row:
                        assert row["external_signal_target"] == child.pid
                        os.kill(child.pid, signal.SIGUSR2)
                        child.stdin.write("sent\n")
                        child.stdin.flush()
                    if row.get("complete"):
                        completed = True
            if probe.poll() is not None:
                raise AssertionError("probe exited before the fixture completed")
            if completed and child.poll() is not None:
                time.sleep(0.2)
                break
        assert started and completed and child.wait(timeout=3) == 0
        if options.health_seconds:
            time.sleep(options.health_seconds)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=3)
        probe.send_signal(signal.SIGINT)
        remaining, _ = probe.communicate(timeout=10)
        stdout.write(remaining)
        output.extend(remaining.splitlines(keepends=True))
        stdout.close()
        stderr.close()
        (options.evidence / "fixture.json").write_text(json.dumps(fixture_rows, indent=2))
        (options.evidence / "fixture.stderr").write_text(child.stderr.read())
    records = []
    for line in output:
        if line.startswith("{"):
            records.append(json.loads(line))
    names = {row["event"] for row in records}
    required = {"root_admitted", "process_fork", "process_exec", "process_exit",
                "signal_call", "signal_return", "signal_generate", "signal_deliver",
                "socket_call", "socket_return", "socket_close", "socket_shutdown", "socket_dup"}
    failures = sorted(required - names)
    result = {"mode": options.mode, "probe_exit": probe.returncode, "records": len(records),
              "event_names": sorted(names), "missing_events": failures}
    (options.evidence / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    assert not failures, "required causal observations are missing"
    assert {row["kind"] for row in records if row["event"] == "signal_call"} >= {1, 2, 3, 4}
    assert any(row["event"] == "signal_call" and row["kind"] == 1 and row["target_argument"] == -child.pid for row in records)
    assert any(row["event"] == "signal_call" and row["context_pid"] == 1 for row in records)
    assert any(row["event"] == "signal_generate" and row["signal"] == signal.SIGSEGV for row in records)
    assert any(row["event"] == "process_exit" and row["raw_exit_code"] == 7 << 8 for row in records)
    assert any(row["event"] == "process_exit" and row["raw_exit_code"] & 127 == signal.SIGSEGV for row in records)
    assert len([row for row in records if row["event"] == "socket_close"]) == (11 if options.mode == "restart" else 10)
    assert len([row for row in records if row["event"] == "root_admitted"]) == 1
    identities = [row for row in records if row["event"] == "task_identity"]
    root_identity = next(row for row in identities if row["subject_pid"] == child.pid)
    assert root_identity["pidns_inode"] == initial["pidns_inode"]
    assert int(root_identity["process_start_boottime_ns"]) * initial["clock_ticks"] // 1_000_000_000 == initial["start_ticks"]
    for first_event, thread_id in initial["prior_threads"].items():
        identity_index = next(index for index, row in enumerate(records)
                              if row["event"] == "task_identity" and row["subject_tid"] == thread_id)
        identity = records[identity_index]
        assert identity["subject_pid"] == child.pid
        assert identity["pidns_inode"] == initial["pidns_inode"]
        assert identity["process_start_boottime_ns"] == root_identity["process_start_boottime_ns"]
        expected = {"bind": ("socket_call", "init_tid"), "close": ("socket_close", "init_tid"),
                    "dup": ("socket_dup", "init_tid"), "shutdown": ("socket_shutdown", "init_tid"),
                    "signal": ("signal_call", "context_init_tid"), "deliver": ("signal_deliver", "init_tid"),
                    "fork": ("process_fork", "parent_init_tid"), "exit": ("process_exit", "init_tid")}
        event_name, id_field = expected[first_event]
        first_index = next(index for index, row in enumerate(records)
                           if row["event"] == event_name and row.get(id_field) == identity["init_tid"])
        assert identity_index < first_index
        for earlier in records[:first_index]:
            if any(earlier.get(field) == identity["init_tid"] for field in ("init_tid", "context_init_tid", "parent_init_tid", "target_init_tid")):
                assert earlier["event"] in {"task_identity", "thread_admitted"}, (first_event, earlier)
        if first_event == "deliver":
            assert not any(row["event"] == "signal_generate" and row["signal"] == signal.SIGUSR2
                           and row["target_init_tid"] == identity["init_tid"] for row in records)
        assert any(row["event"] == "process_exit" and row["init_tid"] == identity["init_tid"] for row in records)
    exec_identity = next(row for row in identities if row["subject_pid"] == initial["prior_exec_pid"]
                         and row["subject_tid"] != row["subject_pid"])
    exec_index = next(index for index, row in enumerate(records) if row["event"] == "process_exec"
                      and row["old_init_tid"] == exec_identity["init_tid"])
    assert records.index(exec_identity) < exec_index
    assert records[exec_index]["old_init_tid"] != records[exec_index]["init_tid"]
    assert records[exec_index]["preparation_observed"] == 1
    assert records[exec_index]["old_start_boottime_ns"] == exec_identity["start_boottime_ns"]
    assert records[exec_index]["start_boottime_ns"] == exec_identity["process_start_boottime_ns"]
    if options.mode == "restart":
        prior_identity = next(row for row in identities if row["subject_pid"] == initial["prior_child"])
        assert any(row["event"] == "ancestry_admitted" and row["init_tid"] == prior_identity["init_tid"] for row in records)
    assert not [row for row in records if row["event"] == "coverage_gap"]
    assert "WARNING" not in (options.evidence / "probe.stderr").read_text()
    assert "ERROR" not in (options.evidence / "probe.stderr").read_text()
    assert "WARNING" not in "".join(output) and "ERROR" not in "".join(output)
    if options.health_seconds:
        health = [row for row in records if row["event"] == "probe_health"]
        assert len(health) >= 2
        assert all(row["ancestry_limit_count"] == 0 for row in health)
    calls = {row["time_ns"] for row in records if row["event"] in {"socket_call", "socket_close", "socket_shutdown"}}
    assert all(row["call_time_ns"] in calls for row in records if row["event"] in {"socket_return", "socket_lifecycle_result"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
