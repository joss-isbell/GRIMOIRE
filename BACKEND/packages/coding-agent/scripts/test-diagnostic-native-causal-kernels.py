"""Capture real IPython faults with the maintained probe in private namespaces.

Expected fault names are an oracle in the test runner, never classifier input.
All destructive operations require PID 1 in a newly created PID namespace and
verified owned descendants. This driver never discovers or targets a daemon.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

CASES = ("shutdown", "kill", "group-kill", "pidfd", "native-crash", "healthy-stop", "close-shell")
MAX_CAPTURE_BYTES = 8 * 1024 * 1024


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".pending")
    temporary.write_text(json.dumps(value, indent=2))
    temporary.chmod(0o600)
    temporary.replace(path)


def process_identity(pid):
    assert pid > 1
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "parent": int(fields[1]), "group": int(fields[2]),
            "startTicks": fields[19], "state": fields[0],
            "pidNamespace": os.readlink(f"/proc/{pid}/ns/pid")}


def bounded_text(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_CAPTURE_BYTES + 1)
    assert len(raw) <= MAX_CAPTURE_BYTES, f"capture exceeds bound: {path.name}"
    return raw.decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--without-probe", action="store_true")
    options = parser.parse_args()
    cases = options.cases.split(",")
    assert cases and len(cases) == len(set(cases)) and all(case in CASES for case in cases)
    assert options.uid > 0, "target UID must be unprivileged"
    package = Path(__file__).resolve().parent.parent
    probe_path = options.probe.resolve() if options.probe else package / "scripts/diagnostic-causal.bt"
    if not options.inside:
        assert sys.platform == "linux"
        options.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        # A privileged stock timeout owns the namespace command group. If this
        # outer client is interrupted, the bounded namespace lifetime remains.
        arguments = ["sudo", "-n", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "290s",
                     "/usr/bin/unshare", "--pid", "--fork", "--mount-proc",
                     "--net", "--mount", "--kill-child=SIGKILL", "/usr/bin/python3",
                     str(Path(__file__).resolve()), "--inside", "--uid", str(options.uid),
                     "--node", str(options.node.resolve()), "--python", str(options.python.absolute()),
                     "--probe", str(probe_path),
                     "--evidence", str(options.evidence.resolve()), "--cases", options.cases]
        if options.without_probe:
            arguments.append("--without-probe")
        return subprocess.call(arguments, timeout=300)
    assert os.getpid() == 1 and os.geteuid() == 0, "refusing faults outside a private PID namespace"
    assert socket.if_nameindex() == [(1, "lo")], "expected a private network namespace"
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=2)
    assert options.evidence.is_dir() and not options.evidence.is_symlink()
    probe_hash = hashlib.sha256(probe_path.read_bytes()).hexdigest()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    offsets = Path("/proc/self/timens_offsets").read_text()
    boottime = next(line.split()[1:] for line in offsets.splitlines() if line.startswith("boottime"))
    platform = {"bootId": boot_id, "clockTicksPerSecond": os.sysconf("SC_CLK_TCK"),
                "procReaderBoottimeOffsetNs": str(int(boottime[0]) * 1_000_000_000 + int(boottime[1]))}
    assert platform["procReaderBoottimeOffsetNs"] == "0", "classifier requires observed zero timens offset"
    scratch = options.evidence / "fixture"
    scratch.mkdir(mode=0o700)
    os.chown(scratch, options.uid, options.uid)

    def unprivileged():
        os.setsid()
        os.setgroups([])
        os.setgid(options.uid)
        os.setuid(options.uid)

    environment = {"PATH": f"{options.node.parent}:/usr/sbin:/usr/bin:/bin", "HOME": str(scratch),
                   "TMPDIR": str(scratch), "LANG": "C.UTF-8", "PRIME_AGENT_DIAGNOSTICS": "native",
                   "PRIME_AGENT_KERNEL_FORKSERVER": "0"}
    owner_log = open(options.evidence / "owner.log", "w")
    owner = subprocess.Popen([str(options.node), str(package / "test/fixtures/diagnostic-native-causal-owner.mjs"),
                              str(scratch), str(package.parents[1] / "node_modules/tsx/dist/loader.mjs"),
                              str(package / "test/fixtures/diagnostic-native-fault-matrix.ts"), str(options.python)],
                             cwd=scratch, env=environment, stdout=owner_log, stderr=owner_log,
                             preexec_fn=unprivileged)
    probe = None
    probe_stdout = open(options.evidence / "probe.stdout", "w")
    probe_stderr = open(options.evidence / "probe.stderr", "w")
    current = None

    def wait_for(predicate, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            assert owner.poll() is None, "owned observer exited early"
            if probe is not None:
                assert probe.poll() is None, "causal probe exited early"
            if current is not None and (current / "error.json").exists():
                raise AssertionError((current / "error.json").read_text())
            result = predicate()
            if result:
                return result
            time.sleep(0.025)
        raise AssertionError("required isolated observation timed out")

    def state(root, name, seconds=15):
        path = root / f"{name}.json"
        return wait_for(lambda: json.loads(path.read_text()) if path.exists() else None, seconds)

    def probe_lines():
        return [line[:-1] for line in bounded_text(options.evidence / "probe.stdout").splitlines(keepends=True)
                if line.startswith("{") and line.endswith("\n")]

    def probe_rows():
        return [json.loads(line) for line in probe_lines()]

    try:
        owner_ready = state(scratch, "owner")
        assert owner_ready["pid"] == owner.pid
        owner_identity = process_identity(owner.pid)
        assert owner_identity["parent"] == 1 and owner_identity["group"] == owner.pid
        if not options.without_probe:
            probe = subprocess.Popen(["/usr/bin/bpftrace", "-B", "line", str(probe_path),
                                      str(options.uid), str(owner.pid)], stdout=probe_stdout, stderr=probe_stderr)
            wait_for(lambda: any(row["event"] == "probe_ready" for row in probe_rows()), 30)
        write_json(scratch / "release.json", {"release": True})
        os.chown(scratch / "release.json", options.uid, options.uid)
        state(scratch, "released")
        if probe is not None:
            wait_for(lambda: any(row["event"] == "root_admitted" for row in probe_rows()))
        for sequence, case in enumerate(cases):
            current = scratch / f"case-{sequence}"
            current.mkdir(mode=0o700)
            os.chown(current, options.uid, options.uid)
            identifier = f"prime-native-causal-{uuid.uuid4()}"
            session = f"causal-{uuid.uuid4()}"
            beginning = len(probe_rows())
            since = time.time()
            command = scratch / f"launch-{sequence}.json"
            write_json(command, {"root": str(current), "identifier": identifier, "session": session})
            os.chown(command, options.uid, options.uid)
            producer = state(scratch, f"spawned-{sequence}")["pid"]
            ready = state(current, "ready", 25)
            assert ready["producerPid"] == producer
            producer_identity = process_identity(producer)
            kernel = process_identity(ready["kernelPid"])
            assert producer_identity["parent"] == owner.pid and kernel["parent"] == producer
            assert kernel["group"] == kernel["pid"] and kernel["group"] != owner.pid
            assert ready["kernelProcessStartId"] == f"proc:{kernel['startTicks']}"
            target = {"bootId": boot_id, "kernelInstanceId": ready["kernelInstanceId"],
                      "pid": kernel["pid"], "pidNamespace": kernel["pidNamespace"],
                      "processStartTicks": kernel["startTicks"]}
            journal = {}

            def journal_rows():
                response = subprocess.run(["/usr/bin/journalctl", "--quiet", "--no-pager", "--all",
                                           "--output=json", f"--identifier={identifier}", f"--since=@{since:.6f}"],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=3)
                assert len(response.stdout) <= MAX_CAPTURE_BYTES, "journal capture exceeds bound"
                for line in response.stdout.splitlines():
                    row = json.loads(line)
                    assert row["SYSLOG_IDENTIFIER"] == identifier and row["_BOOT_ID"] == boot_id
                    journal[row["__CURSOR"]] = line.decode()
                events = []
                for raw in journal.values():
                    try:
                        event = json.loads(json.loads(raw)["MESSAGE"])
                        if isinstance(event, dict) and event.get("schema") == "prime-agent.diagnostic.v1":
                            events.append(event)
                    except (KeyError, TypeError, json.JSONDecodeError):
                        pass  # Plain producer logs remain in the raw provider artifact.
                return events

            def observation(name, request=None):
                return any(row.get("observation") == name and (request is None or row.get("requestMsgId") == request)
                           for row in journal_rows())

            def owned_signal(number, group=False):
                live = process_identity(kernel["pid"])
                assert live["startTicks"] == kernel["startTicks"] and live["parent"] == producer
                parent = process_identity(producer)
                assert parent["startTicks"] == producer_identity["startTicks"] and parent["parent"] == owner.pid
                if group:
                    assert live["group"] == live["pid"] and live["group"] != owner.pid
                os.kill(-kernel["pid"] if group else kernel["pid"], number)

            def fixture_command(value):
                (current / "command").write_text(value)
                os.chown(current / "command", options.uid, options.uid)

            fixture_command("healthy" if case == "healthy-stop" else
                            "sleep" if case in ("kill", "group-kill", "pidfd") else case)
            request = None
            if case != "shutdown":
                request = state(current, "executing")["requestMsgId"]
                # An immediate native crash may die before its IOPub busy frame
                # reaches the observer. That missing protocol frame is evidence,
                # not a prerequisite for observing native fault generation/exit.
                if case != "native-crash":
                    wait_for(lambda: observation("iopub_busy", request))
            if case in ("kill", "group-kill"):
                owned_signal(signal.SIGTERM, case == "group-kill")
            elif case == "pidfd":
                # Open a pidfd first, then verify the retained generation and owner.
                descriptor = os.pidfd_open(kernel["pid"])
                try:
                    live = process_identity(kernel["pid"])
                    assert live["startTicks"] == kernel["startTicks"] and live["parent"] == producer
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                finally:
                    os.close(descriptor)
            if case == "healthy-stop":
                wait_for(lambda: observation("heartbeat_echo", request))
                state(current, "completed", 15)
                (current / "completed.json").unlink()
                (current / "executing.json").unlink()
                fixture_command("sleep")
                request = state(current, "executing")["requestMsgId"]
                wait_for(lambda: observation("iopub_busy", request))
                owned_signal(signal.SIGSTOP)
                wait_for(lambda: observation("heartbeat_unavailable", request), 10)
                assert process_identity(kernel["pid"])["state"] == "T"
                owned_signal(signal.SIGCONT)
            completed = state(current, "completed", 28)
            retained = None
            if case == "healthy-stop":
                fixture_command("sentinel")
                retained = state(current, "retained")
                assert retained == {"status": "ok", "stdout": str(kernel["pid"])}
                assert process_identity(kernel["pid"])["startTicks"] == kernel["startTicks"]
            if case == "close-shell":
                wait_for(lambda: observation("shell_reply_unavailable", request), 10)
                assert process_identity(kernel["pid"])["startTicks"] == kernel["startTicks"]
            assert process_identity(producer)["startTicks"] == producer_identity["startTicks"]
            if probe is not None and case not in ("healthy-stop", "close-shell"):
                def native_exit():
                    rows = probe_rows()[beginning:]
                    identities = [row for row in rows if row["event"] == "task_identity" and row["subject_pid"] == kernel["pid"]]
                    return any(row["event"] == "process_exit" and row["group_dead"] == 1 and
                               any(row["init_pid"] == identity["init_pid"] for identity in identities) for row in rows)
                wait_for(native_exit)
            # Snapshot while the producer is alive, before any test cleanup signal.
            time.sleep(0.2)
            journal_rows()
            cutoff = str(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
            lines = probe_lines()
            prelude = [line for line in lines[:beginning] if json.loads(line)["event"] == "probe_ready"]
            captured = prelude + lines[beginning:]
            destination = options.evidence / f"capture-{sequence}"
            destination.mkdir(mode=0o700)
            (destination / "journal.jsonl").write_text("\n".join(journal.values()) + "\n")
            (destination / "probe.jsonl").write_text("\n".join(captured) + "\n")
            write_json(destination / "capture.json", {"target": target, "platform": platform,
                       "identifier": identifier, "observedUntilBoottimeNs": cutoff,
                       "producerAliveAtCapture": True, "probeSha256": probe_hash,
                       "limitations": ["bounded_observation_window", "probe_async_delivery", "pre_admission_history"]})
            write_json(destination / "oracle.json", {"case": case, "completed": completed,
                       "retained": retained, "observedKernel": kernel, "observedProducer": producer_identity})
            # These captured files are private test evidence, readable by the invoking user.
            for path in destination.iterdir():
                os.chown(path, options.uid, options.uid)
            os.chown(destination, options.uid, options.uid)
            fixture_command("stop")
            # The inherited fixture can retain transport handles after disposal.
            # Cleanup is outside the capture, targets only the verified producer,
            # and is never counted as prevention or causal input for this case.
            cleanup = []
            exited_path = scratch / f"exited-{sequence}.json"
            for number in (signal.SIGTERM, signal.SIGKILL):
                deadline = time.monotonic() + 2
                while not exited_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.025)
                if exited_path.exists():
                    break
                live = process_identity(producer)
                assert live["startTicks"] == producer_identity["startTicks"] and live["parent"] == owner.pid
                os.kill(producer, number)
                cleanup.append(number)
            state(scratch, f"exited-{sequence}", 5)
            try:
                survivor = process_identity(kernel["pid"])
            except FileNotFoundError:
                survivor = None
            assert survivor is None or survivor["state"] == "Z", "fixture cleanup left its original kernel running"
            write_json(destination / "cleanup.json", {"postCaptureProducerSignals": cleanup,
                       "originalKernelRunningAfterCleanup": False})
            os.chown(destination / "cleanup.json", options.uid, options.uid)
            current = None
        stop = scratch / f"launch-{len(cases)}.json"
        write_json(stop, {"stop": True})
        os.chown(stop, options.uid, options.uid)
        assert owner.wait(timeout=5) == 0
    finally:
        if owner.poll() is None:
            os.killpg(owner.pid, signal.SIGKILL)
            owner.wait(timeout=3)
        if probe is not None:
            probe.send_signal(signal.SIGINT)
            try:
                probe.wait(timeout=10)
            except subprocess.TimeoutExpired:
                probe.kill()
                probe.wait(timeout=3)
        for handle in (owner_log, probe_stdout, probe_stderr):
            handle.close()
    assert hashlib.sha256(probe_path.read_bytes()).hexdigest() == probe_hash, "probe changed during capture"
    warnings = []
    if probe is not None:
        assert probe.returncode == 0, "probe did not exit cleanly"
        stderr = bounded_text(options.evidence / "probe.stderr")
        warnings = [line for line in stderr.splitlines() if "ERROR" in line or "WARNING" in line]
        rows = probe_rows()
        assert sum(row["event"] == "root_admitted" for row in rows) == 1
        assert not any(row["event"] == "coverage_gap" for row in rows)
    result = {"captures": len(cases), "cases": cases, "probeSha256": probe_hash,
              "probeEnabled": probe is not None, "platform": platform, "timensOffsets": offsets,
              "providerWarnings": warnings,
              "privatePidNamespace": os.readlink("/proc/self/ns/pid")}
    write_json(options.evidence / "run.json", result)
    os.chown(options.evidence / "run.json", options.uid, options.uid)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
