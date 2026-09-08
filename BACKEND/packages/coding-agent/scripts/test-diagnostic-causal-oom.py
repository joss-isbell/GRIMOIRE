"""Opt-in native OOM check, confined to one disposable memory cgroup.

The observer stays outside the limited cgroup. This is not a service installer.
"""

import argparse
import ctypes
import gzip
import hashlib
import json
import mmap
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import time
import uuid


LIMITS = {"memory.max": "67108864", "memory.swap.max": "0",
          "memory.oom.group": "1", "pids.max": "4"}


def identity(pid):
    root = Path(f"/proc/{pid}")
    return {"pid": pid, "start_ticks": int((root / "stat").read_text().rsplit(") ", 1)[1].split()[19]),
            "pidns_inode": (root / "ns/pid").stat().st_ino,
            "cgroup": (root / "cgroup").read_text().strip()}


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]


def wait_for(predicate, deadline, description):
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError(description)


def fixture():
    assert os.getpid() == 2, "fixture must be the first child in its private namespace"
    print(json.dumps({"ready": identity(os.getpid()), "clock_ticks": os.sysconf("SC_CLK_TCK")}), flush=True)
    assert sys.stdin.readline().strip() == "announce"
    assert ctypes.CDLL(None, use_errno=True).prctl(15, b"prime-agent", 0, 0, 0) == 0
    print(json.dumps({"announced": True}), flush=True)
    assert sys.stdin.readline().strip() == "allocate"
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
    signal.alarm(10)
    allocations = []
    for _ in range(128):
        block = mmap.mmap(-1, 1024 * 1024, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        for offset in range(0, len(block), 4096):
            block[offset] = 1
        allocations.append(block)
    raise AssertionError("bounded allocation completed without an OOM kill")


def snapshot(cgroup):
    return {name: (cgroup / name).read_text().strip()
            for name in [*LIMITS, "cgroup.procs", "memory.events", "memory.events.local",
                         "memory.current", "memory.peak"]}


def inside(options):
    assert os.getpid() == 1 and os.getuid() == 0
    assert socket.if_nameindex() == [(1, "lo")]
    assert options.uid > 0, "fixture must drop privileges"
    assert os.uname().machine == "x86_64"
    kernel_config = gzip.decompress(Path("/proc/config.gz").read_bytes()).decode()
    assert "CONFIG_PREEMPT_COUNT=y\n" in kernel_config
    assert "# CONFIG_PREEMPT_RT is not set\n" in kernel_config
    raw_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    clock_ticks = os.sysconf("SC_CLK_TCK")
    assert 0 < clock_ticks <= 1_000_000
    time_namespace_offsets = Path("/proc/self/timens_offsets").read_text()
    boottime = next(line.split()[1:] for line in time_namespace_offsets.splitlines()
                    if line.startswith("boottime"))
    assert len(boottime) == 2 and 0 <= int(boottime[1]) < 1_000_000_000
    boottime_offset = str(int(boottime[0]) * 1_000_000_000 + int(boottime[1]))
    assert boottime_offset == "0", "OOM proof requires the observed zero reader time-namespace offset"
    platform = {"bootId": uuid.UUID(raw_boot_id).hex, "rawBootId": raw_boot_id,
                "clockTicksPerSecond": clock_ticks, "procReaderBoottimeOffsetNs": boottime_offset,
                "timeNamespaceOffsets": time_namespace_offsets}
    assert Path("/proc/sys/vm/panic_on_oom").read_text().strip() == "0"
    assert {"memory", "pids"} <= set(Path("/sys/fs/cgroup/cgroup.subtree_control").read_text().split())
    options.evidence.mkdir(parents=True, exist_ok=False)
    cgroup = Path("/sys/fs/cgroup") / f"grimoire-causal-oom-{uuid.uuid4().hex}"
    assert cgroup.parent == Path("/sys/fs/cgroup") and not cgroup.exists()
    receipt = {"schema": 1, "probe_sha256": hashlib.sha256(options.probe.read_bytes()).hexdigest(),
               "cgroup": str(cgroup), "controller": identity(1), "limits": LIMITS,
               "allocation_cap_bytes": 128 * 1024 * 1024, "errors": [],
               "platform": platform,
               "kernel_contract": {"machine": os.uname().machine, "release": os.uname().release,
                                   "config_sha256": hashlib.sha256(kernel_config.encode()).hexdigest(),
                                   "preempt_count": True, "preempt_rt": False}}
    child = probe = None
    pidfd = None
    deadline = time.monotonic() + 45
    output = options.evidence / "probe.stdout"
    fixture_output = options.evidence / "fixture.stdout"
    created = False
    try:
        cgroup.mkdir()
        created = True
        for name, value in LIMITS.items():
            (cgroup / name).write_text(value)
        assert all((cgroup / name).read_text().strip() == value for name, value in LIMITS.items())
        assert not (cgroup / "cgroup.procs").read_text().strip()

        def drop_privileges():
            os.setgid(options.uid)
            os.setuid(options.uid)

        with fixture_output.open("w") as fixture_stdout, (options.evidence / "fixture.stderr").open("w") as fixture_stderr:
            child = subprocess.Popen(["/usr/bin/python3", str(Path(__file__).resolve()), "--fixture"],
                                     stdin=subprocess.PIPE, stdout=fixture_stdout, stderr=fixture_stderr,
                                     text=True, preexec_fn=drop_privileges)
        assert child.pid == 2
        pidfd = os.pidfd_open(child.pid)
        initial = wait_for(lambda: rows(fixture_output), deadline, "fixture readiness")[0]
        receipt["fixture_before"] = initial
        before = identity(child.pid)
        (cgroup / "cgroup.procs").write_text(str(child.pid))
        moved = identity(child.pid)
        assert moved["pidns_inode"] == receipt["controller"]["pidns_inode"]
        assert moved["start_ticks"] == before["start_ticks"]
        assert moved["cgroup"] == f"0::/{cgroup.name}"
        assert (cgroup / "cgroup.procs").read_text().split() == [str(child.pid)]
        receipt["fixture_limited"] = moved
        receipt["before"] = snapshot(cgroup)

        with output.open("w") as stdout, (options.evidence / "probe.stderr").open("w") as stderr:
            probe = subprocess.Popen(["/usr/bin/bpftrace", "-B", "line", str(options.probe),
                                      str(options.uid), str(child.pid)], stdout=stdout, stderr=stderr)
        receipt["observer"] = identity(probe.pid)
        assert receipt["observer"]["cgroup"] != moved["cgroup"]
        assert receipt["controller"]["cgroup"] != moved["cgroup"]
        def probe_ready():
            if probe.poll() is not None:
                raise RuntimeError("probe exited before readiness; allocation remains blocked")
            return any(row["event"] == "probe_ready" for row in rows(output))

        wait_for(probe_ready, deadline, "probe readiness")
        assert probe.poll() is None and child.poll() is None
        child.stdin.write("announce\n")
        child.stdin.flush()
        wait_for(lambda: any(row["event"] == "root_admitted" for row in rows(output)), deadline, "root admission")
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                             if line.startswith("MemAvailable:"))) * 1024
        receipt["mem_available_before_bytes"] = available
        assert available >= 2 * 1024 * 1024 * 1024
        assert Path("/proc/sys/vm/panic_on_oom").read_text().strip() == "0"
        assert identity(child.pid) == moved
        assert (cgroup / "cgroup.procs").read_text().split() == [str(child.pid)]
        assert all((cgroup / name).read_text().strip() == value for name, value in LIMITS.items())
        receipt["allocation_released"] = True
        child.stdin.write("allocate\n")
        child.stdin.flush()
        receipt["fixture_returncode"] = child.wait(timeout=min(20, max(1, deadline - time.monotonic())))
        wait_for(lambda: any(row["event"] == "process_exit" for row in rows(output)), deadline, "native exit observation")
        receipt["after"] = snapshot(cgroup)
    except BaseException as error:
        receipt["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        if child is not None and child.poll() is None and pidfd is not None:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            child.wait(timeout=3)
        if probe is not None and probe.poll() is None:
            probe.send_signal(signal.SIGINT)
            try:
                probe.wait(timeout=10)
            except subprocess.TimeoutExpired:
                probe.kill()
                probe.wait(timeout=3)
                receipt["errors"].append("observer exceeded graceful shutdown deadline")
        if probe is not None:
            receipt["probe_returncode"] = probe.returncode
        if pidfd is not None:
            os.close(pidfd)
        if created:
            receipt["cleanup_snapshot"] = snapshot(cgroup)
            if (cgroup / "cgroup.procs").read_text().strip():
                receipt["errors"].append("cgroup unexpectedly remains occupied; retained for inspection")
            else:
                cgroup.rmdir()
                receipt["cgroup_removed"] = True
        (options.evidence / "receipt.json").write_text(json.dumps(receipt, indent=2))
    assert not receipt["errors"], receipt["errors"]
    observed = rows(output)
    marks = [row for row in observed if row["event"] == "oom_victim"]
    kills = [row for row in observed if row["event"] == "signal_generate" and row["signal"] == signal.SIGKILL]
    exits = [row for row in observed if row["event"] == "process_exit" and row["raw_exit_code"] == signal.SIGKILL]
    proof = [row for row in kills if int(row.get("oom_call_time_ns", "0")) > 0 and row["result"] == 0]
    result = {"records": len(observed), "oom_victim_marks": len(marks), "sigkill_generations": len(kills),
              "raw_sigkill_exits": len(exits), "oom_path_signals": len(proof)}
    (options.evidence / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    assert receipt["fixture_returncode"] == -signal.SIGKILL
    assert receipt["probe_returncode"] == 0 and receipt["cgroup_removed"]
    counters = lambda text: {key: int(value) for key, value in (line.split() for line in text.splitlines())}
    assert counters(receipt["after"]["memory.events.local"])["oom_kill"] > counters(receipt["before"]["memory.events.local"])["oom_kill"]
    assert len(marks) == len(exits) == 1 and kills
    assert proof, "OOM mark and exit alone do not prove the signal came from the OOM kill path"
    assert len(proof) == 1 and proof[0]["code"] == 128 and proof[0]["result"] == 0
    enter = next(row for row in observed if row["event"] == "oom_kill_enter" and row["time_ns"] == proof[0]["oom_call_time_ns"])
    leave = next(row for row in observed if row["event"] == "oom_kill_return" and row["call_time_ns"] == enter["time_ns"])
    assert int(enter["time_ns"]) <= int(proof[0]["time_ns"]) <= int(leave["time_ns"])
    assert leave["context_valid"] == 1
    send = next(row for row in observed if row["event"] == "oom_signal_enter" and row["time_ns"] == proof[0]["oom_send_time_ns"])
    sent = next(row for row in observed if row["event"] == "oom_signal_return" and row["call_time_ns"] == send["time_ns"])
    assert sent["context_valid"] == 1 and sent["result"] == 0
    assert int(send["time_ns"]) <= int(proof[0]["time_ns"]) <= int(sent["time_ns"]) <= int(leave["time_ns"])
    assert send["oom_call_time_ns"] == sent["oom_call_time_ns"] == enter["time_ns"]
    assert send["target_init_tid"] == proof[0]["target_init_tid"]
    assert send["target_start_boottime_ns"] == proof[0]["target_start_boottime_ns"]
    assert send["preempt_count"] & 0xFF and not send["preempt_count"] & 0xFF0100
    assert proof[0]["oom_preempt_count"] & 0xFF and not proof[0]["oom_preempt_count"] & 0xFF0100
    assert enter["context_init_tid"] == proof[0]["context_init_tid"] == leave["context_init_tid"]
    assert enter["context_start_boottime_ns"] == proof[0]["context_start_boottime_ns"] == leave["context_start_boottime_ns"]
    assert proof[0]["target_init_tid"] == marks[0]["init_tid"] == exits[0]["init_tid"]
    assert proof[0]["target_start_boottime_ns"] == marks[0]["start_boottime_ns"] == exits[0]["start_boottime_ns"]
    assert not [row for row in observed if row["event"] == "coverage_gap"]
    stderr = (options.evidence / "probe.stderr").read_text()
    assert "WARNING" not in stderr and "ERROR" not in stderr and "lost" not in stderr.lower()
    assert "WARNING" not in output.read_text() and "ERROR" not in output.read_text()
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--fixture", action="store_true")
    options = parser.parse_args()
    if options.fixture:
        return fixture()
    assert options.probe and options.evidence
    if options.inside:
        return inside(options)
    assert sys.platform == "linux"
    return subprocess.call(["sudo", "-n", "/usr/bin/unshare", "--pid", "--fork", "--mount-proc",
                            "--net", "--mount", "--kill-child=SIGKILL", "/usr/bin/python3",
                            str(Path(__file__).resolve()), "--inside", "--uid", str(options.uid),
                            "--probe", str(options.probe.resolve()), "--evidence", str(options.evidence.resolve())],
                           timeout=60)


if __name__ == "__main__":
    sys.exit(main())
