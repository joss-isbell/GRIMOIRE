"""Guard one real supervisor-producer SIGKILL while its owner and tracer survive."""

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
import re


def state(path, value, uid=None):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2))
    temporary.chmod(0o600)
    if uid is not None:
        os.chown(temporary, uid, uid)
    temporary.replace(path)


def identity(pid):
    assert pid > 1
    root = Path(f"/proc/{pid}")
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "parent": int(fields[1]), "group": int(fields[2]), "startTicks": fields[19],
            "pidNamespace": os.readlink(root / "ns/pid")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--native-identifier", required=True)
    parser.add_argument("--application-identifier", required=True)
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--inside", action="store_true")
    options = parser.parse_args()
    assert options.uid > 0
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value)
               for value in (options.native_identifier, options.application_identifier))
    if not options.inside:
        assert sys.platform == "linux"
        options.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        command = ["sudo", "-n", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "90s",
                   "/usr/bin/unshare", "--pid", "--fork", "--mount-proc", "--net", "--mount",
                   "--kill-child=SIGKILL", "/usr/bin/python3", str(Path(__file__).resolve()),
                   "--inside", "--uid", str(options.uid), "--evidence", str(options.evidence.resolve()),
                   "--node", str(options.node.resolve()), "--python", str(options.python.absolute()),
                   "--probe", str(options.probe.resolve()), "--native-identifier", options.native_identifier,
                   "--application-identifier", options.application_identifier]
        return subprocess.call(command, timeout=100)
    assert os.getpid() == 1 and os.geteuid() == 0, "refusing faults outside a private PID namespace"
    assert socket.if_nameindex() == [(1, "lo")]
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=2)
    assert options.evidence.is_dir() and not options.evidence.is_symlink()
    package = Path(__file__).resolve().parent.parent
    scratch = options.evidence / "fixture"
    scratch.mkdir(mode=0o700)
    os.chown(scratch, options.uid, options.uid)
    offsets = Path("/proc/self/timens_offsets").read_text()
    boottime = next(line.split()[1:] for line in offsets.splitlines() if line.startswith("boottime"))
    offset = str(int(boottime[0]) * 1_000_000_000 + int(boottime[1]))
    assert offset == "0"
    platform = {"bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", ""),
                "clockTicksPerSecond": os.sysconf("SC_CLK_TCK"), "procReaderBoottimeOffsetNs": offset}

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
    probe_errors = open(options.evidence / "probe-launch.stderr", "w")
    beginning = time.time()
    deadline = time.monotonic() + 80

    def wait_for(predicate, description):
        while time.monotonic() < deadline:
            if (options.evidence / "abort.json").exists():
                raise RuntimeError("integration client cancelled the owned capture")
            assert owner.poll() is None, "owned observer exited before publication"
            if probe is not None:
                assert probe.poll() is None, "causal provider exited before publication"
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        raise TimeoutError(description)

    def file(name, root=scratch):
        path = root / f"{name}.json"
        return wait_for(lambda: json.loads(path.read_text()) if path.exists() else None, name)

    def journal(identifier):
        completed = subprocess.run(["/usr/bin/journalctl", "--quiet", "--no-pager", "--all", "--output=json",
                                    f"--identifier={identifier}", f"--since=@{beginning:.6f}"],
                                   check=True, capture_output=True, timeout=3)
        assert len(completed.stdout) <= 8 * 1024 * 1024
        return [json.loads(line) for line in completed.stdout.splitlines()]

    def events(identifier):
        result = []
        for row in journal(identifier):
            try:
                result.append(json.loads(row["MESSAGE"]))
            except (KeyError, TypeError, json.JSONDecodeError):
                pass
        return result

    try:
        assert file("owner")["pid"] == owner.pid
        owner_identity = identity(owner.pid)
        assert owner_identity["parent"] == 1 and owner_identity["group"] == owner.pid
        probe = subprocess.Popen(["/usr/bin/systemd-cat", "--identifier", options.native_identifier,
                                  "--level-prefix=false", "/usr/bin/bpftrace", "-q", "-B", "line",
                                  str(options.probe), str(options.uid), str(owner.pid)],
                                 stdout=subprocess.DEVNULL, stderr=probe_errors)
        wait_for(lambda: any(event.get("event") == "probe_ready" for event in events(options.native_identifier)),
                 "native journal probe readiness")
        state(scratch / "release.json", {"release": True}, options.uid)
        file("released")
        wait_for(lambda: any(event.get("event") == "root_admitted" for event in events(options.native_identifier)),
                 "strict private root admission")
        case_root = scratch / "case"
        case_root.mkdir(mode=0o700)
        os.chown(case_root, options.uid, options.uid)
        state(scratch / "launch-0.json", {"root": str(case_root), "identifier": options.application_identifier,
                                          "session": options.application_identifier}, options.uid)
        producer_pid = file("spawned-0")["pid"]
        ready = file("ready", case_root)
        assert ready["producerPid"] == producer_pid
        producer = identity(producer_pid)
        kernel = identity(ready["kernelPid"])
        assert producer["parent"] == owner.pid and kernel["parent"] == producer_pid
        assert producer["pidNamespace"] == owner_identity["pidNamespace"] == kernel["pidNamespace"]
        wait_for(lambda: any(event.get("type") == "supervisor_started" and event.get("producerPid") == producer_pid
                             and event.get("producerStartId") == producer["startTicks"]
                             for event in events(options.application_identifier)), "captured runtime role")
        receipt = {"platform": platform, "owner": owner_identity, "producer": producer, "kernel": kernel,
                   "rootSelector": owner.pid, "probePid": probe.pid,
                   "probeSha256": hashlib.sha256(options.probe.read_bytes()).hexdigest(),
                   "nativeIdentifier": options.native_identifier, "applicationIdentifier": options.application_identifier}
        state(options.evidence / "ready.json", receipt, options.uid)
        file("release-fault", options.evidence)
        assert identity(producer_pid) == producer and identity(owner.pid) == owner_identity
        descriptor = os.pidfd_open(producer_pid)
        try:
            assert identity(producer_pid) == producer
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        finally:
            os.close(descriptor)
        exited = file("exited-0")
        assert exited["signal"] == "SIGKILL"
        wait_for(lambda: any(event.get("event") == "process_exit" and event.get("subject_pid") == producer_pid
                             and event.get("group_dead") == 1
                             for event in events(options.native_identifier)), "native producer exit")
        assert identity(owner.pid) == owner_identity
        receipt["exit"] = exited
        receipt["ownerAliveAtCapture"] = True
        receipt["probeAliveAtCapture"] = probe.poll() is None
        state(options.evidence / "captured.json", receipt, options.uid)
        file("stop", options.evidence)
        assert identity(owner.pid) == owner_identity and probe.poll() is None
        state(options.evidence / "publication-observer-alive.json", {"owner": identity(owner.pid),
                                                                     "probeAlive": True}, options.uid)
        state(scratch / "launch-1.json", {"stop": True}, options.uid)
        owner.wait(timeout=5)
        return 0
    except BaseException as error:
        state(options.evidence / "driver-error.json", {"error": f"{type(error).__name__}: {error}"}, options.uid)
        raise
    finally:
        if probe is not None and probe.poll() is None:
            probe.send_signal(signal.SIGINT)
            try:
                probe.wait(timeout=10)
            except subprocess.TimeoutExpired:
                probe.kill()
                probe.wait(timeout=3)
        if owner.poll() is None:
            owner.kill()
            owner.wait(timeout=3)
        owner_log.close()
        probe_errors.close()


if __name__ == "__main__":
    sys.exit(main())
