"""Finite ABBA admission pilot. --plan is inert; --execute needs the reviewed plan.

Only uniquely named runtime units and delegated child cgroups are changed. Native
history is retained. Installed atop, the working daemon, and global controllers
are outside this harness's ownership and are never changed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from diagnostic_resource_measurement import JournalAnalysis, ProcessObserver, stream_command, verify_disk_root

GIB = 1024 ** 3
MAX_CAPTURE = 64 * 1024 ** 2
JOURNAL_CONFIG = "[Journal]\nStorage=persistent\nSystemMaxUse=2G\nSystemKeepFree=8G\nMaxRetentionSec=3day\n"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(arguments, timeout=10):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if len(result.stdout) + len(result.stderr) > 8 * 1024 ** 2:
        raise RuntimeError("command output exceeded pilot bound")
    if result.returncode:
        raise RuntimeError(f"command failed {arguments}: {result.stderr[-8192:]}")
    return result.stdout


def write_json(path, value, config):
    path = Path(path)
    pending = path.with_suffix(path.suffix + ".pending")
    pending.write_text(json.dumps(value, indent=2))
    pending.chmod(0o600)
    os.chown(pending, config["uid"], config["gid"])
    pending.replace(path)


def unit(config):
    return f"prime-diag-admission-{config['id']}.service"


def namespace(config, index):
    return f"pad-{config['id']}-{index}"


def journal_units(name):
    return [f"systemd-journald@{name}.service", f"systemd-journald@{name}.socket",
            f"systemd-journald-varlink@{name}.socket"]


def launch_command(config, config_path):
    return ["/usr/bin/systemd-run", f"--unit={unit(config)}", "--wait", "--pipe", "--collect",
            "--property=Type=exec", "--property=Delegate=cpu io memory pids", "--property=DelegateSubgroup=observer", "--property=MemoryMax=3G",
            "--property=TasksMax=2048", "--property=RuntimeMaxSec=480", "--property=TimeoutStopSec=15",
            "--property=KillMode=control-group", "/usr/bin/unshare", "--pid", "--fork", "--mount-proc",
            "--mount", "--net", "--kill-child=SIGKILL", "/usr/bin/python3", str(Path(__file__).resolve()),
            "--inside", str(config_path)]


def plan(config, config_path):
    names = [namespace(config, index) for index, mode in enumerate(config["order"]) if mode == "B"]
    return {"schema": 1, "driverSha256": digest(__file__), "configSha256": digest(config_path),
            "measurementHelperSha256": digest(Path(__file__).with_name("diagnostic_resource_measurement.py")),
            "runtimeRoot": config["runtimeRoot"], "runtimeEvidenceRetained": True,
            "requiredRuntimeFilesystem": "Block-backed ext4 verified through findmnt, statfs magic and device identity before any unit starts, then rechecked inside the private namespace.",
            "launch": ["sudo", "-n", "/usr/bin/python3", str(Path(__file__).resolve()), "--host", str(config_path)],
            "transientUnitCommand": launch_command(config, config_path),
            "journalRuntimeFiles": [{"path": f"/run/systemd/journald@{name}.conf.d/90-admission.conf",
                                     "content": JOURNAL_CONFIG} for name in names],
            "journalStarts": [["/usr/bin/systemctl", "start", journal_units(name)[0]] for name in names],
            "journalStops": [["/usr/bin/systemctl", "stop", *journal_units(name)] for name in names],
            "journalControl": "Host controller starts both private namespaces before unshare; idle namespace services remain constant throughout all four rounds. Private PID1 never calls systemctl.",
            "delegatedCgroups": {"requiredUnitBasename": unit(config), "controllers": ["cpu", "io", "memory", "pids"],
                                 "leaves": {"workload": {"memory.max": 2 * GIB, "pids.max": 1024},
                                            "recorder": {"memory.max": 256 * 1024 ** 2, "memory.swap.max": 0, "pids.max": 64},
                                            "trace": {"memory.max": 512 * 1024 ** 2, "pids.max": 64},
                                            "atop": {"memory.max": 128 * 1024 ** 2, "pids.max": 32}}},
            "cleanup": "Stop only listed namespace services/sockets; remove only exact runtime files if bytes still match; retain all native journal files and private evidence; transient unit KillMode=control-group owns namespace descendants.",
            "installedAtop": "Full-host installed sampler is an unchanged constant baseline. A private PID-namespace sampler runs on B only at one second, measuring additional test-process capture, not all-host diagnostics-off admission.",
            "admission": "Descriptive pilot only. Four rounds do not establish a tight confidence bound or full 45-minute artifact/retention capacity."}


def read_config(path):
    config = json.loads(path.read_text())
    assert config["schema"] == 1 and re.fullmatch("[0-9a-f]{16}", config["id"])
    assert Path(config["root"]).resolve() == path.parent and path.parent.is_dir()
    assert config["runtimeRoot"] == f"/var/tmp/{config['id']}"
    assert config["uid"] > 0 and config["gid"] >= 0
    assert config["order"] == ["A", "B", "B", "A"]
    assert config["warmupSeconds"] == 15 and config["measureSeconds"] == 45
    assert config["atopIntervalSeconds"] == 1
    for artifact, expected in config["artifactHashes"].items():
        assert Path(artifact).resolve().is_relative_to(path.parent), "artifact escaped private root"
        assert digest(artifact) == expected, "frozen artifact changed"
    for key in ["cli", "workload", "extension", "service", "probe"]:
        assert config[key] in config["artifactHashes"], "launch input lacks frozen identity"
    return config


def namespace_cleanup(config):
    results = []
    for index, mode in enumerate(config["order"]):
        if mode != "B":
            continue
        name = namespace(config, index)
        paths = journal_units(name)
        stopped = subprocess.run(["/usr/bin/systemctl", "stop", *paths], capture_output=True, text=True, timeout=30)
        states = command(["/usr/bin/systemctl", "show", *paths, "-p", "Id", "-p", "ActiveState"])
        config_path = Path(f"/run/systemd/journald@{name}.conf.d/90-admission.conf")
        if config_path.exists():
            assert not config_path.is_symlink() and config_path.read_text() == JOURNAL_CONFIG, "runtime config changed; refusing cleanup"
            config_path.unlink()
            config_path.parent.rmdir()
        assert "ActiveState=active" not in states and "ActiveState=activating" not in states, "owned namespace still active"
        results.append({"namespace": name, "stopExitCode": stopped.returncode, "readback": states,
                        "runtimeConfigAbsent": not config_path.exists(), "nativeHistoryRetained": True})
    write_json(Path(config["root"]) / "cleanup.json", results, config)


def stats(path, optional=False):
    result = {}
    for name in ["memory.current", "memory.peak", "memory.events", "memory.stat", "cpu.stat", "io.stat", "pids.current", "cgroup.events"]:
        try:
            result[name] = (path / name).read_text().strip()
        except FileNotFoundError:
            if not optional:
                raise
            result[name] = {"unavailable": "controller_file_absent"}
    return result


def flat_bytes(path):
    result = 0
    if not path.exists():
        return result
    with os.scandir(path) as entries:
        for count, entry in enumerate(entries, 1):
            assert count <= 4096 and entry.is_file(follow_symlinks=False), "unknown or oversized native directory"
            value = entry.stat(follow_symlinks=False)
            result += max(value.st_size, value.st_blocks * 512)
    return result


def native_files(path):
    """Provider-owned flat history remains native; do not copy or delete it."""
    result = []
    with os.scandir(path) as entries:
        for count, entry in enumerate(entries, 1):
            assert count <= 4096 and entry.is_file(follow_symlinks=False), "unknown native history entry"
            value = entry.stat(follow_symlinks=False)
            result.append({"path": entry.path, "device": value.st_dev, "inode": value.st_ino,
                           "bytes": value.st_size, "allocatedBytes": value.st_blocks * 512,
                           "mtimeNs": value.st_mtime_ns})
    return result


def analyze_journal(name, output, config):
    analysis = JournalAnalysis()
    try:
        command_result = stream_command(["/usr/bin/journalctl", f"--namespace={name}", "--all", "--quiet", "--no-pager", "--output=json"], analysis.accept)
        analysis.result["command"] = command_result
        return analysis.finish()
    finally:
        # On parser, size or deadline failure this is explicitly an incomplete
        # prefix. Native journal files remain the complete available artifact.
        write_json(output, analysis.snapshot(), config)


def observe_host_launch(config, config_path, output):
    """Read only the exact test recorder cgroups from the host PID namespace."""
    root = Path(config["root"])
    base = Path("/sys/fs/cgroup/system.slice") / unit(config)
    assert base.resolve() == base and base.name == unit(config), "foreign host cgroup"
    observers = {}
    first_oom_ms = None
    child = subprocess.Popen(launch_command(config, config_path), stdout=output, stderr=output)
    deadline = time.monotonic() + 520
    last_sample = 0
    with open(root / "host-process-evidence.jsonl", "w") as evidence:
        def emit(event):
            evidence.write(json.dumps(event) + "\n")
            evidence.flush()
        emit({"event": "coverage", "observerPidNamespace": os.readlink("/proc/self/ns/pid"),
              "limitations": ["polling_may_miss_short_lived_processes", "non_child_exit_status_may_be_unavailable"]})
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("host_controller_deadline")
                sample_now = time.monotonic() - last_sample >= 1
                for index, mode in enumerate(config["order"]):
                    if mode != "B":
                        continue
                    group = base / f"round-{index}" / "recorder"
                    if not group.exists():
                        continue
                    observer = observers.setdefault(index, None)
                    if observer is None:
                        observer = observers[index] = ProcessObserver(group, emit)
                    try:
                        observer.scan()
                    except FileNotFoundError:
                        emit({"event": "cgroup_observation_gap", "group": str(group), "reason": "removed_during_process_scan"})
                        continue
                    if sample_now:
                        observer.sample_memory()
                        try:
                            values = stats(group)
                        except FileNotFoundError:
                            emit({"event": "cgroup_observation_gap", "group": str(group), "reason": "removed_during_snapshot"})
                            continue
                        observed = int(time.time() * 1000)
                        emit({"event": "cgroup_sample", "group": str(group), "observedAtMs": observed, "values": values})
                        counts = dict(line.split() for line in values["memory.events"].splitlines())
                        if int(counts.get("oom_kill", 0)) and first_oom_ms is None:
                            first_oom_ms = observed
                if sample_now:
                    last_sample = time.monotonic()
                time.sleep(.1)
            return child.returncode
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            for observer in observers.values():
                if observer is not None:
                    try:
                        observer.scan()
                    finally:
                        observer.close()
            if first_oom_ms is not None:
                metadata = {"firstObservedOomMs": first_oom_ms, "complete": False}
                try:
                    with open(root / "host-kernel-oom.jsonl", "wb") as raw:
                        result = stream_command(["/usr/bin/journalctl", "-k", "--since", f"@{first_oom_ms//1000-3}",
                                                 "--until", f"@{first_oom_ms//1000+2}", "--no-pager", "--output=json"],
                                                raw.write, timeout=10, max_bytes=2 * 1024 ** 2)
                    metadata.update({"complete": True, "command": result})
                except Exception as error:
                    metadata["limitation"] = str(error)
                write_json(root / "host-kernel-oom-coverage.json", metadata, config)


def db_counts(path):
    if not path.exists():
        return None
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.1) as connection:
        connection.row_factory = sqlite3.Row
        result = dict(connection.execute("SELECT * FROM counts WHERE id=1").fetchone())
        result["journalOccurrences"] = connection.execute("SELECT COUNT(*) FROM occurrences WHERE source='journal:service'").fetchone()[0]
        return result


def inside(config):
    assert os.getpid() == 1 and os.geteuid() == 0, "expected private privileged PID1"
    assert socket.if_nameindex() == [(1, "lo")], "expected isolated network"
    command(["/usr/sbin/ip", "link", "set", "lo", "up"])
    root = Path(config["runtimeRoot"])
    host_metadata = json.loads((Path(config["root"]) / "host-metadata.json").read_text())
    before_filesystem = verify_disk_root(root, config["id"])
    assert before_filesystem["device"] == host_metadata["filesystem"]["device"], "runtime filesystem changed"
    root.mkdir(mode=0o700)
    os.chown(root, config["uid"], config["gid"])
    filesystem = verify_disk_root(root, config["id"], existing=True)
    assert filesystem["device"] == before_filesystem["device"], "runtime filesystem changed during creation"
    relative = Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]
    observer = Path("/sys/fs/cgroup") / relative.lstrip("/")
    base = observer.parent
    assert observer.name == "observer" and base.resolve() == base and base.name == unit(config), "refusing foreign cgroup"
    controllers = {"cpu", "io", "memory", "pids"}
    assert controllers <= set((base / "cgroup.controllers").read_text().split()), "required controllers not delegated"
    (base / "cgroup.subtree_control").write_text("+cpu +io +memory +pids")
    machine = Path("/etc/machine-id").read_text().strip()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    results = []
    installed_atop = host_metadata["installedAtop"]
    preflight = []
    for name in host_metadata["journalCgroups"]:
        command(["/usr/bin/journalctl", f"--namespace={name}", "--sync"])
        analysis = analyze_journal(name, root / f"preflight-{name}.json", config)
        with open(root / f"preflight-{name}.export", "wb") as output:
            exported = stream_command(["/usr/bin/journalctl", f"--namespace={name}", "--all", "--quiet", "--no-pager", "--output=export"], output.write, timeout=10, max_bytes=MAX_CAPTURE)
        preflight.append({"namespace": name, "syncSucceeded": True, "jsonReadCount": analysis["records"], "nativeExport": exported})
    write_json(root / "preflight.json", preflight, config)
    write_json(root / "platform.json", {"bootId": boot, "clockTicks": os.sysconf("SC_CLK_TCK"),
               "timensOffsets": Path("/proc/self/timens_offsets").read_text(), "kernelRelease": os.uname().release,
               "installedAtopUnchangedBaseline": installed_atop, "delegatedRoot": str(base), "filesystem": filesystem}, config)
    for index, mode in enumerate(config["order"]):
        round_root = root / f"round-{index}"
        round_root.mkdir(mode=0o700)
        os.chown(round_root, config["uid"], config["gid"])
        cg = base / f"round-{index}"
        cg.mkdir()
        (cg / "cgroup.subtree_control").write_text("+cpu +io +memory +pids")
        groups = {}
        for name, limits in plan(config, Path(config["root"]) / "config.json")["delegatedCgroups"]["leaves"].items():
            path = cg / name
            path.mkdir()
            for key, value in limits.items():
                (path / key).write_text(str(value))
            groups[name] = path
        children = []
        logs = []
        observations = []
        admission_failures = []
        direct_identities = {}
        recorded_exits = set()
        process_log = open(round_root / "process-evidence.jsonl", "w")
        def emit_process(event):
            process_log.write(json.dumps(event) + "\n")
            process_log.flush()
        process_observer = ProcessObserver(groups["recorder"], emit_process)
        emit_process({"event": "coverage", "limitations": ["polling_cannot_observe_processes_born_and_reaped_between_scans", "non_child_exit_status_may_be_unavailable"], "observerPidNamespace": os.readlink("/proc/self/ns/pid")})
        def capture_exits():
            process_observer.scan()
            for child in children:
                if child.poll() is not None and child not in recorded_exits:
                    recorded_exits.add(child)
                    process_observer.direct_exit(child, direct_identities[child][0], direct_identities[child][1])
        def launch(arguments, group, log_name, environment, unprivileged=False):
            def setup():
                os.setsid()
                (groups[group] / "cgroup.procs").write_text(str(os.getpid()))
                if unprivileged:
                    os.setgroups([])
                    os.setgid(config["gid"])
                    os.setuid(config["uid"])
            log = open(round_root / log_name, "w")
            logs.append(log)
            child = subprocess.Popen(arguments, cwd=round_root, env=environment, stdout=log, stderr=log, preexec_fn=setup)
            children.append(child)
            direct_identities[child] = (group, None)
            direct_identities[child] = (group, process_observer.observe_pid(child.pid))
            emit_process({"event": "owned_child_launched", "label": group, "identity": direct_identities[child][1]})
            return child
        def wait_for(read, description, timeout=30):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                capture_exits()
                error = round_root / "error.json"
                if error.exists():
                    raise RuntimeError(error.read_text())
                value = read()
                if value:
                    return value
                time.sleep(0.05)
            raise RuntimeError(f"timed out: {description}")
        def state(name, timeout=30):
            path = round_root / f"{name}.json"
            return wait_for(lambda: json.loads(path.read_text()) if path.exists() else None, name, timeout)
        def stop(child, sig=signal.SIGTERM, timeout=15):
            started = time.monotonic()
            if child.poll() is None:
                emit_process({"event": "owned_cleanup_signal", "identity": direct_identities[child][1], "signal": int(sig), "reason": "requested_graceful_stop"})
                child.send_signal(sig)
            child.wait(timeout=timeout)
            capture_exits()
            return (time.monotonic() - started) * 1000
        env = {"PATH": f"{Path(config['node']).parent}:/usr/sbin:/usr/bin:/bin", "HOME": str(round_root / "home"),
               "TMPDIR": str(round_root), "LANG": "C.UTF-8", "TZ": "UTC", "PI_PACKAGE_DIR": config["packageRoot"],
               "PRIME_AGENT_CODING_AGENT_DIR": str(round_root / "agent"), "PRIME_AGENT_SESSION_DIR": str(round_root / "sessions"),
               "PRIME_AGENT_KERNEL_PYTHON": config["python"], "PRIME_AGENT_KERNEL_FORKSERVER": "1",
               "PRIME_AGENT_DIAGNOSTICS": "native" if mode == "B" else "off", "PI_OFFLINE": "1",
               "PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_CHILD": "1",
               "PI_SKIP_VERSION_CHECK": "1", "PRIME_AGENT_INSTALL_UV": "0", "RLM_DEPTH": "0"}
        name = namespace(config, index) if mode == "B" else None
        recorder = tracer = atop = None
        journal_path = None
        journal_cgroup = None
        try:
            if name:
                journal_relative = host_metadata["journalCgroups"][name]
                assert journal_relative and Path(journal_relative).name == journal_units(name)[0]
                journal_cgroup = Path("/sys/fs/cgroup") / journal_relative.lstrip("/")
                journal_path = Path(f"/var/log/journal/{machine}.{name}")
                wait_for(journal_path.exists, "private native journal directory")
                assert os.statvfs(root).f_bavail * os.statvfs(root).f_frsize >= 8 * GIB, "free reserve unavailable"
            workload_config = {**config, "root": str(round_root), "namespace": name, "diagnostics": mode == "B"}
            write_json(round_root / "workload-config.json", workload_config, config)
            workload = launch([config["node"], config["workload"], str(round_root / "workload-config.json")],
                              "workload", "workload.log", env, True)
            owner = state("owner")
            assert owner["pid"] == workload.pid and workload.pid > 1
            if name:
                trace_identifier = f"causal-{config['id']}-{index}"
                tracer = launch(["/usr/bin/systemd-cat", "--namespace", name, "--identifier", trace_identifier,
                                 "--level-prefix=false", "/usr/bin/bpftrace", "-B", "line", config["probe"],
                                 str(config["uid"]), str(workload.pid)], "trace", "trace-launch.log", env)
                def probe_ready():
                    if tracer.poll() is not None:
                        raise RuntimeError("probe exited before readiness")
                    raw = command(["/usr/bin/journalctl", f"--namespace={name}", f"--identifier={trace_identifier}",
                                   "--quiet", "--no-pager", "--output=json", "--lines=128"])
                    for line in raw.splitlines():
                        entry = json.loads(line)
                        try:
                            event = json.loads(entry["MESSAGE"])
                        except (KeyError, TypeError, json.JSONDecodeError):
                            continue
                        if event.get("event") == "probe_ready":
                            assert entry["_UID"] == "0" and entry["_EXE"] == "/usr/bin/bpftrace"
                            assert event["root_pid"] == workload.pid and event["target_uid"] == config["uid"]
                            return True
                    return False
                wait_for(probe_ready, "trusted scoped probe readiness")
                atop_dir = round_root / "atop"
                atop_dir.mkdir()
                atop_file = atop_dir / time.strftime("atop_%Y%m%d", time.gmtime())
                atop = launch(["/usr/bin/atop", "-w", str(atop_file), str(config["atopIntervalSeconds"])], "atop", "atop.log", env)
                recorder_config = {"stateRoot": str(round_root / "recorder"), "journal": {"namespace": name},
                                   "atop": {"directory": str(atop_dir), "timeZone": "UTC"},
                                   "causalTrace": {"identifier": trace_identifier, "clockTicksPerSecond": os.sysconf("SC_CLK_TCK")},
                                   "nativeHistoryDirectories": [str(journal_path), str(atop_dir)],
                                   "totalBudgetBytes": 16 * GIB, "freeReserveBytes": 8 * GIB, "maxArtifactBytes": 256 * 1024 ** 2}
                write_json(round_root / "recorder-config.json", recorder_config, config)
                recorder_started = time.monotonic()
                recorder = launch(["/usr/bin/flock", "--no-fork", "--nonblock", str(round_root / "recorder.lock"),
                                   config["node"], config["service"], "--config", str(round_root / "recorder-config.json")],
                                  "recorder", "recorder.log", env)
                def recorder_ready():
                    if recorder.poll() is not None:
                        raise RuntimeError((round_root / "recorder.log").read_text())
                    for line in (round_root / "recorder.log").read_text().splitlines():
                        try:
                            event = json.loads(line)
                            if event.get("type") == "ready":
                                assert event.get("capacity", {}).get("admitted") is True, "recorder capacity rejected"
                                return event
                        except json.JSONDecodeError:
                            pass
                    return None
                ready = wait_for(recorder_ready, "recorder readiness")
                recorder_ready_ms = (time.monotonic() - recorder_started) * 1000
            (round_root / "release").touch()
            prepared = state("prepared", 60)
            (round_root / "go").touch()
            while not (round_root / "result.json").exists():
                capture_exits()
                if workload.poll() is not None or (round_root / "error.json").exists():
                    raise RuntimeError("workload exited or reported failure")
                sample = {"observedAtMs": int(time.time() * 1000), "groups": {key: stats(path) for key, path in groups.items()},
                          "journal": stats(journal_cgroup, True) if journal_cgroup else None}
                observations.append(sample)
                process_observer.sample_memory()
                if recorder:
                    events = dict(line.split() for line in sample["groups"]["recorder"]["memory.events"].splitlines())
                    if (int(events.get("oom_kill", 0)) or recorder.poll() is not None) and not admission_failures:
                        admission_failures.append({"reason": "recorder_oom_or_exit", "returnCode": recorder.poll(), "observedAtMs": sample["observedAtMs"]})
                        write_json(round_root / "first-recorder-failure.json", {"failures": admission_failures, "resources": sample}, config)
                assert len(observations) < 180, "measurement exceeded bound"
                time.sleep(1)
            outcome = state("result")
            write_json(round_root / "admission-failures.json", admission_failures, config)
            resource = {key: stats(path) for key, path in groups.items()}
            journal_resource = stats(journal_cgroup, True) if journal_cgroup else None
            if tracer:
                stop(tracer, signal.SIGINT, 15)
            if atop:
                stop(atop, signal.SIGTERM, 15)
            if name:
                command(["/usr/bin/journalctl", f"--namespace={name}", "--sync"])
                analysis = analyze_journal(name, round_root / "journal-analysis.json", config)
                write_json(round_root / "native-history.json", native_files(journal_path), config)
                assert not admission_failures and recorder.poll() is None, "recorder failed during workload; retained capture is incomplete"
                highwater = analysis["lastCursor"]
                assert highwater, "journal highwater unavailable"
                occurrence_id = hashlib.sha256(json.dumps(["journal:service", highwater], separators=(",", ":")).encode()).hexdigest()
                database = round_root / "recorder/evidence.sqlite"
                def stored_highwater():
                    with sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=0.1) as connection:
                        return connection.execute("SELECT 1 FROM occurrences WHERE source='journal:service' AND id=?", (occurrence_id,)).fetchone()
                wait_for(stored_highwater, "durable journal highwater", 15)
                recorder_stop_ms = stop(recorder, signal.SIGTERM, 15)
                assert recorder.returncode == 0 and "populated 0" in (groups["recorder"] / "cgroup.events").read_text()
                resource = {key: stats(path) for key, path in groups.items()}
                counts = db_counts(database)
                native_bytes = flat_bytes(journal_path) + flat_bytes(round_root / "atop")
                db_bytes = sum(max(path.stat().st_size, path.stat().st_blocks * 512) for path in
                               [database, Path(f"{database}-wal"), Path(f"{database}-shm")] if path.exists())
                warnings = analysis["warningExamples"]
            assert workload.poll() is None, "recorder stop affected workload owner"
            (round_root / "stop").touch()
            try:
                workload.wait(timeout=15)
            except subprocess.TimeoutExpired:
                stop(workload)
            record = {"index": index, "mode": mode, "workload": outcome, "resources": resource,
                      "journalResources": journal_resource, "knownProviderWarnings": warnings if name else [],
                      "recorderReadyMs": recorder_ready_ms if name else None, "recorderStopMs": recorder_stop_ms if name else None,
                      "store": counts if name else None, "nativeAllocatedBytes": native_bytes if name else 0,
                      "databaseAllocatedBytes": db_bytes if name else 0, "nativeHistory": str(journal_path) if name else None,
                      "lossLimitations": ["reported losses and durable highwater only; absence of warnings does not prove complete native coverage"],
                      "exportPressureExercised": bool(name and counts["artifact_bytes"])}
            write_json(round_root / "resources.json", observations, config)
            write_json(round_root / "round.json", record, config)
            results.append(record)
        finally:
            try:
                capture_exits()
                write_json(round_root / "resources.json", observations, config)
                write_json(round_root / "cleanup-start-resources.json", {key: stats(path) for key, path in groups.items()}, config)
                if journal_path:
                    write_json(round_root / "native-history.json", native_files(journal_path), config)
            except Exception as error:
                print(f"pre-cleanup evidence unavailable: {error}", file=sys.stderr)
            for child in reversed(children):
                if child.poll() is None:
                    emit_process({"event": "owned_cleanup_signal", "identity": direct_identities[child][1], "signal": int(signal.SIGTERM), "reason": "round_finally_cleanup"})
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        emit_process({"event": "owned_cleanup_signal", "identity": direct_identities[child][1], "signal": int(signal.SIGKILL), "reason": "owned_cleanup_timeout"})
                        child.kill()
                        child.wait(timeout=3)
            for path in groups.values():
                if "populated 1" in (path / "cgroup.events").read_text():
                    (path / "cgroup.kill").write_text("1")
            try:
                capture_exits()
            except Exception as error:
                print(f"final process evidence unavailable: {error}", file=sys.stderr)
            finally:
                process_observer.close()
                process_log.close()
            for handle in logs:
                handle.close()
            for path in round_root.iterdir():
                if path.is_file():
                    os.chown(path, config["uid"], config["gid"])
    report = []
    for result in results:
        rows = [json.loads(line) for line in (root / f"round-{result['index']}" / "samples.jsonl").read_text().splitlines()]
        kinds = {}
        for kind in sorted({row["kind"] for row in rows}):
            times = sorted(row["elapsedMs"] for row in rows if row["phase"] == "measure" and row["kind"] == kind and row["ok"])
            if times:
                kinds[kind] = {"count": len(times), "p95Ms": times[min(len(times)-1, int(len(times)*0.95))],
                               "perSecond": len(times) / (result["workload"]["phaseDurations"]["measure"] / 1000)}
        report.append({"index": result["index"], "mode": result["mode"], "requestTypes": kinds})
    comparisons = []
    for ai, bi in [(0, 1), (3, 2)]:
        comparisons.append({"baseline": ai, "enabled": bi, "requestTypes": {
            kind: {"throughputLoss": 1 - report[bi]["requestTypes"][kind]["perSecond"] / baseline["perSecond"],
                   "additionalP95": report[bi]["requestTypes"][kind]["p95Ms"] / baseline["p95Ms"] - 1}
            for kind, baseline in report[ai]["requestTypes"].items() if kind in report[bi]["requestTypes"]}})
    write_json(root / "report.json", {"status": "pilot_inconclusive", "rounds": report, "pairedComparisons": comparisons,
               "thresholds": {"throughputLoss": 0.05, "additionalP95": 0.10, "recorderBytes": 256 * 1024 ** 2,
                              "readyMs": 30000, "stopMs": 15000, "totalDiagnosticBytes": 16 * GIB, "freeReserveBytes": 8 * GIB},
               "limitations": config["limitations"] + ["rates require longer observation to separate native preallocation from steady growth", "incident frequency and burst capacity are not established by a healthy pilot"]}, config)


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ["plan", "execute", "host", "inside"]:
        mode.add_argument(f"--{name}", type=Path)
    options = parser.parse_args()
    path = next(value for value in vars(options).values() if value is not None).resolve()
    config = read_config(path)
    if options.plan:
        write_json(path.parent / "launch-plan.json", plan(config, path), config)
        print(json.dumps(plan(config, path), indent=2))
        return
    reviewed = json.loads((path.parent / "launch-plan.json").read_text())
    assert reviewed == plan(config, path), "launch plan changed; review the new plan before execution"
    if options.execute:
        raise SystemExit(subprocess.call(reviewed["launch"]))
    if options.host:
        assert os.geteuid() == 0 and os.getpid() != 1
        filesystem = verify_disk_root(Path(config["runtimeRoot"]), config["id"])
        try:
            metadata = {"filesystem": filesystem, "installedAtop": command(["/usr/bin/systemctl", "show", "atop.service", "-p", "ActiveState", "-p", "ExecStart", "-p", "MainPID"]), "journalCgroups": {}}
            for index, mode in enumerate(config["order"]):
                if mode != "B":
                    continue
                name = namespace(config, index)
                config_dir = Path(f"/run/systemd/journald@{name}.conf.d")
                config_dir.mkdir(mode=0o755)
                (config_dir / "90-admission.conf").write_text(JOURNAL_CONFIG)
                command(["/usr/bin/systemctl", "start", journal_units(name)[0]])
                metadata["journalCgroups"][name] = command(["/usr/bin/systemctl", "show", journal_units(name)[0], "-p", "ControlGroup", "--value"]).strip()
            write_json(path.parent / "host-metadata.json", metadata, config)
            with open(path.parent / "launch.log", "w") as output:
                code = observe_host_launch(config, path, output)
            if code:
                raise RuntimeError(f"Pilot failed; retained launch.log, exit={code}")
        finally:
            subprocess.run(["/usr/bin/systemctl", "stop", unit(config)], capture_output=True, timeout=30)
            namespace_cleanup(config)
    elif options.inside:
        inside(config)


if __name__ == "__main__":
    main()
