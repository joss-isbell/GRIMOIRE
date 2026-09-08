"""Bounded observers for the isolated admission harness, not recorder runtime."""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time


def command_json(arguments):
    raw = subprocess.check_output(arguments, timeout=5)
    if len(raw) > 65536:
        raise ValueError("filesystem_metadata_limit")
    return json.loads(raw)


def verify_disk_root(root, identity, *, existing=False):
    """Require this machine's verified block-backed ext4 path; never create it."""
    root = Path(root)
    if not re.fullmatch(r"[0-9a-f]{16}", identity) or root != Path("/var/tmp") / identity:
        raise ValueError("runtime_root_path")
    if root.parent.resolve() != root.parent or root.is_symlink():
        raise ValueError("runtime_root_path_symlink")
    if root.exists() != existing or (existing and not root.is_dir()):
        raise ValueError("runtime_root_existence")
    target = root if existing else root.parent
    rows = command_json(["/usr/bin/findmnt", "--json", "--target", str(target), "--output", "TARGET,SOURCE,FSTYPE"])
    filesystems = rows.get("filesystems", [])
    if len(filesystems) != 1:
        raise ValueError("runtime_disk_filesystem_unknown")
    filesystem = filesystems[0]
    source = filesystem.get("source", "")
    if filesystem.get("fstype") != "ext4" or not source.startswith("/dev/"):
        raise ValueError("runtime_disk_filesystem_required")
    magic = subprocess.check_output(["/usr/bin/stat", "-f", "-c", "%t", "--", str(target)], timeout=5).decode().strip()
    backing = os.stat(source)
    device = os.stat(target).st_dev
    if magic != "ef53" or not stat.S_ISBLK(backing.st_mode) or device != backing.st_rdev:
        raise ValueError("runtime_disk_filesystem_mismatch")
    capacity = os.statvfs(target)
    free = capacity.f_bavail * capacity.f_frsize
    if free < 8 * 1024 ** 3:
        raise ValueError("runtime_free_reserve_unavailable")
    return {"root": str(root), "fileSystem": "ext4", "statfsMagic": magic,
            "source": source, "mount": filesystem["target"], "device": device, "availableBytes": free}


def stream_command(arguments, consume, *, timeout=60, max_bytes=16 * 1024 ** 3):
    """Drain both pipes; retain at most one 64KiB read and 4KiB of stderr."""
    child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    for stream in (child.stdout, child.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    count = stderr_count = 0
    digest = hashlib.sha256()
    stderr = b""
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("owned_reader_deadline")
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is child.stdout:
                    count += len(chunk)
                    if count > max_bytes:
                        raise ValueError("owned_reader_byte_limit")
                    digest.update(chunk)
                    consume(chunk)
                else:
                    stderr_count += len(chunk)
                    stderr = (stderr + chunk)[-4096:]
        code = child.wait(timeout=max(.01, deadline - time.monotonic()))
        if code:
            raise RuntimeError(f"owned_reader_exit={code}: {stderr.decode(errors='replace')}")
        return {"bytes": count, "sha256": digest.hexdigest(), "stderrBytes": stderr_count,
                "stderrTail": stderr.decode(errors="replace"), "stderrTruncated": stderr_count > len(stderr), "returnCode": code}
    finally:
        selector.close()
        # The command has its own session. Cancel descendants even if the leader
        # exited while an inherited pipe remained open; no unrelated PID lookup.
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Keep the leader unreaped until the final group signal. Its PID
            # cannot be reused for an unrelated process group during cleanup.
            terminate_deadline = time.monotonic() + 1
            while time.monotonic() < terminate_deadline:
                if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                    break
                time.sleep(.01)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait(timeout=2)
        child.stdout.close()
        child.stderr.close()


class JournalAnalysis:
    def __init__(self, *, max_line_bytes=2 * 1024 ** 2, max_warning_examples=128):
        self.max_line_bytes = max_line_bytes
        self.max_warning_examples = max_warning_examples
        self.buffer = bytearray()
        self.digest = hashlib.sha256()
        self.result = {"complete": False, "records": 0, "bytes": 0, "types": {},
                       "warningCount": 0, "warningExamples": [], "suppressedMessages": 0,
                       "warningExamplesTruncated": False, "lastCursor": None,
                       "firstTimestampUs": None, "lastTimestampUs": None}

    def accept(self, chunk):
        self.digest.update(chunk)
        self.result["bytes"] += len(chunk)
        self.buffer.extend(chunk)
        while True:
            end = self.buffer.find(b"\n")
            if end < 0:
                if len(self.buffer) > self.max_line_bytes:
                    raise ValueError("journal_line_limit")
                return
            if end > self.max_line_bytes:
                raise ValueError("journal_line_limit")
            raw = bytes(self.buffer[:end+1])
            del self.buffer[:end+1]
            self._line(raw)

    def _line(self, raw):
        row = json.loads(raw)
        if not isinstance(row, dict) or not isinstance(row.get("__CURSOR"), str) or len(row["__CURSOR"]) > 16384:
            raise ValueError("journal_cursor_invalid")
        timestamp = row.get("__REALTIME_TIMESTAMP")
        if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{1,20}", timestamp):
            raise ValueError("journal_timestamp_invalid")
        timestamp = int(timestamp)
        message = row.get("MESSAGE")
        event = None
        if isinstance(message, str):
            try:
                event = json.loads(message)
            except json.JSONDecodeError:
                pass
        if isinstance(event, dict) and event.get("schema") == "prime-agent.diagnostic.v1":
            family, kind = "application", event.get("type", "unknown")
        elif isinstance(event, dict) and "event" in event:
            family, kind = "probe", event["event"]
        else:
            family, kind = "provider", "text_or_opaque"
        if not isinstance(kind, str) or len(kind) > 128:
            raise ValueError("journal_type_invalid")
        key = f"{family}:{kind}"
        types = self.result["types"]
        if key not in types and len(types) >= 128:
            raise ValueError("journal_type_limit")
        item = types.setdefault(key, {"count": 0, "bytes": 0, "messageBytes": 0, "maxBytes": 0,
                                     "firstTimestampUs": timestamp, "lastTimestampUs": timestamp})
        item["count"] += 1
        item["bytes"] += len(raw)
        item["messageBytes"] += len(message.encode()) if isinstance(message, str) else 0
        item["maxBytes"] = max(item["maxBytes"], len(raw))
        item["firstTimestampUs"] = min(item["firstTimestampUs"], timestamp)
        item["lastTimestampUs"] = max(item["lastTimestampUs"], timestamp)
        self.result["records"] += 1
        if self.result["records"] > 2_000_000:
            raise ValueError("journal_record_limit")
        self.result["lastCursor"] = row["__CURSOR"]
        first = self.result["firstTimestampUs"]
        last = self.result["lastTimestampUs"]
        self.result["firstTimestampUs"] = timestamp if first is None else min(first, timestamp)
        self.result["lastTimestampUs"] = timestamp if last is None else max(last, timestamp)
        if isinstance(message, str) and re.search(r"WARNING|ERROR|[Ll]ost \d+ events|Suppressed \d+ messages", message):
            self.result["warningCount"] += 1
            suppressed = re.search(r"Suppressed (\d+) messages", message)
            if suppressed:
                self.result["suppressedMessages"] += int(suppressed[1])
            if len(self.result["warningExamples"]) < self.max_warning_examples:
                self.result["warningExamples"].append({"timestampUs": timestamp, "message": message[:4096]})
            else:
                self.result["warningExamplesTruncated"] = True

    def snapshot(self):
        return {**self.result, "sha256": self.digest.hexdigest()}

    def finish(self):
        if self.buffer:
            raise ValueError("journal_unterminated_record")
        self.result["complete"] = True
        return self.snapshot()


class ProcessObserver:
    """Only enumerates one owned cgroup; pidfds fence PID reuse.

    Non-child processes can be proven exited through a pidfd, but their wait
    status is unavailable unless captured as a zombie. Never invent that status.
    Processes born and reaped between polls remain an explicit coverage gap.
    """
    def __init__(self, group, emit):
        self.group = Path(group)
        self.emit = emit
        self.live = {}
        self.known = {}
        self.observed_count = 0
        self.selector = selectors.DefaultSelector()

    def observe_pid(self, pid):
        if pid in self.live:
            return self.live[pid][0]
        if len(self.live) >= 64 or self.observed_count >= 4096:
            raise ValueError("process_observer_limit")
        if pid <= 1:
            raise ValueError("process_observer_pid")
        fd = os.pidfd_open(pid)
        try:
            proc = Path(f"/proc/{pid}")
            before = (proc / "stat").read_text()
            fields = before.rsplit(")", 1)[1].split()
            status = (proc / "status").read_text()
            identity = {"pid": pid, "startTicks": fields[19], "parentPid": int(fields[1]),
                        "pidNamespace": os.readlink(proc / "ns/pid"),
                        "namespacePids": next((line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:")), []),
                        "cgroup": (proc / "cgroup").read_text().strip()}
            after = (proc / "stat").read_text().rsplit(")", 1)[1].split()
            if after[19] != fields[19]:
                raise ValueError("process_generation_changed")
            self.live[pid] = (identity, fd)
            self.known[pid] = identity
            self.observed_count += 1
            self.selector.register(fd, selectors.EVENT_READ, pid)
            self.emit({"event": "process_observed", "identity": identity, "observedAtMs": int(time.time()*1000)})
            return identity
        except BaseException:
            os.close(fd)
            raise

    def scan(self):
        for key, _ in self.selector.select(0):
            identity, fd = self.live.pop(key.data)
            self.selector.unregister(fd)
            os.close(fd)
            wait_status = None
            try:
                fields = Path(f"/proc/{identity['pid']}/stat").read_text().rsplit(")", 1)[1].split()
                if fields[0] == "Z" and fields[19] == identity["startTicks"] and len(fields) > 49:
                    wait_status = int(fields[49])
            except FileNotFoundError:
                pass
            self.emit({"event": "process_exit_observed", "identity": identity, "evidence": "pidfd_ready",
                       "waitStatus": wait_status, "limitation": "not_direct_child_wait_status_unavailable" if wait_status is None else None,
                       "observedAtMs": int(time.time()*1000)})
        if not self.group.exists():
            return
        raw = (self.group / "cgroup.procs").read_text()
        pids = raw.split()
        if len(pids) > 64:
            raise ValueError("process_cgroup_limit")
        for text in pids:
            pid = int(text)
            try:
                self.observe_pid(pid)
            except ProcessLookupError:
                self.emit({"event": "process_observation_gap", "pid": pid, "reason": "exited_before_identity_read"})
            except FileNotFoundError:
                self.emit({"event": "process_observation_gap", "pid": pid, "reason": "proc_identity_unavailable"})

    def direct_exit(self, child, label, identity=None):
        code = child.poll()
        if code is not None:
            identity = identity or self.known.get(child.pid)
            self.emit({"event": "direct_child_exit", "label": label, "identity": identity,
                       "returnCode": code, "evidence": "owned_subprocess_wait", "observedAtMs": int(time.time()*1000)})

    def sample_memory(self):
        for identity, _ in list(self.live.values()):
            try:
                proc = Path(f"/proc/{identity['pid']}")
                fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                if fields[19] != identity["startTicks"]:
                    continue
                status = (proc / "status").read_text()
                values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines()
                          if line.split(":", 1)[0] in ("State", "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmSwap")}
                after = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                if after[19] == identity["startTicks"]:
                    self.emit({"event": "process_memory_sample", "identity": identity, "values": values,
                               "observedAtMs": int(time.time()*1000)})
            except (FileNotFoundError, ProcessLookupError):
                pass

    def close(self):
        for _, fd in self.live.values():
            os.close(fd)
        self.live.clear()
        self.selector.close()
