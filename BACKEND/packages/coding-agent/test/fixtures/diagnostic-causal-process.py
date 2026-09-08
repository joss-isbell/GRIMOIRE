import ctypes
import json
import os
from pathlib import Path
import platform
import signal
import socket
import sys
import threading
import time
import warnings


libc = ctypes.CDLL(None, use_errno=True)
assert platform.machine() == "x86_64", "fixture syscall numbers require x86_64"
signal.signal(signal.SIGUSR1, lambda *_: None)
signal.signal(signal.SIGUSR2, lambda *_: None)


def name_root():
    assert libc.prctl(15, b"prime-agent", 0, 0, 0) == 0


prior_child = None
if sys.argv[1] == "restart":
    name_root()
    wake_read, wake_write = os.pipe()
    prior_child = os.fork()
    if prior_child == 0:
        os.close(wake_write)
        assert os.read(wake_read, 1) == b"g"
        late = socket.socket(socket.AF_UNIX)
        late.bind(os.path.join(sys.argv[2], "late.sock"))
        late.close()
        os._exit(0)
    os.close(wake_read)

exec_read, exec_write = os.pipe()
exec_ready_read, exec_ready_write = os.pipe()
prior_exec_pid = os.fork()
if prior_exec_pid == 0:
    os.close(exec_write)
    os.close(exec_ready_read)

    def execute_from_prior_thread():
        os.write(exec_ready_write, b"r")
        assert os.read(exec_read, 1) == b"g"
        os.execl("/usr/bin/true", "true")

    execution_thread = threading.Thread(target=execute_from_prior_thread)
    execution_thread.start()
    execution_thread.join()
    os._exit(99)
os.close(exec_read)
os.close(exec_ready_write)
assert os.read(exec_ready_read, 1) == b"r"
os.close(exec_ready_read)

thread_events = ("bind", "close", "dup", "shutdown", "signal", "deliver", "fork", "exit")
thread_ready = threading.Barrier(len(thread_events) + 1)
thread_go = threading.Event()
prior_threads = {}
thread_failures = []
shared_socket = None
duplicate_socket = None
shutdown_socket = None


def prior_thread(first_event):
    prior_threads[first_event] = threading.get_native_id()
    if first_event == "deliver":
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    thread_ready.wait()
    assert thread_go.wait(10)
    try:
        if first_event == "bind":
            late = socket.socket(socket.AF_UNIX)
            late.bind(os.path.join(sys.argv[2], "thread.sock"))
            late.close()
        elif first_event == "close":
            shared_socket.close()
        elif first_event == "dup":
            copied = os.dup(duplicate_socket.fileno())
            os.close(copied)
        elif first_event == "shutdown":
            try:
                shutdown_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        elif first_event == "signal":
            assert libc.syscall(200, threading.get_native_id(), signal.SIGUSR1) == 0
        elif first_event == "deliver":
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR2})
        elif first_event == "fork":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                forked = os.fork()
            if forked == 0:
                os._exit(0)
            os.waitpid(forked, 0)
    except BaseException as error:
        thread_failures.append(repr(error))


threads = [threading.Thread(target=prior_thread, args=(first_event,)) for first_event in thread_events]
for thread in threads:
    thread.start()
thread_ready.wait()
assert libc.syscall(234, os.getpid(), prior_threads["deliver"], signal.SIGUSR2) == 0
start_ticks = int(Path("/proc/self/stat").read_text().split(") ", 1)[1].split()[19])
pidns_inode = os.stat("/proc/self/ns/pid").st_ino
print(json.dumps({"ready": os.getpid(), "start_ticks": start_ticks,
                  "clock_ticks": os.sysconf("SC_CLK_TCK"), "pidns_inode": pidns_inode,
                  "prior_child": prior_child, "prior_threads": prior_threads,
                  "prior_exec_pid": prior_exec_pid}), flush=True)
assert sys.stdin.readline().strip() == "go"
if sys.argv[1] == "rename":
    name_root()
os.getuid()
shared_socket = socket.socket(socket.AF_UNIX)
shared_socket.bind(os.path.join(sys.argv[2], "leader.sock"))
duplicate_socket = socket.socket(socket.AF_UNIX)
duplicate_socket.bind(os.path.join(sys.argv[2], "duplicate.sock"))
shutdown_socket = socket.socket(socket.AF_UNIX)
shutdown_socket.bind(os.path.join(sys.argv[2], "shutdown.sock"))
thread_go.set()
for thread in threads:
    thread.join(3)
assert not thread_failures and all(not thread.is_alive() for thread in threads)
duplicate_socket.close()
shutdown_socket.close()
os.write(exec_write, b"g")
os.close(exec_write)
assert os.waitpid(prior_exec_pid, 0)[1] == 0
if prior_child:
    os.write(wake_write, b"g")
    os.close(wake_write)
    os.waitpid(prior_child, 0)

child = os.fork()
if child == 0:
    time.sleep(0.5)
    os._exit(7)

os.kill(os.getpid(), signal.SIGUSR1)
assert libc.syscall(200, os.getpid(), signal.SIGUSR1) == 0
assert libc.syscall(234, os.getpid(), os.getpid(), signal.SIGUSR1) == 0
descriptor = os.pidfd_open(os.getpid())
signal.pidfd_send_signal(descriptor, signal.SIGUSR1)
os.close(descriptor)
os.killpg(os.getpgrp(), signal.SIGUSR1)

server = socket.socket(socket.AF_UNIX)
server.bind(os.path.join(sys.argv[2], "owned.sock"))
server.listen()
client = socket.socket(socket.AF_UNIX)
client.connect(os.path.join(sys.argv[2], "owned.sock"))
accepted, _ = server.accept()
copy = os.dup(client.fileno())
os.close(copy)
copy = os.open("/dev/null", os.O_RDONLY)
os.dup2(client.fileno(), copy)
os.close(copy)
client.shutdown(socket.SHUT_RDWR)
client.close()
accepted.close()
server.close()
for _ in range(2000):
    left, right = socket.socketpair()
    left.close()
    right.close()

print(json.dumps({"external_signal_target": os.getpid()}), flush=True)
assert sys.stdin.readline().strip() == "sent"
os.waitpid(child, 0)
crash = os.fork()
if crash == 0:
    libc.prctl(4, 0, 0, 0, 0)
    ctypes.string_at(0)
    os._exit(99)
_, crash_status = os.waitpid(crash, 0)
executable = os.fork()
if executable == 0:
    os.execl("/usr/bin/true", "true")
os.waitpid(executable, 0)
print(json.dumps({"complete": True, "pid": os.getpid(), "child": child,
                  "crash": crash, "crash_status": crash_status}), flush=True)
