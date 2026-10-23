"""Tests of the helpers that start and stop the worker processes."""
import multiprocessing
import os
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from utils.process_utils import sigint_blocked

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

posix_only = pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX only")


def _report_sigint(connection):
    """Target of a spawned worker: is SIGINT blocked or ignored when it starts?"""
    blocked = signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, [])
    connection.send((blocked, signal.getsignal(signal.SIGINT) == signal.SIG_IGN))
    connection.close()


@posix_only
def test_worker_started_inside_sigint_blocked_does_not_receive_ctrl_c():
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    worker = context.Process(target=_report_sigint, args=(sender,))
    try:
        with sigint_blocked():
            assert signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, [])
            worker.start()
            # Ctrl+C while the worker starts: it stays pending in the worker, which never handles it
            os.kill(worker.pid, signal.SIGINT)
        assert signal.SIGINT not in signal.pthread_sigmask(signal.SIG_BLOCK, [])
        sender.close()

        assert receiver.poll(60), "the process did not respond"
        blocked, ignored = receiver.recv()
        worker.join(60)
        assert blocked or ignored
        assert worker.exitcode == 0
    finally:
        if worker.is_alive():
            worker.kill()
            worker.join()


# The worker reports its pid and whether it ignores SIGINT, then that it is still alive after a few parent checks
_WORKER = """
import os, signal, time
from utils import process_utils
process_utils.PARENT_CHECK_INTERVAL = 0.05
process_utils.init_worker_process(os.getppid())
print(os.getpid(), signal.getsignal(signal.SIGINT) == signal.SIG_IGN, flush=True)
time.sleep(0.25)
print("alive", flush=True)
time.sleep(60)
"""

_PARENT = """
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", sys.argv[1]])
time.sleep(60)
"""


def _read_line(stream, timeout):
    assert select.select([stream], [], [], timeout)[0], "no response from the process"
    return stream.readline().decode()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_worker_exits_by_itself_when_the_main_process_is_killed():
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    # Unbuffered: select() sees every line that readline() has not read yet
    parent = subprocess.Popen([sys.executable, "-c", _PARENT, _WORKER], stdout=subprocess.PIPE, env=env, bufsize=0)
    worker_pid = None
    try:
        worker_pid, ignores_ctrl_c = _read_line(parent.stdout, 60).split()
        worker_pid = int(worker_pid)
        assert ignores_ctrl_c == "True"
        os.kill(worker_pid, signal.SIGINT)
        # Still running while its parent is alive, after Ctrl+C
        assert _read_line(parent.stdout, 60) == "alive\n"

        parent.kill()
        parent.wait()
        killed = time.monotonic()
        # The worker is the last writer of the pipe: end of file when it exits
        assert _read_line(parent.stdout, 10) == ""
        assert time.monotonic() - killed < 5
        worker_pid = None
    finally:
        parent.kill()
        parent.wait()
        parent.stdout.close()
        if worker_pid is not None:
            try:
                os.kill(worker_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


# A spawned worker, as in the analysis pools: it awaits its parent's exit through the multiprocessing sentinel
_SPAWNING_PARENT = """
import multiprocessing, os, sys, time
from pathlib import Path
from utils import process_utils

def cleanup():
    Path(sys.argv[1]).write_text("removed")

def work():
    process_utils.PARENT_CHECK_INTERVAL = 60  # the sentinel, not polling, must notice the exit
    process_utils.init_worker_process(os.getppid(), cleanup)
    print(os.getpid(), flush=True)
    time.sleep(60)

if __name__ == "__main__":
    multiprocessing.get_context("spawn").Process(target=work).start()
    time.sleep(60)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_spawned_worker_cleans_up_and_exits_at_once_when_the_main_process_is_killed(tmp_path):
    script = tmp_path / "parent.py"
    script.write_text(_SPAWNING_PARENT)
    marker = tmp_path / "cleanup.txt"
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    parent = subprocess.Popen([sys.executable, str(script), str(marker)], stdout=subprocess.PIPE, env=env, bufsize=0)
    worker_pid = None
    try:
        worker_pid = int(_read_line(parent.stdout, 60))
        parent.kill()
        parent.wait()
        killed = time.monotonic()
        assert _read_line(parent.stdout, 10) == ""
        assert time.monotonic() - killed < 2
        assert marker.read_text() == "removed"
        worker_pid = None
    finally:
        parent.kill()
        parent.wait()
        parent.stdout.close()
        if worker_pid is not None:
            try:
                os.kill(worker_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class _Interrupted(Exception):
    pass


def _raise_interrupted(signum, frame):
    raise _Interrupted


@posix_only
@pytest.mark.parametrize("block_raises", [False, True])
def test_ctrl_c_taken_by_another_thread_is_deferred_until_the_end_of_the_block(block_raises):
    events = []
    stop = threading.Event()
    # The kernel delivers a Ctrl+C to any thread that does not block it
    other = threading.Thread(target=stop.wait)
    previous = signal.signal(signal.SIGINT, _raise_interrupted)
    other.start()
    try:
        with pytest.raises(_Interrupted):
            with sigint_blocked():
                os.kill(os.getpid(), signal.SIGINT)
                time.sleep(0.2)
                events.append("block finished")
                if block_raises:
                    raise OSError("failed to start the processes")
            time.sleep(0.2)
    finally:
        signal.signal(signal.SIGINT, previous)
        stop.set()
        other.join()
    assert events == ["block finished"]
