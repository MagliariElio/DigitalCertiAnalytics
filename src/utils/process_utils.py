import multiprocessing
import os
import signal
import threading
import time
from contextlib import contextmanager
from typing import Callable, Iterator

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Seconds between the checks that the main process is still alive, when its exit cannot be awaited directly
PARENT_CHECK_INTERVAL = 2.0


@contextmanager
def sigint_blocked() -> Iterator[None]:
    """Defer Ctrl+C while worker processes are started: they inherit the blocked signal, so it never interrupts their
    start-up.

    A Ctrl+C received meanwhile is delivered to the main process at the end of the block, even if the block raises.
    """
    handler = signal.getsignal(signal.SIGINT)
    if (not hasattr(signal, "pthread_sigmask") or threading.current_thread() is not threading.main_thread()
            or handler is None):
        yield
        return
    # On Python 3.10 starting the resource tracker unblocks SIGINT: start it before blocking the signal
    from multiprocessing import resource_tracker
    resource_tracker.ensure_running()
    # The mask holds only for this thread: a Ctrl+C taken by another thread (e.g. a progress bar's) still runs the
    # Python handler here, so it is recorded and raised again after the block
    received = []
    signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        signal.signal(signal.SIGINT, handler)
        if received:
            signal.raise_signal(signal.SIGINT)


def _watch_parent(parent_pid: int, on_parent_exit: Callable[[], None] | None) -> None:
    parent = multiprocessing.parent_process()
    if parent is not None and parent.pid == parent_pid:
        # The parent's sentinel becomes ready when it exits, on every platform
        parent.join()
    else:
        while os.getppid() == parent_pid:
            time.sleep(PARENT_CHECK_INTERVAL)
    try:
        if on_parent_exit is not None:
            on_parent_exit()
    finally:
        os._exit(1)


def init_worker_process(parent_pid: int, on_parent_exit: Callable[[], None] | None = None) -> None:
    """Prepare a worker process: Ctrl+C is left to the main process, which stops the workers, and the worker exits on
    its own when the main process is gone (killed), so it never outlives the analysis.

    `on_parent_exit` runs just before such an exit, e.g. to remove the worker's temporary files.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    threading.Thread(target=_watch_parent, args=(parent_pid, on_parent_exit), daemon=True).start()
