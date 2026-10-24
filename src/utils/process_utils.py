import logging
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


# Signals that stop the program like Ctrl+C inside stop_signals_as_ctrl_c(): the terminal window was closed (SIGHUP)
# or the program was asked to stop (SIGTERM, e.g. by `kill` or at logout). Their default action ends the program at
# once, which would lose the results not saved yet and leave the worker processes' temporary files. Windows has
# neither: closing the console ends the program within seconds.
_STOP_SIGNAL_NAMES = ("SIGHUP", "SIGTERM")
# Standard output and error when they are a terminal, noted while it still works: once the window is closed (and the
# terminal revoked), isatty() can no longer tell
_terminal_outputs: set[int] = set()
_stop_received = False


def stop_requested() -> bool:
    """Whether a stop signal (see stop_signals_as_ctrl_c) arrived: the program is stopping."""
    return _stop_received


def _note_terminal_outputs() -> None:
    for descriptor in (1, 2):
        try:
            if os.isatty(descriptor):
                _terminal_outputs.add(descriptor)
        except OSError:
            pass


def _silence_closed_terminal() -> None:
    """Send the output meant for the closed terminal to the null device: writing to it would fail (app.log still gets
    the log)."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    try:
        for descriptor in (1, 2):
            try:
                if descriptor in _terminal_outputs or os.isatty(descriptor):
                    os.dup2(null, descriptor)
            except OSError:
                pass
    finally:
        os.close(null)


def _stop_like_ctrl_c(signum: int, frame) -> None:
    global _stop_received
    _stop_received = True
    for name in _STOP_SIGNAL_NAMES:
        # The program is stopping: another signal (a closed terminal can send SIGHUP twice) must not cut its clean-up
        signal.signal(getattr(signal, name), signal.SIG_IGN)
    if signum == getattr(signal, "SIGHUP", None):
        _silence_closed_terminal()
    logging.info(f"{signal.Signals(signum).name} received (the terminal window was closed, or the program was asked "
                 "to stop): stopping as after Ctrl+C...")
    if callable(signal.getsignal(signal.SIGINT)):
        # Through the Ctrl+C handler, so that it waits wherever a Ctrl+C waits (e.g. while the results are saved)
        signal.raise_signal(signal.SIGINT)
    else:
        raise KeyboardInterrupt


@contextmanager
def stop_signals_as_ctrl_c() -> Iterator[None]:
    """Handle SIGHUP (the terminal window was closed) and SIGTERM like Ctrl+C while the block runs (macOS, Linux).

    Signals that are ignored (e.g. under nohup) or have a handler of their own are left alone. After a stop signal the
    next ones stay ignored, also after the block, so that the program can finish its clean-up.
    """
    if os.name != "posix" or threading.current_thread() is not threading.main_thread():
        yield
        return
    _note_terminal_outputs()
    installed = []
    for name in _STOP_SIGNAL_NAMES:
        number = getattr(signal, name, None)
        if number is not None and signal.getsignal(number) == signal.SIG_DFL:
            signal.signal(number, _stop_like_ctrl_c)
            installed.append(number)
    try:
        yield
    finally:
        for number in installed:
            if signal.getsignal(number) == _stop_like_ctrl_c:
                signal.signal(number, signal.SIG_DFL)
