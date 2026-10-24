"""Start, reuse and stop the MongoDB server included in the project folder, which stores the ZLint results.

The installer puts a portable MongoDB server in .tools/mongodb. When no MongoDB server answers at the local address of
the analysis (localhost:27017), ensure_mongodb() starts that server on 127.0.0.1, with its data in data/mongodb and
its log in data/mongodb.log, and the server stops when the analysis no longer uses it, or at the latest when the
program ends. Without the bundled server nothing changes: the analysis uses the MongoDB service installed by the user.

- The server runs in its own process group (its own session on macOS and Linux), so Ctrl+C reaches only the analysis,
  which saves its results before stopping the server.
- A MongoDB server that is already running is used as it is. If it is the bundled one (its data folder is
  data/mongodb), for example one left running by an analysis that was killed, it is stopped at the end like a server
  started by this run, unless another program (another analysis, MongoDB Compass, ...) is still connected to it.
- Inside stop_signals_as_ctrl_c(), closing the terminal window (SIGHUP) or a request to stop the program (SIGTERM)
  is handled like Ctrl+C, so that the results are saved and the server is stopped cleanly instead of being left
  running.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from pymongo.uri_parser import parse_uri

# Admin: Anuar Elio Magliari
# Politecnico di Torino

PROJECT_DIR = Path(__file__).resolve().parents[2]
EXE_SUFFIX = ".exe" if os.name == "nt" else ""
# Read when used, so that the tests can point them elsewhere
MONGOD_PATH = PROJECT_DIR / ".tools" / "mongodb" / "bin" / f"mongod{EXE_SUFFIX}"
DB_PATH = PROJECT_DIR / "data" / "mongodb"
LOG_PATH = PROJECT_DIR / "data" / "mongodb.log"

DEFAULT_URI = "mongodb://localhost:27017/"
# Addresses of this computer: only for these is the bundled server started
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Only programs on this computer can connect to the bundled server (it has no password), and the firewalls of macOS
# and Windows do not ask to allow it
BIND_IP = "127.0.0.1"

PROBE_TIMEOUT = 1.0             # Seconds to connect to the port, to tell whether anything listens on it
PING_TIMEOUT = 10.0             # Seconds for a program listening on the port to answer as a MongoDB server
START_TIMEOUT = 120.0           # Seconds for the bundled server to answer: after a crash it first recovers its data
READY_POLL_TIMEOUT = 0.5        # Seconds of each readiness check
OTHER_CLIENTS_TIMEOUT = 12.0    # A closed connection can stay listed for a heartbeat (10 s) of its client
OTHER_CLIENTS_POLL = 0.5
SHUTDOWN_TIMEOUT = 60.0         # Seconds to save the data and exit after the shutdown command
TERMINATE_TIMEOUT = 15.0        # Then after SIGTERM (on Windows CTRL_BREAK), which also shuts it down cleanly
KILL_TIMEOUT = 5.0
POLL_INTERVAL = 0.1
LOCK_HOLDER_POLL = 1.0
LOG_ROTATE_SIZE = 50 * 1024 * 1024   # The log is moved to data/mongodb.log.old when it grows beyond this size
MAX_STARTS = 5

# mongod exit codes
_EXIT_NETWORK_ERROR = 48        # e.g. the port is already in use
_EXIT_DBPATH_IN_USE = 100       # Another mongod holds the data folder (mongod.lock)

# Windows: GetExitCodeProcess value of a running process, and the access right to query a process
_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5


class MongoServerError(RuntimeError):
    """The bundled MongoDB server cannot be used; the message says what to do."""


def app_name() -> str:
    """Client name of this process, shown in the server's connection list: other names are other programs."""
    return f"DigitalCertiAnalytics-{os.getpid()}"


def bundled_server_installed() -> bool:
    return MONGOD_PATH.is_file()


def _local_address(uri: str) -> tuple[str, int] | None:
    """(host, port) of a single-host MongoDB URI on this computer, else None."""
    if not uri.startswith("mongodb://"):
        return None     # mongodb+srv:// is always remote, and parsing it would query the DNS
    try:
        nodes = parse_uri(uri)["nodelist"]
    except Exception:
        return None
    if len(nodes) != 1 or nodes[0][0].lower() not in LOCAL_HOSTS:
        return None
    return nodes[0]


def pid_alive(pid: int | None) -> bool:
    """Whether a process with this id exists (on Windows os.kill cannot check it: it would stop the process)."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True     # A process of another user
    except OSError:
        return False
    return True


def _windows_pid_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ctypes.get_last_error() == _ERROR_ACCESS_DENIED
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _client(uri_or_host: str, port: int | None = None, timeout: float = PING_TIMEOUT, **options) -> MongoClient:
    milliseconds = int(timeout * 1000)
    return MongoClient(uri_or_host, port, serverSelectionTimeoutMS=milliseconds, connectTimeoutMS=milliseconds,
                       socketTimeoutMS=max(milliseconds, 10000), appname=app_name(), **options)


def _direct_client(port: int, timeout: float) -> MongoClient:
    """Client of the bundled server at 127.0.0.1 (on Windows 'localhost' tries ::1 first, and a refused connection
    there takes about a second)."""
    return _client(BIND_IP, port, timeout, directConnection=True)


def _listening(host: str, port: int) -> bool:
    """Whether a program accepts connections on the port: a refused connection is immediate, unlike a server
    selection of pymongo, which waits for its whole timeout."""
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    # IPv4 first: MongoDB servers listen on 127.0.0.1 by default
    addresses.sort(key=lambda address: address[0] != socket.AF_INET)
    for family, kind, protocol, _, address in addresses:
        try:
            with socket.socket(family, kind, protocol) as probe:
                probe.settimeout(PROBE_TIMEOUT)
                probe.connect(address)
            return True
        except OSError:
            continue
    return False


def _same_path(first: str | os.PathLike, second: str | os.PathLike) -> bool:
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bundled_server_at(client: MongoClient, port: int) -> BundledServer | None:
    """The bundled server if the client's server is the one with the data folder data/mongodb, else None."""
    try:
        options = client.admin.command("getCmdLineOpts")
        status = client.admin.command("serverStatus")
    except PyMongoError:
        return None     # e.g. a server that requires a password: never the bundled one
    db_path = options.get("parsed", {}).get("storage", {}).get("dbPath")
    if not isinstance(db_path, str) or not _same_path(db_path, DB_PATH):
        return None
    pid = _int_or_none(status.get("pid"))
    # Started by this process, then left running for another program: once it exits, only its Popen can reap it
    return BundledServer(port, pid, _started_processes.get(pid))


def _port_in_use_message(port: int) -> str:
    return (f"Port {port} of this computer is used by another program, which is not a MongoDB server the analysis can "
            "use, so the MongoDB server included with the project cannot start. Close that program (or restart the "
            "computer) and run the analysis again.")


def _running_server(uri: str, host: str, port: int) -> tuple[bool, BundledServer | None]:
    """Whether a MongoDB server answers at the URI, and the bundled server if it is that one.

    MongoServerError if another program holds the port.
    """
    if not _listening(host, port):
        return False, None
    client = _client(uri, timeout=PING_TIMEOUT)
    try:
        client.admin.command("ping")
        return True, _bundled_server_at(client, port)
    except PyMongoError:
        if _lock_state()[0]:
            # The bundled server is probably starting or stopping: starting it again waits for it
            return False, None
        raise MongoServerError(_port_in_use_message(port)) from None
    finally:
        client.close()


def _rotate_log() -> None:
    try:
        if LOG_PATH.stat().st_size > LOG_ROTATE_SIZE:
            os.replace(LOG_PATH, LOG_PATH.with_name(LOG_PATH.name + ".old"))
    except OSError:
        pass    # No log yet, or a server left running still writes it (Windows)


def _logged_error(entry: object) -> str | None:
    """Message of an error or fatal entry of the server's JSON log."""
    if not isinstance(entry, dict) or entry.get("s") not in ("E", "F"):
        return None
    attributes = entry.get("attr") if isinstance(entry.get("attr"), dict) else {}
    error = attributes.get("error")
    if isinstance(error, dict):
        error = error.get("errmsg") or error.get("codeName")
    return f"{entry.get('msg', '')}: {error}" if error else str(entry.get("msg", ""))


def _log_excerpt(offset: int) -> str:
    """Last error the server logged after offset (one JSON object per line), else the last other line."""
    try:
        with open(LOG_PATH, "rb") as log:
            log.seek(offset)
            lines = log.read()[-65536:].decode("utf-8", "replace").splitlines()
    except OSError:
        return ""
    errors, others = [], []
    for line in lines:
        try:
            error = _logged_error(json.loads(line))
        except ValueError:
            # e.g. a missing system library, reported before the server starts logging
            others.extend([line.strip()] if line.strip() else [])
            continue
        errors.extend([error] if error else [])
    return (errors or others or [""])[-1][:500]


def _exit_code_text(code: int) -> str:
    # Windows reports crashes as NTSTATUS values, e.g. 0xC0000135 for a missing DLL
    return f"{code:#x}" if code > 255 else str(code)


def _lock_state() -> tuple[bool, int | None]:
    """Whether a running server may hold data/mongodb/mongod.lock, and its process id if known.

    A server writes its process id in the file, which is empty after a clean stop and keeps the id of a server that
    crashed. On Windows the running server may keep the file locked, so that it cannot be read.
    """
    try:
        holder = _int_or_none((DB_PATH / "mongod.lock").read_text(encoding="ascii", errors="replace").strip())
    except FileNotFoundError:
        return False, None
    except OSError:
        return True, None
    return pid_alive(holder), holder


# Signals that stop the program like Ctrl+C inside stop_signals_as_ctrl_c(): the terminal window was closed (SIGHUP)
# or the program was asked to stop (SIGTERM, e.g. by `kill` or at logout). Their default action ends the program at
# once, which would leave the bundled server running and lose the results not saved yet. Windows has neither: closing
# the console ends the program within seconds, and the bundled server, which gets the same console event, stops by
# itself.
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


def _ignore_ctrl_c_at_exit() -> None:
    """The program has finished: a Ctrl+C now would only interrupt pymongo's own clean-up at exit (it waits up to a
    second for its threads), printing a traceback. Registered after pymongo's exit hook, so it runs before it."""
    if threading.current_thread() is threading.main_thread():
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (ValueError, OSError):
            pass


atexit.register(_ignore_ctrl_c_at_exit)


@contextmanager
def _ctrl_c_deferred() -> Iterator[None]:
    """Hold Ctrl+C while the server stops, so that it is never left half stopped; a Ctrl+C received meanwhile is
    handled at the end."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    received = []
    try:
        previous = signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))
    except (ValueError, OSError):
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
        if received and callable(previous):
            previous(signal.SIGINT, None)


class BundledServer:
    """The bundled MongoDB server: started by this run (process) or found running (pid)."""

    def __init__(self, port: int, pid: int | None, process: subprocess.Popen | None = None) -> None:
        self.port = port
        self.pid = pid
        self.process = process
        self.users = 0
        self.stopped = False

    def running(self) -> bool:
        if self.stopped:
            return False
        if self.process is not None:
            return self.process.poll() is None
        return pid_alive(self.pid)

    def release(self) -> None:
        """One user is done with the server: the last one stops it."""
        with _lock:
            self.users = max(0, self.users - 1)
            if self.users > 0:
                return
        self.stop()

    def stop(self) -> None:
        """Stop the server, unless another program is connected to it: shutdown command, then terminate, then kill."""
        global _server
        with _lock:
            if self.stopped:
                return
            running = self.running()
            self.stopped = True
            if _server is self:
                _server = None
        if not running:
            if self.process is not None:
                logging.warning(f"The bundled MongoDB server had stopped by itself (exit code "
                                f"{_exit_code_text(self.process.returncode)}): see '{LOG_PATH}'.")
            return
        with _ctrl_c_deferred():
            if self._other_clients_remain():
                logging.warning("The bundled MongoDB server is left running because another program is connected to it "
                                "(another analysis, or a tool such as MongoDB Compass): the last analysis that uses it "
                                "stops it.")
                return
            logging.info("Stopping the bundled MongoDB server (it saves its data first, please wait)...")
            self._stop_now()

    def _stop_now(self) -> None:
        self._shutdown()
        if self._wait_exit(SHUTDOWN_TIMEOUT):
            logging.info("Bundled MongoDB server stopped.")
            return
        logging.warning(f"The bundled MongoDB server did not stop within {SHUTDOWN_TIMEOUT:.0f} seconds: terminating it.")
        self._terminate()
        if not self._wait_exit(TERMINATE_TIMEOUT):
            self._kill()
            self._wait_exit(KILL_TIMEOUT)

    def _other_clients(self, client: MongoClient) -> list[dict]:
        operations = client.admin.aggregate([{"$currentOp": {"allUsers": True, "idleConnections": True,
                                                             "localOps": True}}])
        own = app_name()
        return [operation for operation in operations if operation.get("client") and operation.get("appName") != own]

    def _other_clients_remain(self) -> bool:
        deadline = time.monotonic() + OTHER_CLIENTS_TIMEOUT
        client = _direct_client(self.port, PING_TIMEOUT)
        try:
            while True:
                try:
                    if not self._other_clients(client):
                        return False
                except PyMongoError:
                    return False    # It does not answer: nobody can be using it
                if time.monotonic() >= deadline:
                    return True
                time.sleep(OTHER_CLIENTS_POLL)
        finally:
            client.close()

    def _shutdown(self) -> None:
        client = _direct_client(self.port, PING_TIMEOUT)
        try:
            client.admin.command("shutdown")
        except PyMongoError:
            pass    # The server closes the connection when it stops
        finally:
            client.close()

    def _wait_exit(self, timeout: float) -> bool:
        if self.process is not None:
            try:
                self.process.wait(timeout)
                return True
            except subprocess.TimeoutExpired:
                return False
        deadline = time.monotonic() + timeout
        while pid_alive(self.pid):
            if time.monotonic() >= deadline:
                return False
            time.sleep(POLL_INTERVAL)
        return True

    def _terminate(self) -> None:
        try:
            if self.process is not None:
                _terminate(self.process)
            elif os.name != "nt" and pid_alive(self.pid):
                # On Windows only the server's own process group can be asked to stop: it is killed instead
                os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass

    def _kill(self) -> None:
        try:
            if self.process is not None:
                self.process.kill()
            elif pid_alive(self.pid):
                # On Windows a signal other than CTRL_* kills the process (TerminateProcess)
                os.kill(self.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except OSError:
            pass


def _terminate(process: subprocess.Popen) -> None:
    """Ask a server started by this run to shut down cleanly."""
    if os.name == "nt":
        # Sent to the server's own process group, like a Ctrl+Break in its console
        os.kill(process.pid, signal.CTRL_BREAK_EVENT)
    else:
        process.terminate()


def _halt(process: subprocess.Popen) -> None:
    """Stop a server that is still starting: terminate, then kill."""
    if process.poll() is not None:
        return
    try:
        _terminate(process)
        process.wait(TERMINATE_TIMEOUT)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
        process.wait(KILL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        pass


_lock = threading.RLock()
_server: BundledServer | None = None
_started_processes: dict[int, subprocess.Popen] = {}
_atexit_registered = False


def _stop_at_exit() -> None:
    server = _server
    if server is not None:
        try:
            server.stop()
        except BaseException as e:   # Also a Ctrl+C: the interpreter is exiting anyway
            logging.error(f"Could not stop the bundled MongoDB server: {e!r}")


def _use(server: BundledServer) -> BundledServer:
    global _server, _atexit_registered
    _server = server
    server.users += 1
    if not _atexit_registered:
        # Also after Ctrl+C (KeyboardInterrupt) and sys.exit(); not when the process is killed: the next run reuses it
        atexit.register(_stop_at_exit)
        _atexit_registered = True
    return server


def ensure_mongodb(uri: str = DEFAULT_URI) -> BundledServer | None:
    """Make sure that a MongoDB server answers at the URI, starting the bundled one when nothing answers.

    Return the bundled server in use (started now or found running), whose release() the caller calls when done; None
    when the URI is not on this computer, when the bundled server is not installed (MongoDB is then used exactly as
    before) or when another MongoDB server answers, which is left alone.
    Raise MongoServerError, with a message that says what to do, when the bundled server cannot be used.
    """
    address = _local_address(uri)
    if address is None or not bundled_server_installed():
        return None
    host, port = address
    with _lock:
        if _server is not None and _server.port == port and _server.running():
            return _use(_server)
        reachable, bundled = _running_server(uri, host, port)
        if not reachable:
            bundled = _start(port)
        elif bundled is not None:
            logging.info(f"Using the bundled MongoDB server already running (process {bundled.pid}).")
        return None if bundled is None else _use(bundled)


def _launch(port: int) -> tuple[subprocess.Popen, int]:
    """Start mongod with its output appended to data/mongodb.log; return it and where its output starts in the log."""
    command = [os.fspath(MONGOD_PATH), "--dbpath", os.fspath(DB_PATH), "--port", str(port), "--bind_ip", BIND_IP,
               "--setParameter", "diagnosticDataCollectionEnabled=false"]
    if os.name == "nt":
        # Ctrl+C in the console reaches only the analysis; CTRL_BREAK still stops the server cleanly
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        # No socket file in /tmp, and a session of its own: Ctrl+C and the closing of the terminal reach only the
        # analysis
        command.append("--nounixsocket")
        options = {"start_new_session": True}
    _rotate_log()
    try:
        with open(LOG_PATH, "ab") as log:
            offset = os.fstat(log.fileno()).st_size
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       **options)
    except OSError as e:
        raise MongoServerError(f"The MongoDB server included with the project ('{MONGOD_PATH}') could not be started "
                               f"({e}). Run the installer again to repair the installation.") from None
    return process, offset


def _wait_until_ready(server: BundledServer, deadline: float) -> bool:
    """Wait for the server started by this run to answer; False if it exited."""
    client = _direct_client(server.port, READY_POLL_TIMEOUT)
    try:
        while time.monotonic() < deadline:
            if server.process.poll() is not None:
                return False
            try:
                if _int_or_none(client.admin.command("serverStatus").get("pid")) == server.pid:
                    return True
                # Another server answers on the port: this one is about to exit with a network error
            except PyMongoError:
                pass    # Not answering yet: each check waits up to READY_POLL_TIMEOUT
            time.sleep(POLL_INTERVAL)
    finally:
        client.close()
    raise MongoServerError(f"The MongoDB server included with the project did not become ready within "
                           f"{START_TIMEOUT:.0f} seconds. The reason is at the end of its log, '{LOG_PATH}'. Restarting "
                           "the computer or running the installer again usually fixes it.")


def _started(server: BundledServer, deadline: float) -> bool:
    try:
        ready = _wait_until_ready(server, deadline)
    except BaseException:
        # A timeout, or Ctrl+C while it starts: it must not be left running
        server.stopped = True
        _halt(server.process)
        raise
    if not ready:
        server.stopped = True
    return ready


def _wait_for_lock_holder(uri: str, port: int, deadline: float) -> tuple[bool, BundledServer | None]:
    """Another server holds the data folder: wait until it answers on the port (reused) or exits (started again)."""
    held, holder = _lock_state()
    while held and time.monotonic() < deadline:
        reachable, bundled = _running_server(uri, BIND_IP, port)
        if reachable:
            return reachable, bundled
        time.sleep(LOCK_HOLDER_POLL)
        held, holder = _lock_state()
    if held:
        process = "" if holder is None else f" (process {holder})"
        raise MongoServerError(f"Another MongoDB server{process} is using the data folder '{DB_PATH}' but does not "
                               f"answer on port {port}. Wait a minute and try again; if it keeps happening, restart the "
                               "computer.")
    return False, None


def _after_failed_start(code: int, offset: int, port: int, deadline: float) -> tuple[bool, BundledServer | None]:
    """The started server exited: (whether another server answers instead, the bundled server if it is that one)."""
    uri = f"mongodb://{BIND_IP}:{port}/"
    if code == _EXIT_DBPATH_IN_USE:
        return _wait_for_lock_holder(uri, port, deadline)
    if code == _EXIT_NETWORK_ERROR:
        # The port was taken meanwhile, e.g. by an analysis started at the same time; if it is free again, retry
        return _running_server(uri, BIND_IP, port)
    raise MongoServerError(f"The MongoDB server included with the project stopped right after starting (exit code "
                           f"{_exit_code_text(code)}): {_log_excerpt(offset) or 'no message'}. Its full log is "
                           f"'{LOG_PATH}'. Run the installer again to repair the installation.")


def _start(port: int) -> BundledServer | None:
    """Start the bundled server and wait until it answers; None if another (not bundled) server took the port."""
    try:
        DB_PATH.mkdir(parents=True, exist_ok=True)
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise MongoServerError(f"Cannot create the MongoDB data folder '{DB_PATH}' ({e}): check that the project folder "
                               "can be written.") from None
    deadline = time.monotonic() + START_TIMEOUT
    for _ in range(MAX_STARTS):
        logging.info("Starting the MongoDB server included with the project...")
        process, offset = _launch(port)
        server = BundledServer(port, process.pid, process)
        if _started(server, deadline):
            logging.info(f"MongoDB server ready (data in '{DB_PATH}', log in '{LOG_PATH}').")
            _started_processes[process.pid] = process
            return server
        reachable, bundled = _after_failed_start(process.returncode, offset, port, deadline)
        if reachable:
            if bundled is not None:
                logging.info(f"Using the bundled MongoDB server already running (process {bundled.pid}).")
            return bundled
        if time.monotonic() >= deadline:
            break
    raise MongoServerError(f"The MongoDB server included with the project could not be started (exit code "
                           f"{_exit_code_text(process.returncode)}): {_log_excerpt(offset) or 'no message'}. Its full "
                           f"log is '{LOG_PATH}'. Restarting the computer or running the installer again usually fixes "
                           "it.")
