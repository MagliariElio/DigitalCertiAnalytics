"""The bundled MongoDB server (db.mongo_server) with a fake mongod that speaks enough of the MongoDB wire protocol."""
import contextlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest
from pymongo import MongoClient

from db import MongoDbDatabase as mongo_database
from db import mongo_server
from db.database import DatabaseType

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the fake mongod is a script with a shebang")

# Like mongod: --dbpath, --port and --bind_ip; mongod.lock holds the pid of the running server (empty after a clean
# stop) and a live holder makes it exit with 100; a port in use makes it exit with 48. It answers hello, ping,
# serverStatus, getCmdLineOpts, $currentOp (its client connections with their application names) and shutdown.
# FAKE_MONGOD (JSON) changes its behaviour: exit (exit code, after logging an error), never_ready (never listens),
# ignore_stop (ignores shutdown and SIGTERM), commands (file where it appends the name of each command).
FAKE_MONGOD = """#!{python}
import json, os, signal, socket, struct, sys, threading, time
import bson

ARGS = sys.argv[1:]
def option(name):
    return ARGS[ARGS.index(name) + 1]

DB_PATH, PORT, BIND_IP = option("--dbpath"), int(option("--port")), option("--bind_ip")
CONFIG = json.loads(os.environ.get("FAKE_MONGOD") or "{{}}")
LOCK = os.path.join(DB_PATH, "mongod.lock")
connections = {{}}

def log(severity, msg, **attr):
    print(json.dumps({{"s": severity, "c": "CONTROL", "msg": msg, "attr": attr}}), flush=True)

def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

def stop(code=0):
    open(LOCK, "w").close()
    log("I", "mongod shutdown complete")
    os._exit(code)

log("I", "Starting the fake mongod", argv=ARGS)
if "exit" in CONFIG:
    log("E", "DBException in initAndListen, terminating", error="Fatal: something is broken")
    sys.exit(CONFIG["exit"])
try:
    holder = int(open(LOCK).read().strip() or 0)
except (OSError, ValueError):
    holder = 0
if holder and holder != os.getpid() and alive(holder):
    log("E", "DBException in initAndListen, terminating", error="DBPathInUse: Unable to lock the lock file")
    sys.exit(100)
with open(LOCK, "w") as lock:
    lock.write(str(os.getpid()))
if CONFIG.get("never_ready"):
    time.sleep(3600)
signal.signal(signal.SIGTERM, signal.SIG_IGN if CONFIG.get("ignore_stop") else lambda *args: stop())
listener = socket.socket()
try:
    listener.bind((BIND_IP, PORT))
except OSError as e:
    log("E", "Error setting up listener", error={{"errmsg": str(e)}})
    open(LOCK, "w").close()
    sys.exit(48)
listener.listen(64)
log("I", "Waiting for connections", port=PORT)

def reply(command, connection):
    name = next(iter(command))
    if CONFIG.get("commands"):
        with open(CONFIG["commands"], "a") as commands:
            commands.write(name + "\\n")
    if name.lower() in ("ismaster", "hello"):
        connections[connection]["appName"] = command.get("client", {{}}).get("application", {{}}).get("name")
        return {{"ismaster": True, "isWritablePrimary": True, "helloOk": True, "maxWireVersion": 21, "minWireVersion": 0,
                "maxBsonObjectSize": 16777216, "maxMessageSizeBytes": 48000000, "maxWriteBatchSize": 100000, "ok": 1.0}}
    if name == "serverStatus":
        return {{"pid": os.getpid(), "process": "mongod", "ok": 1.0}}
    if name == "getCmdLineOpts":
        return {{"argv": [sys.argv[0], *ARGS], "parsed": {{"storage": {{"dbPath": DB_PATH}}, "net": {{"port": PORT}}}},
                "ok": 1.0}}
    if name == "aggregate":
        operations = [{{"desc": "conn", "client": "%s:%d" % peer, "appName": details["appName"]}}
                      for peer, details in list(connections.items())]
        operations.append({{"desc": "Checkpointer"}})
        return {{"cursor": {{"id": 0, "ns": "admin.$cmd.aggregate", "firstBatch": operations}}, "ok": 1.0}}
    if name == "shutdown" and not CONFIG.get("ignore_stop"):
        stop()
    return {{"n": 0, "ok": 1.0}}

def receive(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data

def serve(stream, peer):
    connections[peer] = {{"appName": None}}
    try:
        while True:
            length, request_id, _, opcode = struct.unpack("<iiii", receive(stream, 16))
            body = receive(stream, length - 16)
            if opcode == 2004:      # OP_QUERY, for the first hello
                start = body.index(b"\\0", 4) + 9
                size = struct.unpack("<i", body[start:start + 4])[0]
                answer = bson.encode(reply(bson.decode(body[start:start + size]), peer))
                payload = struct.pack("<iqii", 0, 0, 0, 1) + answer
                stream.sendall(struct.pack("<iiii", 16 + len(payload), 0, request_id, 1) + payload)
                continue
            position, command = 4, None     # OP_MSG: flag bits, then sections
            while position < len(body):
                kind = body[position]
                size = struct.unpack("<i", body[position + 1:position + 5])[0]
                if kind == 0:
                    command = bson.decode(body[position + 1:position + 1 + size])
                position += 1 + size
            payload = struct.pack("<iB", 0, 0) + bson.encode(reply(command, peer))
            stream.sendall(struct.pack("<iiii", 16 + len(payload), 0, request_id, 2013) + payload)
    except (EOFError, OSError):
        pass
    finally:
        connections.pop(peer, None)
        stream.close()

while True:
    stream, peer = listener.accept()
    threading.Thread(target=serve, args=(stream, peer), daemon=True).start()
"""


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _running(pid):
    return mongo_server.pid_alive(pid) and not _zombie(pid)


def _zombie(pid):
    output = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return output.strip().startswith("Z")


def _wait_gone(pid, timeout=10):
    deadline = time.monotonic() + timeout
    while _running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _running(pid)


class Bundled:
    """A project folder with the fake mongod installed as the bundled server."""

    def __init__(self, directory, monkeypatch):
        self.directory = directory
        self.port = _free_port()
        self.uri = f"mongodb://localhost:{self.port}/"
        self.mongod = directory / ".tools" / "mongodb" / "bin" / "mongod"
        self.mongod.parent.mkdir(parents=True)
        self.mongod.write_text(FAKE_MONGOD.format(python=sys.executable))
        self.mongod.chmod(self.mongod.stat().st_mode | stat.S_IEXEC)
        self.db_path = directory / "data" / "mongodb"
        self.log = directory / "data" / "mongodb.log"
        self.commands = directory / "commands.log"
        self._monkeypatch = monkeypatch
        monkeypatch.setattr(mongo_server, "MONGOD_PATH", self.mongod)
        monkeypatch.setattr(mongo_server, "DB_PATH", self.db_path)
        monkeypatch.setattr(mongo_server, "LOG_PATH", self.log)
        self.configure()
        self.pids = []

    def configure(self, **config):
        self._monkeypatch.setenv("FAKE_MONGOD", json.dumps({"commands": str(self.commands), **config}))

    def received(self):
        return self.commands.read_text().split() if self.commands.exists() else []

    def start_elsewhere(self, db_path=None, port=None, **config):
        """Pid of a server started by another program (e.g. an analysis that was killed), not a child of the tests."""
        environment = {**os.environ, "FAKE_MONGOD": json.dumps({"commands": str(self.commands), **config})}
        db_path, port = db_path or self.db_path, port or self.port
        db_path.mkdir(parents=True, exist_ok=True)
        launcher = subprocess.run(["/bin/sh", "-c", '"$@" > /dev/null 2>&1 & echo $!', "sh", str(self.mongod),
                                   "--dbpath", str(db_path), "--port", str(port), "--bind_ip", "127.0.0.1"],
                                  env=environment, capture_output=True, text=True, check=True)
        pid = int(launcher.stdout)
        self.pids.append(pid)
        with MongoClient("127.0.0.1", port, serverSelectionTimeoutMS=10000) as client:
            client.admin.command("ping")
        return pid

    def cleanup(self):
        """Kill the fake servers still running: those started elsewhere and the one holding the lock file."""
        lock = self.db_path / "mongod.lock"
        holder = lock.read_text().strip() if lock.exists() else ""
        for pid in dict.fromkeys(self.pids + ([int(holder)] if holder.isdigit() else [])):
            command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True).stdout
            if str(self.mongod) in command:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)


@pytest.fixture
def bundled(tmp_path, monkeypatch):
    for name, value in (("START_TIMEOUT", 20.0), ("PING_TIMEOUT", 2.0), ("OTHER_CLIENTS_TIMEOUT", 1.0),
                        ("SHUTDOWN_TIMEOUT", 5.0), ("TERMINATE_TIMEOUT", 5.0), ("LOCK_HOLDER_POLL", 0.1)):
        monkeypatch.setattr(mongo_server, name, value)
    monkeypatch.setattr(mongo_server, "_server", None)
    monkeypatch.setattr(mongo_server, "_started_processes", {})
    folder = Bundled(tmp_path, monkeypatch)
    yield folder
    # Servers left running by a failed test
    for process in mongo_server._started_processes.values():
        if process.poll() is None:
            process.kill()
            process.wait()
    folder.cleanup()


def test_nothing_happens_without_the_bundled_server(tmp_path, monkeypatch):
    monkeypatch.setattr(mongo_server, "MONGOD_PATH", tmp_path / "missing" / "mongod")

    def no_probe(*args):
        raise AssertionError("nothing must be probed")

    monkeypatch.setattr(mongo_server, "_listening", no_probe)
    assert mongo_server.ensure_mongodb("mongodb://localhost:27017/") is None


@pytest.mark.parametrize("uri", ["mongodb://db.example.test:27017/", "mongodb+srv://cluster.example.test/",
                                 "mongodb://localhost:1,localhost:2/?replicaSet=rs", "not a uri"])
def test_remote_servers_are_left_alone(bundled, uri):
    assert mongo_server.ensure_mongodb(uri) is None
    assert not bundled.log.exists()


def test_local_addresses():
    assert mongo_server._local_address("mongodb://localhost:27017/") == ("localhost", 27017)
    assert mongo_server._local_address("mongodb://127.0.0.1/") == ("127.0.0.1", 27017)
    assert mongo_server._local_address("mongodb://[::1]:27018/?directConnection=true") == ("::1", 27018)


def test_starts_the_bundled_server_and_stops_it_when_released(bundled):
    started = time.monotonic()
    server = mongo_server.ensure_mongodb(bundled.uri)

    assert time.monotonic() - started < 10
    assert server is not None and server.process is not None and server.running()
    assert server.pid == server.process.pid
    # Its own session and process group: Ctrl+C in the terminal does not reach it
    assert os.getsid(server.pid) == server.pid != os.getsid(0)
    assert os.getpgid(server.pid) == server.pid != os.getpgid(0)
    with MongoClient(bundled.uri, serverSelectionTimeoutMS=5000) as client:
        assert client.admin.command("ping")["ok"] == 1.0
    options = json.loads(bundled.log.read_text().splitlines()[0])["attr"]["argv"]
    assert options == ["--dbpath", str(bundled.db_path), "--port", str(bundled.port), "--bind_ip", "127.0.0.1",
                       "--setParameter", "diagnosticDataCollectionEnabled=false", "--nounixsocket"]
    assert (bundled.db_path / "mongod.lock").read_text() == str(server.pid)

    server.release()

    assert server.process.poll() == 0
    assert "shutdown" in bundled.received()
    assert (bundled.db_path / "mongod.lock").read_text() == ""
    assert mongo_server._server is None


def test_users_share_the_server_and_the_last_one_stops_it(bundled):
    first = mongo_server.ensure_mongodb(bundled.uri)
    second = mongo_server.ensure_mongodb(bundled.uri)
    assert first is second and first.users == 2

    first.release()
    assert first.running()
    second.release()
    assert first.process.poll() is not None


def test_stopped_at_exit_after_ctrl_c_and_alive_until_then(bundled, tmp_path):
    # An analysis that is interrupted while it uses the server: Ctrl+C reaches its whole process group
    script = tmp_path / "analysis.py"
    script.write_text(textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(Path(mongo_server.__file__).resolve().parents[1])!r})
        from pathlib import Path
        from pymongo import MongoClient
        from db import mongo_server
        mongo_server.MONGOD_PATH = Path({str(bundled.mongod)!r})
        mongo_server.DB_PATH = Path({str(bundled.db_path)!r})
        mongo_server.LOG_PATH = Path({str(bundled.log)!r})
        server = mongo_server.ensure_mongodb({bundled.uri!r})
        print(server.pid, flush=True)
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            # The results are saved after Ctrl+C: the server must still answer
            with MongoClient({bundled.uri!r}, serverSelectionTimeoutMS=5000) as client:
                client.admin.command("ping")
            print("saved", flush=True)
            sys.exit(130)
    """))
    with subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True, start_new_session=True,
                          preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL)) as analysis:
        pid = int(analysis.stdout.readline())
        os.killpg(analysis.pid, signal.SIGINT)
        stdout, _ = analysis.communicate(timeout=30)

    assert stdout == "saved\n"
    assert analysis.returncode == 130
    assert _wait_gone(pid)
    assert "shutdown" in bundled.received()


def test_server_left_by_a_killed_analysis_is_reused_and_stopped(bundled, tmp_path):
    script = tmp_path / "analysis.py"
    script.write_text(textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(Path(mongo_server.__file__).resolve().parents[1])!r})
        from pathlib import Path
        from db import mongo_server
        mongo_server.MONGOD_PATH = Path({str(bundled.mongod)!r})
        mongo_server.DB_PATH = Path({str(bundled.db_path)!r})
        mongo_server.LOG_PATH = Path({str(bundled.log)!r})
        print(mongo_server.ensure_mongodb({bundled.uri!r}).pid, flush=True)
        time.sleep(60)
    """))
    with subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True) as analysis:
        pid = int(analysis.stdout.readline())
        analysis.kill()
    try:
        assert _running(pid)

        server = mongo_server.ensure_mongodb(bundled.uri)

        assert server.process is None and server.pid == pid
        assert bundled.received().count("serverStatus") >= 1
        log_size = bundled.log.stat().st_size
        server.release()
        assert _wait_gone(pid)
        # Not started again
        assert bundled.log.stat().st_size >= log_size
        assert len([line for line in bundled.log.read_text().splitlines() if "Starting the fake" in line]) == 1
    finally:
        if _running(pid):
            os.kill(pid, signal.SIGKILL)


def test_another_mongodb_server_is_left_alone(bundled, tmp_path):
    # e.g. a MongoDB service installed by the user: its data folder is not the bundled one
    pid = bundled.start_elsewhere(db_path=tmp_path / "service")

    assert mongo_server.ensure_mongodb(bundled.uri) is None
    assert _running(pid)
    assert "shutdown" not in bundled.received()
    assert not bundled.log.exists()


def test_server_used_by_another_program_is_left_running(bundled, caplog):
    server = mongo_server.ensure_mongodb(bundled.uri)
    with MongoClient(bundled.uri, appname="MongoDB Compass") as other:
        other.admin.command("ping")
        server.release()
        assert server.process.poll() is None
        assert "shutdown" not in bundled.received()
        assert mongo_server._server is None
        assert "left running because another program is connected to it" in caplog.text

    # The next user finds the bundled server running and stops it at its end (this process reaps it)
    reused = mongo_server.ensure_mongodb(bundled.uri)
    assert reused.pid == server.pid and reused.process is server.process
    started = time.monotonic()
    reused.release()
    assert server.process.poll() == 0
    assert time.monotonic() - started < 3


def test_readiness_timeout_points_to_the_log(bundled, monkeypatch):
    monkeypatch.setattr(mongo_server, "START_TIMEOUT", 1.5)
    bundled.configure(never_ready=True)

    with pytest.raises(mongo_server.MongoServerError) as error:
        mongo_server.ensure_mongodb(bundled.uri)

    assert "did not become ready within 2 seconds" in str(error.value)
    assert str(bundled.log) in str(error.value)
    pid = int((bundled.db_path / "mongod.lock").read_text())
    assert _wait_gone(pid)
    assert mongo_server._server is None


def test_server_that_exits_at_once_reports_its_error(bundled):
    bundled.configure(exit=14)

    with pytest.raises(mongo_server.MongoServerError) as error:
        mongo_server.ensure_mongodb(bundled.uri)

    message = str(error.value)
    assert "stopped right after starting (exit code 14)" in message
    assert "DBException in initAndListen, terminating: Fatal: something is broken" in message
    assert "Run the installer again" in message


def test_executable_that_cannot_run(bundled):
    bundled.mongod.chmod(0o644)

    with pytest.raises(mongo_server.MongoServerError) as error:
        mongo_server.ensure_mongodb(bundled.uri)

    assert "could not be started" in str(error.value) and "Run the installer again" in str(error.value)


def test_port_held_by_another_program(bundled):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", bundled.port))
        listener.listen(8)
        with pytest.raises(mongo_server.MongoServerError) as error:
            mongo_server.ensure_mongodb(bundled.uri)

    assert f"Port {bundled.port} of this computer is used by another program" in str(error.value)
    assert not bundled.log.exists()


def _first_probe_misses(monkeypatch):
    """The first probe finds the port free, as if another program took it just after."""
    real_listening = mongo_server._listening
    probes = []

    def first_probe_misses(host, port):
        probes.append(port)
        return len(probes) > 1 and real_listening(host, port)

    monkeypatch.setattr(mongo_server, "_listening", first_probe_misses)


def test_port_taken_while_starting_is_reported(bundled, monkeypatch):
    _first_probe_misses(monkeypatch)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", bundled.port))
        listener.listen(8)
        with pytest.raises(mongo_server.MongoServerError) as error:
            mongo_server.ensure_mongodb(bundled.uri)

    # mongod exited with 48, and the port is still held by a program that is not MongoDB
    assert f"Port {bundled.port} of this computer is used by another program" in str(error.value)
    assert "Error setting up listener" in bundled.log.read_text()


def test_starts_are_retried_a_few_times_then_reported(bundled, monkeypatch):
    # The port looks free each time, but every start fails on it
    monkeypatch.setattr(mongo_server, "_listening", lambda host, port: False)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", bundled.port))
        listener.listen(8)
        with pytest.raises(mongo_server.MongoServerError) as error:
            mongo_server.ensure_mongodb(bundled.uri)

    assert "could not be started (exit code 48): Error setting up listener: " in str(error.value)
    assert bundled.log.read_text().count("Error setting up listener") == mongo_server.MAX_STARTS


def test_concurrent_start_reuses_the_bundled_server_that_won(bundled, monkeypatch):
    # Another analysis started the bundled server just after the probe: this start finds the data folder in use
    winner = bundled.start_elsewhere()
    _first_probe_misses(monkeypatch)

    server = mongo_server.ensure_mongodb(bundled.uri)

    assert server.pid == winner and server.process is None
    server.release()
    assert _wait_gone(winner)


def test_concurrent_start_of_another_server_on_the_port(bundled, monkeypatch, tmp_path):
    # Another MongoDB server took the port just after the probe: this start exits with 48 and that server is used
    other = bundled.start_elsewhere(db_path=tmp_path / "service")
    _first_probe_misses(monkeypatch)

    assert mongo_server.ensure_mongodb(bundled.uri) is None
    assert _running(other)
    assert "Error setting up listener" in bundled.log.read_text()


def test_stale_lock_of_a_dead_process_is_no_problem(bundled):
    dead = subprocess.Popen(["true"])
    dead.wait()
    bundled.db_path.mkdir(parents=True)
    (bundled.db_path / "mongod.lock").write_text(str(dead.pid))

    server = mongo_server.ensure_mongodb(bundled.uri)

    assert server.running()
    server.release()


def test_data_folder_held_by_a_server_that_does_not_answer(bundled, monkeypatch):
    monkeypatch.setattr(mongo_server, "START_TIMEOUT", 2.0)
    holder = bundled.start_elsewhere(port=_free_port())

    with pytest.raises(mongo_server.MongoServerError) as error:
        mongo_server.ensure_mongodb(bundled.uri)

    assert f"Another MongoDB server (process {holder}) is using the data folder" in str(error.value)
    assert _running(holder)


def test_data_folder_freed_by_a_server_that_stops(bundled):
    # e.g. the server of an analysis that has just ended, still saving its data
    port = _free_port()
    holder = bundled.start_elsewhere(port=port)

    def stop_holder_soon():
        time.sleep(0.5)
        with MongoClient("127.0.0.1", port, serverSelectionTimeoutMS=5000) as client:
            with contextlib.suppress(Exception):
                client.admin.command("shutdown")

    stopper = threading.Thread(target=stop_holder_soon)
    stopper.start()
    try:
        server = mongo_server.ensure_mongodb(bundled.uri)
    finally:
        stopper.join()

    assert _wait_gone(holder)
    assert server.process is not None and server.running()
    server.release()


def test_unreadable_lock_of_a_running_server(bundled, monkeypatch):
    # On Windows the running server may keep mongod.lock locked: its process id is unknown
    monkeypatch.setattr(mongo_server, "START_TIMEOUT", 1.0)
    bundled.start_elsewhere(port=_free_port())
    read_text = Path.read_text

    def locked(path, *args, **kwargs):
        if path.name == "mongod.lock":
            raise PermissionError(13, "The process cannot access the file")
        return read_text(path, *args, **kwargs)

    with monkeypatch.context() as patch, pytest.raises(mongo_server.MongoServerError) as error:
        patch.setattr(Path, "read_text", locked)
        mongo_server.ensure_mongodb(bundled.uri)

    assert "Another MongoDB server is using the data folder" in str(error.value)


def test_lock_state(bundled):
    assert mongo_server._lock_state() == (False, None)
    bundled.db_path.mkdir(parents=True)
    lock = bundled.db_path / "mongod.lock"
    lock.write_text("")
    assert mongo_server._lock_state() == (False, None)
    lock.write_text(str(os.getpid()))
    assert mongo_server._lock_state() == (True, os.getpid())
    lock.write_text("")


def test_server_that_ignores_the_shutdown_is_terminated_then_killed(bundled, monkeypatch):
    monkeypatch.setattr(mongo_server, "SHUTDOWN_TIMEOUT", 0.5)
    monkeypatch.setattr(mongo_server, "TERMINATE_TIMEOUT", 0.5)
    bundled.configure(ignore_stop=True)
    server = mongo_server.ensure_mongodb(bundled.uri)

    started = time.monotonic()
    server.release()

    assert server.process.poll() == -signal.SIGKILL
    assert time.monotonic() - started < 5
    assert "shutdown" in bundled.received()


def test_stopping_twice_does_nothing_more(bundled, caplog):
    server = mongo_server.ensure_mongodb(bundled.uri)
    server.stop()
    server.stop()
    server.release()

    assert server.process.poll() == 0
    assert bundled.received().count("shutdown") == 1
    assert "stopped by itself" not in caplog.text


def test_port_held_while_the_bundled_server_starts_or_stops(bundled, monkeypatch):
    # Something answers on the port but not as MongoDB while the data folder is held, e.g. a server shutting down
    monkeypatch.setattr(mongo_server, "START_TIMEOUT", 1.0)
    bundled.db_path.mkdir(parents=True)
    (bundled.db_path / "mongod.lock").write_text(str(os.getppid()))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", bundled.port))
        listener.listen(8)
        assert mongo_server._running_server(bundled.uri, "localhost", bundled.port) == (False, None)
    (bundled.db_path / "mongod.lock").write_text("")


def test_server_that_stopped_by_itself(bundled, caplog):
    server = mongo_server.ensure_mongodb(bundled.uri)
    server.process.kill()
    server.process.wait()

    server.release()

    assert "had stopped by itself" in caplog.text
    # The next user starts it again
    again = mongo_server.ensure_mongodb(bundled.uri)
    assert again is not server and again.running()
    again.release()


def test_ctrl_c_while_stopping_is_handled_after_the_stop(bundled):
    server = mongo_server.ensure_mongodb(bundled.uri)
    shutdown = server._shutdown

    def ctrl_c_during_the_shutdown():
        signal.raise_signal(signal.SIGINT)
        shutdown()

    server._shutdown = ctrl_c_during_the_shutdown
    with pytest.raises(KeyboardInterrupt):
        server.release()
    assert server.process.poll() == 0


def test_ctrl_c_while_starting_stops_the_server(bundled, monkeypatch):
    bundled.configure(never_ready=True)
    lock = bundled.db_path / "mongod.lock"

    def ctrl_c_once_started(server, deadline):
        deadline = time.monotonic() + 10
        while not (lock.exists() and lock.read_text()) and time.monotonic() < deadline:
            time.sleep(0.01)
        raise KeyboardInterrupt

    monkeypatch.setattr(mongo_server, "_wait_until_ready", ctrl_c_once_started)
    with pytest.raises(KeyboardInterrupt):
        mongo_server.ensure_mongodb(bundled.uri)

    assert _wait_gone(int(lock.read_text()))
    assert mongo_server._server is None


def test_log_is_rotated_when_too_big(bundled, monkeypatch):
    monkeypatch.setattr(mongo_server, "LOG_ROTATE_SIZE", 10)
    bundled.log.parent.mkdir(parents=True)
    bundled.log.write_text("an old and long log\n")

    mongo_server.ensure_mongodb(bundled.uri).release()

    assert bundled.log.with_name("mongodb.log.old").read_text() == "an old and long log\n"
    assert "Starting the fake mongod" in bundled.log.read_text()


def test_log_excerpt(bundled):
    bundled.log.parent.mkdir(parents=True)
    lines = ['{"s":"I","msg":"Starting"}', '{"s":"E","msg":"Error setting up listener","attr":{"error":'
             '{"code":9001,"codeName":"SocketException","errmsg":"Address already in use"}}}', '{"s":"I","msg":"Bye"}']
    bundled.log.write_text("old line\n" + "\n".join(lines) + "\n")
    assert mongo_server._log_excerpt(len("old line\n")) == "Error setting up listener: Address already in use"

    bundled.log.write_text("dyld: Library not loaded: libssl.3.dylib\n")
    assert mongo_server._log_excerpt(0) == "dyld: Library not loaded: libssl.3.dylib"
    assert mongo_server._exit_code_text(0xC0000135) == "0xc0000135"


def test_pid_alive():
    assert mongo_server.pid_alive(os.getpid())
    assert not mongo_server.pid_alive(None)
    assert not mongo_server.pid_alive(0)
    dead = subprocess.Popen(["true"])
    dead.wait()
    assert not mongo_server.pid_alive(dead.pid)


def test_mongodb_database_uses_and_releases_the_bundled_server(bundled):
    database = mongo_database.MongoDbDatabase(DatabaseType.LEAF, uri=bundled.uri)
    database.connect()
    server = database._server
    assert server is not None and server.running()
    assert "dropDatabase" in bundled.received()

    database.close()

    assert server.process.poll() == 0
    assert database._server is None


def test_mongodb_database_without_the_bundled_server(tmp_path, monkeypatch):
    monkeypatch.setattr(mongo_server, "MONGOD_PATH", tmp_path / "missing")
    database = mongo_database.MongoDbDatabase(DatabaseType.LEAF, uri="mongodb://localhost:9/?serverSelectionTimeoutMS=100")

    with pytest.raises(Exception):
        database.connect()

    assert database.client is None and database._server is None


def test_failed_connection_releases_the_server(bundled, monkeypatch):
    def failing_client(*args, **kwargs):
        raise OSError("no client")

    monkeypatch.setattr(mongo_database, "MongoClient", failing_client)
    database = mongo_database.MongoDbDatabase(DatabaseType.LEAF, uri=bundled.uri)
    with pytest.raises(OSError):
        database.connect()

    assert database._server is None
    assert mongo_server._server is None
    assert "shutdown" in bundled.received()


# --- Closing the terminal window, SIGTERM, and Ctrl+C at exit ---------------------------------------------------------

SRC = str(Path(mongo_server.__file__).resolve().parents[1])

# An analysis that uses the bundled server, started by a shell in a terminal window (a pseudo-terminal), until the
# window is closed
HANGUP_ANALYSIS = """
import os, sys, time
sys.path.insert(0, {src!r})
from pathlib import Path
from pymongo import MongoClient
from db import mongo_server
mongo_server.MONGOD_PATH = Path({mongod!r})
mongo_server.DB_PATH = Path({db_path!r})
mongo_server.LOG_PATH = Path({log!r})
report = open({report!r}, "w", buffering=1)
with mongo_server.stop_signals_as_ctrl_c():
    server = mongo_server.ensure_mongodb({uri!r})
    report.write(f"{{os.getpid()}} {{server.pid}}\\n")
    print("ready", flush=True)
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        # The results are saved after the window is closed: the server must still answer
        with MongoClient({uri!r}, serverSelectionTimeoutMS=5000) as client:
            client.admin.command("ping")
        # The terminal is gone (revoked once its shell exits): writing to it must not fail
        for line in range(100):
            print("output for the closed window", line, flush=True)
        report.write("saved\\n")
        server.release()
        report.write("released\\n")
        sys.exit(130)
"""
# The window's shell: it leads the session of the pseudo-terminal, as in Terminal, and runs the analysis as a child
WINDOW_SHELL = ("import fcntl, os, sys, termios; fcntl.ioctl(0, termios.TIOCSCTTY, 0); "
                "os.execv('/bin/sh', ['sh', '-c', sys.argv[1]])")


def _read_until(descriptor, text, timeout=30):
    output, deadline = b"", time.monotonic() + timeout
    while text not in output and time.monotonic() < deadline:
        output += os.read(descriptor, 1024)
    return output


def test_closing_the_terminal_window_stops_like_ctrl_c(bundled, tmp_path):
    import pty

    script, report = tmp_path / "analysis.py", tmp_path / "report.txt"
    script.write_text(HANGUP_ANALYSIS.format(src=SRC, mongod=str(bundled.mongod), db_path=str(bundled.db_path),
                                             log=str(bundled.log), report=str(report), uri=bundled.uri))
    terminal, window = pty.openpty()
    command = f'"{sys.executable}" "{script}"; status=$?; exit $status'
    with subprocess.Popen([sys.executable, "-c", WINDOW_SHELL, command], stdin=window, stdout=window, stderr=window,
                          start_new_session=True) as shell:
        os.close(window)
        try:
            assert b"ready" in _read_until(terminal, b"ready")
        finally:
            # The window is closed: the shell and the analysis get SIGHUP, and the terminal stops working
            os.close(terminal)
        shell.wait(timeout=30)

    analysis_pid, server_pid = (int(pid) for pid in report.read_text().split()[:2])
    assert _wait_gone(analysis_pid, timeout=30)
    assert report.read_text().split()[2:] == ["saved", "released"]
    assert _wait_gone(server_pid)
    assert "shutdown" in bundled.received()


STOP_SIGNALS = """
import os, signal, sys, time
sys.path.insert(0, {src!r})
from db import mongo_server

signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGHUP, signal.SIG_IGN)  # As under nohup
with mongo_server.stop_signals_as_ctrl_c():
    print("nohup kept:", signal.getsignal(signal.SIGHUP) == signal.SIG_IGN)
    try:
        # Like Ctrl+C, SIGTERM waits for the end of a stop of the server
        with mongo_server._ctrl_c_deferred():
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)
            print("deferred")
    except KeyboardInterrupt:
        print("interrupted")
    # The program is stopping: another stop signal does not cut its clean-up
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(0.2)
print("still ignored:", signal.getsignal(signal.SIGTERM) == signal.SIG_IGN)
"""


def test_sigterm_stops_like_ctrl_c_and_a_second_one_is_ignored(tmp_path):
    script = tmp_path / "stop_signals.py"
    script.write_text(STOP_SIGNALS.format(src=SRC))
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=30)
    assert result.stdout.split("\n") == ["nohup kept: True", "deferred", "interrupted", "still ignored: True", ""]
    assert result.returncode == 0 and "Traceback" not in result.stderr


def test_signals_are_restored_when_none_arrived():
    previous = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        with mongo_server.stop_signals_as_ctrl_c():
            assert signal.getsignal(signal.SIGTERM) == mongo_server._stop_like_ctrl_c
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
    finally:
        signal.signal(signal.SIGTERM, previous)


LATE_CTRL_C = """
import os, signal, sys, time
sys.path.insert(0, {src!r})
from db import mongo_server  # Registers its exit hook after pymongo's
import pymongo.synchronous.monitor as monitor

def slow_shutdown():
    # Ctrl+C while pymongo waits for its threads at exit
    os.kill(os.getpid(), signal.SIGINT)
    time.sleep(0.2)
    print("pymongo clean-up finished", flush=True)

signal.signal(signal.SIGINT, signal.default_int_handler)
monitor._shutdown_executors = slow_shutdown
print("Application finished successfully.", flush=True)
"""


def test_ctrl_c_after_the_program_finished_prints_no_traceback(tmp_path):
    script = tmp_path / "late_ctrl_c.py"
    script.write_text(LATE_CTRL_C.format(src=SRC))
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=30)
    assert result.stdout.splitlines() == ["Application finished successfully.", "pymongo clean-up finished"]
    assert result.returncode == 0
    assert "Traceback" not in result.stderr and "KeyboardInterrupt" not in result.stderr
