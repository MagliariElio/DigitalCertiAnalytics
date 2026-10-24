"""ZLint analysis tests with a fake zlint executable and a fake MongoDB."""
import contextlib
import copy
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from helpers import Pki

from db.database import DatabaseType
from utils import zlint_utils

# Like zlint: lints stdin or each file argument, one JSON line per input in order, and exits at the first input it
# cannot parse. Every start is logged with its number of files. Markers in the input: BAD fails, SLOW hangs.
FAKE_ZLINT = """#!{python}
import json, sys, time
files = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(f"{{len(files)}}\\n")
for data in ([open(path).read() for path in files] if files else [sys.stdin.read()]):
    if "BEGIN CERTIFICATE" not in data or "BAD" in data:
        sys.stderr.write("unable to parse PEM\\n")
        sys.exit(1)
    if "SLOW" in data:
        time.sleep(30)
    print(json.dumps({{"e_lint_a": {{"result": "pass"}}, "w_lint_b": {{"result": "warn"}}, "n_lint_c": {{"result": "pass"}}}}),
          flush=True)
    {extra}
"""

LINTS = {"e_lint_a": {"result": "pass"}, "w_lint_b": {"result": "warn"}, "n_lint_c": {"result": "pass"}}


class FakeCollection:
    def __init__(self):
        self.documents = []
        self.inserts = []

    def insert_one(self, document):
        self.documents.append(document)

    def insert_many(self, documents):
        self.inserts.append([document["certificate_id"] for document in documents])
        self.documents.extend(documents)


class FakeMongo:
    instances = []

    def __init__(self, db_type):
        self.db_type = db_type
        self.collections = {}
        self.closed = False
        FakeMongo.instances.append(self)

    def connect(self):
        pass

    def get_collection(self, name):
        return self.collections.setdefault(name, FakeCollection())

    def close(self):
        self.closed = True


class FakeZlint:
    """Writes the fake executable and reads back how many files each start received."""

    def __init__(self, directory, extra=""):
        if os.name == "nt":
            pytest.skip("the fake zlint is a script with a shebang, which Windows cannot run")
        self.log = directory / "zlint.log"
        self.path = directory / "zlint"
        self.path.write_text(FAKE_ZLINT.format(python=sys.executable, log=str(self.log), extra=extra))
        self.path.chmod(self.path.stat().st_mode | stat.S_IEXEC)

    def starts(self):
        return [int(line) for line in self.log.read_text().split()] if self.log.exists() else []


@pytest.fixture
def fake_zlint(tmp_path, monkeypatch):
    zlint = FakeZlint(tmp_path)
    monkeypatch.setattr(zlint_utils, "ZLINT_PATH", zlint.path)
    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", FakeMongo)
    FakeMongo.instances.clear()
    return zlint


def _insert_rows(open_database, count):
    database, dao = open_database(DatabaseType.LEAF)
    for row in Pki().rows(count):
        if row["data"]["tls"]["status"] == "success":
            server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            with database.transaction():
                dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    return database, dao


def _rows(raws):
    return [(index + 1, f"site{index}.example.test", raw, "CA", "Org", "CN=CA") for index, raw in enumerate(raws)]


def _settings(zlint, tmp_path, timeout=10):
    return zlint_utils._Settings(str(zlint.path), timeout, str(tmp_path))


def test_results_are_stored(fake_zlint, open_database, tmp_path, monkeypatch):
    # Temporary files of the run go here, to check they are removed
    (tmp_path / "tmp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    database, dao = _insert_rows(open_database, 5)
    database.conn.execute("UPDATE Certificates SET raw = NULL WHERE certificate_id = 1")
    database.conn.commit()

    zlint_utils.run_zlint_check(dao)

    mongo = FakeMongo.instances[-1]
    results = mongo.collections["zlint_results"].documents
    errors = mongo.collections["zlint_errors"].documents
    assert [document["certificate_id"] for document in results] == [2, 3, 4, 5]
    assert results[0]["count_results"] == {"pass": 2, "warn": 1}
    assert results[0]["issuer_common_name"] == "Test Intermediate CA"
    assert results[0]["zlint_results"] == LINTS
    assert list(results[0]) == ["count_results", "certificate_id", "leaf_domain", "issuer_common_name",
                                "issuer_organization", "issuer_dn", "zlint_results"]
    # NULL raw: the same error document as before, without starting zlint
    assert [document["certificate_id"] for document in errors] == [1]
    assert errors[0]["error_message"] == "Unexpected error during processing: 'NoneType' object has no attribute 'encode'"
    assert fake_zlint.starts() == [4]
    assert mongo.closed
    assert list((tmp_path / "tmp").iterdir()) == []


def test_failing_certificate_gets_single_error_and_rest_is_retried(fake_zlint, tmp_path):
    rows = _rows(["AAAA", "BBBB", "BAD", "CCCC", "DDDD", "EEEE"])
    documents = zlint_utils._lint_chunk(rows, _settings(fake_zlint, tmp_path))

    assert [(collection, document["certificate_id"]) for collection, document in documents] == [
        ("zlint_results", 1), ("zlint_results", 2), ("zlint_errors", 3),
        ("zlint_results", 4), ("zlint_results", 5), ("zlint_results", 6)]
    assert documents[2][1]["error_message"] == "Error running ZLint: unable to parse PEM\n"
    assert set(documents[2][1]) == {"certificate_id", "leaf_domain", "error_message", "timestamp"}
    # One start for the chunk, one (stdin) for the failing certificate, one for the remaining three
    assert fake_zlint.starts() == [6, 0, 3]


def test_zlint_linting_only_the_first_file(tmp_path):
    zlint = FakeZlint(tmp_path, extra="break")
    documents = zlint_utils._lint_chunk(_rows(["A", "B", "C", "D", "E"]), _settings(zlint, tmp_path))

    assert [document["certificate_id"] for _, document in documents] == [1, 2, 3, 4, 5]
    assert all(collection == "zlint_results" for collection, _ in documents)
    assert zlint.starts() == [5, 0, 3, 0, 0]


def test_output_not_matching_the_files_falls_back_to_one_start_per_certificate(tmp_path):
    zlint = FakeZlint(tmp_path, extra="print('{}')")
    documents = zlint_utils._lint_chunk(_rows(["A", "B", "C"]), _settings(zlint, tmp_path))

    # Two lines per input: as before, the single starts cannot decode their output
    assert [document["error_message"] for _, document in documents] == ["Error decoding the ZLint JSON output."] * 3
    assert zlint.starts() == [3, 0, 0, 0]


def test_timeout_keeps_the_results_printed_before(fake_zlint, tmp_path):
    documents = zlint_utils._lint_chunk(_rows(["A", "SLOW", "C"]), _settings(fake_zlint, tmp_path, timeout=1))

    assert [collection for collection, _ in documents] == ["zlint_results", "zlint_errors", "zlint_results"]
    assert "timed out after 1 seconds" in documents[1][1]["error_message"]
    assert documents[1][1]["error_message"].startswith("Unexpected error during processing: ")
    assert fake_zlint.starts() == [3, 0, 0]


def test_equal_lint_results_are_shared(fake_zlint, tmp_path):
    documents = zlint_utils._lint_chunk(_rows(["A", "B"]), _settings(fake_zlint, tmp_path))

    first, second = (document["zlint_results"] for _, document in documents)
    assert first == second == LINTS
    # One object for equal results, also across the documents of the chunk
    assert first["e_lint_a"] is first["n_lint_c"] is second["e_lint_a"]


def test_lint_results_that_cannot_be_shared_are_kept():
    result = {"a": {"result": "pass"}, "b": {"result": "pass", "details": ["x"]}, "c": "text"}
    assert zlint_utils._share_equal_lints(dict(result), {}) == result
    assert zlint_utils._share_equal_lints(["text"], {}) == ["text"]


def test_only_lint_results_of_strings_are_shared():
    # Equal values of different types (True == 1 == 1.0) and equal items in another order must not be merged
    lints = {"int": {"result": "pass", "n": 1}, "bool": {"result": "pass", "n": True}, "float": {"result": "pass", "n": 1.0},
             "none": {"result": "pass", "n": None}, "none_again": {"result": "pass", "n": None},
             "text": {"result": "pass", "n": "1"}, "text_again": {"result": "pass", "n": "1"},
             "reordered": {"n": "1", "result": "pass"}}
    shared = {}
    first = zlint_utils._share_equal_lints(copy.deepcopy(lints), shared)
    second = zlint_utils._share_equal_lints(copy.deepcopy(lints), shared)

    for result in (first, second):
        assert result == lints
        assert [[(key, type(value)) for key, value in lint.items()] for lint in result.values()] == [
            [(key, type(value)) for key, value in lint.items()] for lint in lints.values()]
    # Objects of strings are shared, also across documents; the others stay distinct
    assert first["text"] is first["text_again"] is second["text"]
    distinct = [first[name] for name in ("int", "bool", "float", "none", "none_again", "text", "reordered")]
    distinct += [second[name] for name in ("int", "bool", "float", "none")]
    assert len({id(lint) for lint in distinct}) == len(distinct)


def test_zlint_that_cannot_start_gives_the_single_certificate_errors(tmp_path):
    settings = zlint_utils._Settings(str(tmp_path / "missing"), 10, str(tmp_path))
    documents = zlint_utils._lint_chunk(_rows(["A", "B", "C"]), settings)

    assert [collection for collection, _ in documents] == ["zlint_errors"] * 3
    assert all(document["error_message"].startswith("Unexpected error during processing: [Errno 2]")
               for _, document in documents)


def test_unwritable_temporary_files_fall_back_to_one_start_per_certificate(fake_zlint, tmp_path, monkeypatch):
    def no_space(rows, settings):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(zlint_utils, "_write_pem_files", no_space)
    documents = zlint_utils._lint_chunk(_rows(["A", None, "C"]), _settings(fake_zlint, tmp_path))

    assert [collection for collection, _ in documents] == ["zlint_results", "zlint_errors", "zlint_results"]
    assert fake_zlint.starts() == [0, 0]


def test_chunks_run_in_parallel_and_are_saved_in_order_per_db_batch(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 4)
    monkeypatch.setattr(zlint_utils, "ZLINT_WORKERS", 3)
    _, dao = _insert_rows(open_database, 9)

    zlint_utils.run_zlint_check(dao)

    collection = FakeMongo.instances[-1].collections["zlint_results"]
    assert collection.inserts == [[1, 2, 3, 4], [5, 6, 7, 8], [9]]
    # The last chunk has a single certificate, linted as before through stdin
    assert sorted(fake_zlint.starts()) == [0, 2, 2, 2, 2]


def test_worker_processes_give_the_same_documents(fake_zlint, open_database, monkeypatch):
    _, dao = _insert_rows(open_database, 6)
    zlint_utils.run_zlint_check(dao)
    with_threads = FakeMongo.instances[-1].collections["zlint_results"].documents

    monkeypatch.setattr(zlint_utils, "ZLINT_PROCESSES_FROM", 0)
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    zlint_utils.run_zlint_check(dao)
    with_processes = FakeMongo.instances[-1].collections["zlint_results"].documents

    assert len(with_threads) == 6
    assert with_processes == with_threads


def test_threads_when_worker_processes_cannot_start(fake_zlint, open_database, monkeypatch, caplog):
    def no_processes(*args, **kwargs):
        raise OSError("no processes")

    monkeypatch.setattr(zlint_utils, "ZLINT_PROCESSES_FROM", 0)
    monkeypatch.setattr(zlint_utils, "ProcessPoolExecutor", no_processes)
    _, dao = _insert_rows(open_database, 3)

    zlint_utils.run_zlint_check(dao)

    documents = FakeMongo.instances[-1].collections["zlint_results"].documents
    assert [document["certificate_id"] for document in documents] == [1, 2, 3]
    assert "Could not start the ZLint worker processes (no processes)" in caplog.text


# A main process holding a pool of 2 zlint workers, with the run directory 'run'. The workers import this script too,
# so they check their parent every 0.1 s when they cannot await its exit, and with SLOW_START they wait for the 'go'
# file while starting up. In 'kill' mode each worker lints a chunk of 2 certificates with BLOCKING_ZLINT.
POOL_HOLDER = """
import os, sys, time
sys.path.insert(0, {src!r})
from utils import process_utils

process_utils.PARENT_CHECK_INTERVAL = 0.1
if __name__ == "__mp_main__" and os.environ.get("SLOW_START"):
    print("worker starting", flush=True)
    while not os.path.exists({go!r}):
        time.sleep(0.01)

if __name__ == "__main__":
    from utils import zlint_utils
    zlint_utils.ZLINT_PROCESSES_FROM = 0
    zlint_utils.ZLINT_WORKERS = 2
    mode, run = sys.argv[1], {run!r}
    os.mkdir(run)
    try:
        if mode == "start":
            os.environ["SLOW_START"] = "1"
        executor = zlint_utils._start_executor(1, run)
        if mode == "submit":
            os.environ["SLOW_START"] = "1"
        rows = [(1, "a.test", "AAAA", "CA", "Org", "CN=CA"), (2, "b.test", "BBBB", "CA", "Org", "CN=CA")]
        settings = zlint_utils._Settings({zlint!r}, 60, run)
        # The idle worker takes one chunk, the other one is started
        chunks = [zlint_utils._submit(executor, rows if mode == "kill" else [], settings) for _ in range(2)]
        deadline = time.monotonic() + 30
        while mode == "kill" and len(os.listdir({started!r})) < 2:
            # A chunk ends while zlint blocks only if zlint could not be started
            if any(chunk.done() for chunk in chunks) or time.monotonic() > deadline:
                print("zlint not started", flush=True)
                os._exit(1)
            time.sleep(0.01)
        print("ready", flush=True)
        time.sleep(30)
    except KeyboardInterrupt:
        print("interrupted", flush=True)
"""

# Logs its start in the 'started' directory and lints until the worker that started it is gone
BLOCKING_ZLINT = """#!{python}
import os, time
parent = os.getppid()
open(os.path.join({started!r}, str(os.getpid())), "w").close()
while os.getppid() == parent:
    time.sleep(0.05)
"""


def _reset_sigint():
    # Ctrl+C as in an interactive shell, also when the tests run with SIGINT ignored (e.g. as a background job)
    signal.signal(signal.SIGINT, signal.SIG_DFL)


def _start_pool_holder(tmp_path, mode):
    script, zlint, started = tmp_path / "pool_holder.py", tmp_path / "blocking_zlint", tmp_path / "started"
    started.mkdir()
    zlint.write_text(BLOCKING_ZLINT.format(python=sys.executable, started=str(started)))
    zlint.chmod(zlint.stat().st_mode | stat.S_IEXEC)
    src = Path(zlint_utils.__file__).resolve().parents[1]
    script.write_text(POOL_HOLDER.format(src=str(src), go=str(tmp_path / "go"), run=str(tmp_path / "run"),
                                         zlint=str(zlint), started=str(started)))
    return subprocess.Popen([sys.executable, str(script), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True, preexec_fn=_reset_sigint)


def _kill_group(process):
    # The holder leads its own process group, with its workers and their zlint processes. macOS refuses (EPERM) a
    # group left with only zombies
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


@contextlib.contextmanager
def _watchdog(process, timeout=60):
    """Kill the holder's process group if it is still awaited after `timeout` seconds, so that a hang fails the test."""
    timer = threading.Timer(timeout, _kill_group, (process,))
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        # Not reaped yet, so its pid still names its group
        if process.returncode is None:
            _kill_group(process)


def _children(pid):
    output = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, check=True).stdout
    return [int(child) for child, parent in (line.split() for line in output.splitlines()) if int(parent) == pid]


def _running(pids):
    if not pids:
        return []
    # A zombie has exited, even if nobody reaped it yet
    output = subprocess.run(["ps", "-o", "pid=,stat=", "-p", ",".join(map(str, pids))], capture_output=True,
                            text=True).stdout
    return [int(line.split()[0]) for line in output.splitlines() if not line.split()[1].startswith("Z")]


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signals")
@pytest.mark.parametrize("mode", ["start", "submit"])
def test_ctrl_c_while_workers_start_interrupts_only_the_main_process(tmp_path, mode):
    with _start_pool_holder(tmp_path, mode) as process, _watchdog(process):
        while (line := process.stdout.readline()) != "worker starting\n":
            assert line == "ready\n"
        # Ctrl+C reaches the whole process group while a worker is starting
        os.killpg(process.pid, signal.SIGINT)
        (tmp_path / "go").touch()
        stdout, stderr = process.communicate(timeout=30)

    assert stdout.splitlines()[-1] == "interrupted"
    assert "Traceback" not in stderr and "KeyboardInterrupt" not in stderr


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX signals")
def test_workers_exit_and_remove_their_files_when_the_main_process_is_killed(tmp_path):
    run = tmp_path / "run"
    pids = []
    with _start_pool_holder(tmp_path, "kill") as process:
        try:
            with _watchdog(process):
                assert process.stdout.readline() == "ready\n"
                # The 2 workers, multiprocessing's resource tracker and the 2 zlint processes
                pids = _children(process.pid) + [int(name) for name in os.listdir(tmp_path / "started")]
                assert len(pids) == 5
                assert sorted(len(list(directory.iterdir())) for directory in run.iterdir()) == [2, 2]
                process.kill()
                process.wait()

            deadline = time.monotonic() + 10
            while _running(pids) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert _running(pids) == []
            assert not run.exists()
        finally:
            for pid in _running(pids):
                os.kill(pid, signal.SIGKILL)


def _make_worker_files(run):
    directory = run / f"{os.getpid()}-{threading.main_thread().ident}"
    directory.mkdir(parents=True)
    (directory / "0.pem").write_text("PEM")


def test_killed_worker_removes_its_files_and_the_last_one_the_run_directory(tmp_path):
    # Another worker's files are still there: only this worker's are removed
    run = tmp_path / "run"
    _make_worker_files(run)
    (run / "1-1").mkdir()
    zlint_utils._remove_worker_files(str(run))
    assert [path.name for path in run.iterdir()] == ["1-1"]

    # The last worker removes the run directory too
    last_run = tmp_path / "last_run"
    _make_worker_files(last_run)
    zlint_utils._remove_worker_files(str(last_run))
    assert not last_run.exists()

    # A run directory removed meanwhile is no error
    zlint_utils._remove_worker_files(str(last_run))


def test_killed_worker_removes_its_files_after_writing_them(tmp_path, monkeypatch):
    monkeypatch.setattr(zlint_utils, "_pem_files_lock", threading.Lock())
    run = tmp_path / "run"
    run.mkdir()
    removal = threading.Thread(target=zlint_utils._remove_worker_files, args=(str(run),))
    waited = []
    to_pem = zlint_utils.Certificate.to_pem

    def kill_while_writing(raw):
        if raw == "B":
            # The main process is killed while the worker writes its files: the removal waits for them
            removal.start()
            removal.join(timeout=0.2)
            waited.append(removal.is_alive())
        return to_pem(raw)

    monkeypatch.setattr(zlint_utils.Certificate, "to_pem", kill_while_writing)
    files = zlint_utils._write_pem_files(_rows(["A", "B", "C"]), zlint_utils._Settings("zlint", 10, str(run)))
    removal.join(timeout=10)

    assert len(files) == 3
    assert waited == [True]
    assert not run.exists()
    # The worker writes no more files before it exits
    assert zlint_utils._pem_files_lock.locked()


def _exited_pid():
    process = subprocess.Popen(["true"])
    process.wait()
    return process.pid


@pytest.mark.skipif(os.name != "posix", reason="POSIX processes")
def test_directories_of_killed_runs_are_removed_by_the_next_run(fake_zlint, open_database, tmp_path, monkeypatch):
    temp = tmp_path / "tmp"
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    killed = _exited_pid()
    (temp / f"zlint_{killed}-abcd_123" / "1-2").mkdir(parents=True)
    (temp / f"zlint_{killed}-abcd_123" / "1-2" / "0.pem").write_text("PEM")
    # A run still going on, names of other programs or versions, and entries that are not directories
    kept = [f"zlint_{os.getppid()}-abcd_123", f"zlint_{killed}_abcd_123", "zlint_abcd_123", f"other_{killed}-abcd_123",
            f"zlint_{'9' * 30}-abcd_123", "target"]
    for name in kept:
        (temp / name).mkdir()
    (temp / f"zlint_{killed}-file").write_text("")
    (temp / f"zlint_{killed}-link").symlink_to(temp / "target")
    kept += [f"zlint_{killed}-file", f"zlint_{killed}-link"]
    run_directories = []
    lint_certificates = zlint_utils._lint_certificates

    def record_directory(dao, mongo, directory, zlint_path):
        run_directories.append(Path(directory))
        lint_certificates(dao, mongo, directory, zlint_path)

    monkeypatch.setattr(zlint_utils, "_lint_certificates", record_directory)
    _, dao = _insert_rows(open_database, 2)

    zlint_utils.run_zlint_check(dao)

    assert sorted(path.name for path in temp.iterdir()) == sorted(kept)
    # The run's own directory is named after its process, so that the next run can tell when it was killed
    [directory] = run_directories
    assert directory.parent == temp
    assert zlint_utils._RUN_DIRECTORY_NAME.fullmatch(directory.name)[1] == str(os.getpid())
    assert not directory.exists()


def test_missing_executable(tmp_path, monkeypatch, open_database, caplog):
    monkeypatch.setattr(zlint_utils, "ZLINT_PATH", tmp_path / "missing")
    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", FakeMongo)
    FakeMongo.instances.clear()
    _, dao = open_database(DatabaseType.LEAF)
    zlint_utils.run_zlint_check(dao)
    assert FakeMongo.instances == []
    assert f"The ZLint executable '{tmp_path / 'missing'}' is missing or cannot run" in caplog.text
    assert "Run the installer again" in caplog.text


def _executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def zlint_locations(tmp_path, monkeypatch):
    """The installer's and the legacy locations in tmp_path, an empty PATH and no DCA_ZLINT_PATH."""
    locations = (tmp_path / ".tools" / "zlint" / "zlint", tmp_path / "zlint" / "v3" / "zlint")
    monkeypatch.setattr(zlint_utils, "ZLINT_LOCATIONS", locations)
    monkeypatch.delenv("DCA_ZLINT_PATH", raising=False)
    (tmp_path / "path").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "path"))
    return locations


@pytest.mark.skipif(os.name != "posix", reason="executable bit")
def test_zlint_lookup_order(zlint_locations, tmp_path, monkeypatch, caplog):
    tools, legacy = zlint_locations
    assert zlint_utils.find_zlint() is None

    on_path = _executable(tmp_path / "path" / "zlint")
    assert zlint_utils.find_zlint() == on_path
    _executable(legacy)
    assert zlint_utils.find_zlint() == legacy
    _executable(tools)
    assert zlint_utils.find_zlint() == tools

    configured = _executable(tmp_path / "custom" / "my-zlint")
    monkeypatch.setenv("DCA_ZLINT_PATH", str(configured))
    assert zlint_utils.find_zlint() == configured

    # A wrong variable is reported, and the other locations are still searched
    monkeypatch.setenv("DCA_ZLINT_PATH", str(tmp_path / "nowhere"))
    assert zlint_utils.find_zlint() == tools
    assert f"DCA_ZLINT_PATH is '{tmp_path / 'nowhere'}', which is not an executable file" in caplog.text

    # Set by code (e.g. the tests), ZLINT_PATH is used as it is
    monkeypatch.setattr(zlint_utils, "ZLINT_PATH", tmp_path / "explicit")
    assert zlint_utils.find_zlint() == tmp_path / "explicit"


@pytest.mark.skipif(os.name != "posix", reason="executable bit")
def test_files_that_cannot_run_are_skipped(zlint_locations, tmp_path):
    tools, legacy = zlint_locations
    tools.parent.mkdir(parents=True)
    tools.write_text("not executable")
    _executable(legacy)
    (tools.parent / "folder").mkdir()
    assert zlint_utils.find_zlint() == legacy


def test_zlint_locations_of_the_project():
    project = Path(zlint_utils.__file__).resolve().parents[2]
    suffix = ".exe" if os.name == "nt" else ""
    assert zlint_utils.ZLINT_LOCATIONS == (project / ".tools" / "zlint" / f"zlint{suffix}",
                                           project / "zlint" / "v3" / f"zlint{suffix}")
    assert zlint_utils.ZLINT_WORKERS <= (61 if os.name == "nt" else zlint_utils.ZLINT_WORKERS)


def test_no_zlint_installed_says_to_run_the_installer(zlint_locations, open_database, monkeypatch, caplog):
    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", FakeMongo)
    FakeMongo.instances.clear()
    _, dao = open_database(DatabaseType.LEAF)

    zlint_utils.run_zlint_check(dao)

    assert FakeMongo.instances == []
    assert "ZLint is not installed, so the certificates cannot be checked with ZLint. Run the installer again" in caplog.text


def test_interrupt_saves_the_collected_results(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 6)
    monkeypatch.setattr(zlint_utils, "ZLINT_WORKERS", 1)
    _, dao = _insert_rows(open_database, 9)
    collect = zlint_utils._collect
    collected = []

    def ctrl_c_on_the_third_chunk(documents, chunk_documents):
        if len(collected) == 2:
            raise KeyboardInterrupt
        collected.append(chunk_documents)
        collect(documents, chunk_documents)

    monkeypatch.setattr(zlint_utils, "_collect", ctrl_c_on_the_third_chunk)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)

    mongo = FakeMongo.instances[-1]
    # The first two chunks of the batch were collected: saved, although the batch was not complete
    assert mongo.collections["zlint_results"].inserts == [[1, 2, 3, 4]]
    assert mongo.closed


def test_interrupted_batch_save_is_not_repeated(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_documents
    saved = []

    def ctrl_c_while_saving(mongo, documents):
        saved.append([document["certificate_id"] for document in documents["zlint_results"]])
        save(mongo, documents)
        if len(saved) == 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(zlint_utils, "_save_documents", ctrl_c_while_saving)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)

    # The interrupted save is not repeated at the end; nothing else was collected
    assert saved == [[1, 2], []]
    assert FakeMongo.instances[-1].collections["zlint_results"].inserts == [[1, 2]]


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signals")
def test_ctrl_c_during_a_batch_save_waits_for_its_end(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_documents
    saved = []

    def ctrl_c_while_saving(mongo, documents):
        if not saved:
            signal.raise_signal(signal.SIGINT)
        saved.append([document["certificate_id"] for document in documents["zlint_results"]])
        save(mongo, documents)

    monkeypatch.setattr(zlint_utils, "_save_documents", ctrl_c_while_saving)
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            zlint_utils.run_zlint_check(dao)
    finally:
        signal.signal(signal.SIGINT, previous)

    # The Ctrl+C stops the stage only once the batch is saved, and the batch is saved once
    assert saved == [[1, 2], []]
    assert FakeMongo.instances[-1].collections["zlint_results"].inserts == [[1, 2]]


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
@pytest.mark.parametrize("stop_signal", ["SIGHUP", "SIGTERM"])
def test_closing_the_terminal_during_a_batch_save_stops_like_ctrl_c(fake_zlint, open_database, monkeypatch, stop_signal):
    from db import mongo_server

    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_documents
    saved, silenced, directories = [], [], []

    def window_closed_while_saving(mongo, documents):
        if not saved:
            signal.raise_signal(getattr(signal, stop_signal))
        saved.append([document["certificate_id"] for document in documents["zlint_results"]])
        directories.extend(Path(tempfile.gettempdir()).glob(f"zlint_{os.getpid()}-*"))
        save(mongo, documents)

    monkeypatch.setattr(zlint_utils, "_save_documents", window_closed_while_saving)
    # The output of the tests is not a closed terminal, and the other tests must not see a stop
    monkeypatch.setattr(mongo_server, "_silence_closed_terminal", lambda: silenced.append(True))
    monkeypatch.setattr(mongo_server, "_stop_received", False)
    signals = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)
    previous = {number: signal.getsignal(number) for number in signals}
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        with pytest.raises(KeyboardInterrupt):
            zlint_utils.run_zlint_check(dao)
        # The program is stopping: further stop signals are ignored until it ends
        assert signal.getsignal(signal.SIGHUP) == signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)

    # Like Ctrl+C: the stage stops once the batch is saved, the batch is saved once, the temporary files are removed
    assert saved == [[1, 2], []]
    assert FakeMongo.instances[-1].collections["zlint_results"].inserts == [[1, 2]]
    assert FakeMongo.instances[-1].closed
    assert directories and not any(directory.exists() for directory in directories)
    assert silenced == ([True] if stop_signal == "SIGHUP" else [])
    assert mongo_server.stop_requested()


def test_error_while_stopping_after_the_window_was_closed_still_stops(fake_zlint, open_database, monkeypatch):
    # e.g. the progress bar writing to the closed terminal while the stage stops: the program must not go on
    def write_to_the_closed_terminal(*args):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(zlint_utils, "_lint_certificates", write_to_the_closed_terminal)
    monkeypatch.setattr(zlint_utils, "stop_requested", lambda: True)
    _, dao = _insert_rows(open_database, 2)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)
    assert FakeMongo.instances[-1].closed


def test_bundled_mongodb_that_cannot_start_is_reported(fake_zlint, open_database, monkeypatch, caplog):
    class UnavailableMongo(FakeMongo):
        def connect(self):
            raise zlint_utils.MongoServerError("Port 27017 is used by another program. Close it.")

    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", UnavailableMongo)
    _, dao = _insert_rows(open_database, 2)

    zlint_utils.run_zlint_check(dao)

    assert "Port 27017 is used by another program. Close it." in caplog.text
    assert "check that the service is running" not in caplog.text
    assert fake_zlint.starts() == []
    assert FakeMongo.instances[-1].closed


def test_unreachable_mongodb_keeps_the_message(fake_zlint, open_database, monkeypatch, caplog):
    class UnreachableMongo(FakeMongo):
        def connect(self):
            raise OSError("connection refused")

    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", UnreachableMongo)
    _, dao = _insert_rows(open_database, 2)

    zlint_utils.run_zlint_check(dao)

    assert "Could not connect to MongoDB: check that the service is running (see the README)." in caplog.text
    assert fake_zlint.starts() == []
