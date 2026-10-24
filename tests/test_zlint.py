"""ZLint analysis tests with a fake zlint executable; the results go to the SQLite tables of db.zlint_store."""
import contextlib
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from helpers import Pki

from db import zlint_store
from db.database import DatabaseType
from utils import process_utils, zlint_utils

# Like zlint: lints stdin or each file argument, one JSON line per input in order, and exits at the first input it
# cannot parse. Every start is logged with its number of files (not `-version`). Markers in the input: BAD fails,
# SLOW hangs.
FAKE_ZLINT = """#!{python}
import json, sys, time
files = sys.argv[1:]
if files == ["-version"]:
    print("ZLint version fake")
    sys.exit(0)
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
NULL_RAW_ERROR = "Unexpected error during processing: 'NoneType' object has no attribute 'encode'"


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
    return zlint


def _insert_rows(open_database, count, db_type=DatabaseType.LEAF, repeat=1):
    """A database of `count` Pki rows (each success row inserted `repeat` times in a row)."""
    database, dao = open_database(db_type)
    for row in Pki().rows(count):
        if row["data"]["tls"]["status"] == "success":
            server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            for _ in range(repeat):
                with database.transaction():
                    dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    return database, dao


def _remove_raw(database, occurrence_id):
    """The certificate of the occurrence loses its raw (as a NULL raw of the old layout)."""
    database.conn.execute("UPDATE CertificateData SET raw_id = NULL WHERE certificate_id = "
                          "(SELECT certificate_id FROM Occurrences WHERE occurrence_id = ?)", (occurrence_id,))
    database.conn.commit()


def _documents(dao):
    """The stored results per certificate occurrence, like the former MongoDB documents."""
    reader = zlint_store.ZlintReader(dao.connection)
    columns = "certificate_id, leaf_domain, issuer_common_name, issuer_organization, issuer_dn, body_id, error_message"
    names = columns.split(", ")
    documents = []
    for row in reader.documents(columns):
        document = dict(zip(names, row))
        body_id = document.pop("body_id")
        document["zlint_results"] = reader.body(body_id) if body_id is not None else None
        documents.append(document)
    return documents


def _units(dao):
    """raw_ids of the distinct certificates, in the order they are linted."""
    return [row[0] for row in dao.connection.execute(
        "SELECT DISTINCT COALESCE(raw_id, 0) FROM CertificateData ORDER BY 1")]


def _saved_raw_ids(dao):
    return [row[0] for row in dao.connection.execute("SELECT raw_id FROM ZlintResults ORDER BY raw_id")]


def _run_state(dao):
    return zlint_store.ZlintReader(dao.connection).run_values()["state"]


def _record_saves(monkeypatch):
    """Record the raw_ids of each save of results."""
    saves = []
    save = zlint_store.ZlintStore.save

    def recording_save(self, results):
        if results:
            saves.append([result.raw_id for result in results])
        save(self, results)

    monkeypatch.setattr(zlint_store.ZlintStore, "save", recording_save)
    return saves


def _rows(raws):
    return [(index + 1, raw) for index, raw in enumerate(raws)]


def _settings(zlint, tmp_path, timeout=10):
    return zlint_utils._Settings(str(zlint.path), timeout, str(tmp_path))


def _outcomes(results):
    return [("result" if result.digest is not None else "error", result.raw_id) for result in results]


def test_results_are_stored(fake_zlint, open_database, tmp_path, monkeypatch, caplog):
    # Temporary files of the run go here, to check they are removed
    (tmp_path / "tmp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    database, dao = _insert_rows(open_database, 5)
    _remove_raw(database, 1)

    zlint_utils.run_zlint_check(dao)

    documents = _documents(dao)
    assert [document["certificate_id"] for document in documents] == [1, 2, 3, 4, 5]
    results = [document for document in documents if document["error_message"] is None]
    assert [document["certificate_id"] for document in results] == [2, 3, 4, 5]
    assert results[0]["leaf_domain"] == "site1.example.test"
    assert results[0]["issuer_common_name"] == "Test Intermediate CA"
    assert results[0]["zlint_results"] == LINTS
    # The key order of zlint's output is kept
    assert list(results[0]["zlint_results"]) == list(LINTS)
    # NULL raw: the same error as before, without starting zlint
    assert documents[0]["error_message"] == NULL_RAW_ERROR and documents[0]["zlint_results"] is None
    assert f"Error processing certificate ID 1: {NULL_RAW_ERROR}" in caplog.text
    assert fake_zlint.starts() == [4]
    # Equal outputs are stored once
    assert dao.connection.execute("SELECT COUNT(*) FROM ZlintBodies").fetchone()[0] == 1
    run = zlint_store.ZlintReader(dao.connection).run_values()
    assert run["state"] == "finished" and run["zlint_version"] == "ZLint version fake" and run["units"] == 5
    assert list((tmp_path / "tmp").iterdir()) == []


def test_each_distinct_certificate_is_linted_once(fake_zlint, open_database, caplog):
    database, dao = _insert_rows(open_database, 3, repeat=2)
    assert dao.get_certificates_count() == 6 and len(_units(dao)) == 3
    _remove_raw(database, 3)

    zlint_utils.run_zlint_check(dao)

    documents = _documents(dao)
    assert [document["certificate_id"] for document in documents] == [1, 2, 3, 4, 5, 6]
    assert [document["leaf_domain"] for document in documents] == [
        "site0.example.test", "site0.example.test", "site1.example.test", "site1.example.test",
        "site2.example.test", "site2.example.test"]
    errors = [None, None, NULL_RAW_ERROR, NULL_RAW_ERROR, None, None]
    assert [document["error_message"] for document in documents] == errors
    # Two certificates with a raw, linted together; the error is logged once per occurrence
    assert fake_zlint.starts() == [2]
    assert [record.getMessage() for record in caplog.records if record.levelname == "ERROR"] == [
        f"Error processing certificate ID 3: {NULL_RAW_ERROR}", f"Error processing certificate ID 4: {NULL_RAW_ERROR}"]


def test_intermediate_certificates_seen_many_times_are_linted_once(fake_zlint, open_database):
    _, dao = _insert_rows(open_database, 1, DatabaseType.INTERMEDIATE, repeat=4)
    assert dao.get_certificates_count() == 4 and len(_units(dao)) == 1

    zlint_utils.run_zlint_check(dao)

    documents = _documents(dao)
    assert [document["certificate_id"] for document in documents] == [1, 2, 3, 4]
    assert all(document["zlint_results"] == LINTS for document in documents)
    # A single certificate: linted through stdin, as before
    assert fake_zlint.starts() == [0]


def test_a_new_run_replaces_the_previous_results(fake_zlint, open_database):
    database, dao = _insert_rows(open_database, 3)
    zlint_utils.run_zlint_check(dao)
    _remove_raw(database, 2)

    zlint_utils.run_zlint_check(dao)

    assert [document["error_message"] for document in _documents(dao)] == [None, NULL_RAW_ERROR, None]
    assert _saved_raw_ids(dao) == _units(dao)
    assert fake_zlint.starts() == [3, 2]


def test_failing_certificate_gets_single_error_and_rest_is_retried(fake_zlint, tmp_path):
    rows = _rows(["AAAA", "BBBB", "BAD", "CCCC", "DDDD", "EEEE"])
    results = zlint_utils._lint_chunk(rows, _settings(fake_zlint, tmp_path))

    assert _outcomes(results) == [("result", 1), ("result", 2), ("error", 3), ("result", 4), ("result", 5),
                                  ("result", 6)]
    assert results[2].error_message == "Error running ZLint: unable to parse PEM\n"
    assert results[2].error_timestamp and results[2].body is None
    assert zlint_store.decode_body(results[0].body) == LINTS
    assert results[0].digest == zlint_store.body_digest(results[0].body)
    # One start for the chunk, one (stdin) for the failing certificate, one for the remaining three
    assert fake_zlint.starts() == [6, 0, 3]


def test_zlint_linting_only_the_first_file(tmp_path):
    zlint = FakeZlint(tmp_path, extra="break")
    results = zlint_utils._lint_chunk(_rows(["A", "B", "C", "D", "E"]), _settings(zlint, tmp_path))

    assert _outcomes(results) == [("result", raw_id) for raw_id in range(1, 6)]
    assert zlint.starts() == [5, 0, 3, 0, 0]


def test_output_not_matching_the_files_falls_back_to_one_start_per_certificate(tmp_path):
    zlint = FakeZlint(tmp_path, extra="print('{}')")
    results = zlint_utils._lint_chunk(_rows(["A", "B", "C"]), _settings(zlint, tmp_path))

    # Two lines per input: as before, the single starts cannot decode their output
    assert [result.error_message for result in results] == ["Error decoding the ZLint JSON output."] * 3
    assert zlint.starts() == [3, 0, 0, 0]


def test_timeout_keeps_the_results_printed_before(fake_zlint, tmp_path):
    results = zlint_utils._lint_chunk(_rows(["A", "SLOW", "C"]), _settings(fake_zlint, tmp_path, timeout=1))

    assert [kind for kind, _ in _outcomes(results)] == ["result", "error", "result"]
    assert "timed out after 1 seconds" in results[1].error_message
    assert results[1].error_message.startswith("Unexpected error during processing: ")
    assert fake_zlint.starts() == [3, 0, 0]


def test_zlint_that_cannot_start_gives_the_single_certificate_errors(tmp_path):
    settings = zlint_utils._Settings(str(tmp_path / "missing"), 10, str(tmp_path))
    results = zlint_utils._lint_chunk(_rows(["A", "B", "C"]), settings)

    assert [kind for kind, _ in _outcomes(results)] == ["error"] * 3
    assert all(result.error_message.startswith("Unexpected error during processing: [Errno 2]") for result in results)


def test_unwritable_temporary_files_fall_back_to_one_start_per_certificate(fake_zlint, tmp_path, monkeypatch):
    def no_space(rows, settings):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(zlint_utils, "_write_pem_files", no_space)
    results = zlint_utils._lint_chunk(_rows(["A", None, "C"]), _settings(fake_zlint, tmp_path))

    assert [kind for kind, _ in _outcomes(results)] == ["result", "error", "result"]
    assert results[1].error_message == NULL_RAW_ERROR
    assert fake_zlint.starts() == [0, 0]


def test_version_of_a_zlint_that_prints_none(tmp_path):
    assert zlint_utils._zlint_version(str(tmp_path / "missing")) is None
    zlint = FakeZlint(tmp_path, extra="")
    zlint.path.write_text("#!/bin/sh\nexit 3\n")
    assert zlint_utils._zlint_version(str(zlint.path)) is None


def test_chunks_run_in_parallel_and_are_saved_in_order_per_db_batch(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 4)
    monkeypatch.setattr(zlint_utils, "ZLINT_WORKERS", 3)
    _, dao = _insert_rows(open_database, 9)
    saves = _record_saves(monkeypatch)

    zlint_utils.run_zlint_check(dao)

    units = _units(dao)
    assert saves == [units[0:4], units[4:8], units[8:9]]
    # The last chunk has a single certificate, linted as before through stdin
    assert sorted(fake_zlint.starts()) == [0, 2, 2, 2, 2]
    assert len(_documents(dao)) == 9


def test_worker_processes_give_the_same_documents(fake_zlint, open_database, monkeypatch):
    _, dao = _insert_rows(open_database, 6)
    zlint_utils.run_zlint_check(dao)
    with_threads = _documents(dao)

    monkeypatch.setattr(zlint_utils, "ZLINT_PROCESSES_FROM", 0)
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    zlint_utils.run_zlint_check(dao)
    with_processes = _documents(dao)

    assert len(with_threads) == 6
    assert with_processes == with_threads


def test_threads_when_worker_processes_cannot_start(fake_zlint, open_database, monkeypatch, caplog):
    def no_processes(*args, **kwargs):
        raise OSError("no processes")

    monkeypatch.setattr(zlint_utils, "ZLINT_PROCESSES_FROM", 0)
    monkeypatch.setattr(zlint_utils, "ProcessPoolExecutor", no_processes)
    _, dao = _insert_rows(open_database, 3)

    zlint_utils.run_zlint_check(dao)

    assert [document["certificate_id"] for document in _documents(dao)] == [1, 2, 3]
    assert "Could not start the ZLint worker processes (no processes)" in caplog.text


def test_failed_save_is_logged_and_the_run_goes_on(fake_zlint, open_database, monkeypatch, caplog):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_store.ZlintStore.save
    calls = []

    def disk_full_once(self, results):
        calls.append(len(results))
        if len(calls) == 1:
            raise sqlite3.OperationalError("database or disk is full")
        save(self, results)

    monkeypatch.setattr(zlint_store.ZlintStore, "save", disk_full_once)
    zlint_utils.run_zlint_check(dao)

    assert "Error saving the ZLint results to the database: database or disk is full" in caplog.text
    assert _saved_raw_ids(dao) == _units(dao)[2:]
    assert _run_state(dao) == "finished"


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
        rows = [(1, "AAAA"), (2, "BBBB")]
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

    def record_directory(dao, store, directory, zlint_path):
        run_directories.append(Path(directory))
        lint_certificates(dao, store, directory, zlint_path)

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
    _, dao = open_database(DatabaseType.LEAF)
    zlint_utils.run_zlint_check(dao)
    assert not zlint_store.has_tables(dao.connection)
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
    _, dao = open_database(DatabaseType.LEAF)

    zlint_utils.run_zlint_check(dao)

    assert not zlint_store.has_tables(dao.connection)
    assert "ZLint is not installed, so the certificates cannot be checked with ZLint. Run the installer again" in caplog.text


def test_interrupt_saves_the_collected_results(fake_zlint, open_database, monkeypatch, caplog):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 6)
    monkeypatch.setattr(zlint_utils, "ZLINT_WORKERS", 1)
    database, dao = _insert_rows(open_database, 9)
    _remove_raw(database, 2)
    collect = zlint_utils._collect
    collected = []

    def ctrl_c_on_the_third_chunk(results, chunk_results):
        if len(collected) == 2:
            raise KeyboardInterrupt
        collected.append(chunk_results)
        collect(results, chunk_results)

    monkeypatch.setattr(zlint_utils, "_collect", ctrl_c_on_the_third_chunk)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)

    # The first two chunks of the batch were collected: saved, although the batch was not complete
    assert _saved_raw_ids(dao) == sorted(_units(dao)[:4])
    assert _run_state(dao) == "interrupted"
    # The errors of the saved results are logged
    assert f"Error processing certificate ID 2: {NULL_RAW_ERROR}" in caplog.text
    assert dao.connection.execute("SELECT name FROM sqlite_temp_master WHERE name = 'zlint_units'").fetchone() is None


def test_interrupted_batch_save_is_not_repeated(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_results
    saved = []

    def ctrl_c_while_saving(store, results):
        saved.append([result.raw_id for result in results])
        save(store, results)
        if len(saved) == 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(zlint_utils, "_save_results", ctrl_c_while_saving)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)

    # The interrupted save is not repeated at the end; nothing else was collected
    units = _units(dao)
    assert saved == [units[:2], []]
    assert _saved_raw_ids(dao) == units[:2]


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signals")
def test_ctrl_c_during_a_batch_save_waits_for_its_end(fake_zlint, open_database, monkeypatch):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_results
    saved = []

    def ctrl_c_while_saving(store, results):
        if not saved:
            signal.raise_signal(signal.SIGINT)
        saved.append([result.raw_id for result in results])
        save(store, results)

    monkeypatch.setattr(zlint_utils, "_save_results", ctrl_c_while_saving)
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            zlint_utils.run_zlint_check(dao)
    finally:
        signal.signal(signal.SIGINT, previous)

    # The Ctrl+C stops the stage only once the batch is saved, and the batch is saved once
    units = _units(dao)
    assert saved == [units[:2], []]
    assert _saved_raw_ids(dao) == units[:2]
    assert _run_state(dao) == "interrupted"


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
@pytest.mark.parametrize("stop_signal", ["SIGHUP", "SIGTERM"])
def test_closing_the_terminal_during_a_batch_save_stops_like_ctrl_c(fake_zlint, open_database, monkeypatch, stop_signal):
    monkeypatch.setattr(zlint_utils, "ZLINT_CHUNK_SIZE", 2)
    monkeypatch.setattr(zlint_utils, "BATCH_SIZE", 2)
    _, dao = _insert_rows(open_database, 4)
    save = zlint_utils._save_results
    saved, silenced, directories = [], [], []

    def window_closed_while_saving(store, results):
        if not saved:
            signal.raise_signal(getattr(signal, stop_signal))
        saved.append([result.raw_id for result in results])
        directories.extend(Path(tempfile.gettempdir()).glob(f"zlint_{os.getpid()}-*"))
        save(store, results)

    monkeypatch.setattr(zlint_utils, "_save_results", window_closed_while_saving)
    # The output of the tests is not a closed terminal, and the other tests must not see a stop
    monkeypatch.setattr(process_utils, "_silence_closed_terminal", lambda: silenced.append(True))
    monkeypatch.setattr(process_utils, "_stop_received", False)
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
    units = _units(dao)
    assert saved == [units[:2], []]
    assert _saved_raw_ids(dao) == units[:2]
    assert directories and not any(directory.exists() for directory in directories)
    assert silenced == ([True] if stop_signal == "SIGHUP" else [])
    assert process_utils.stop_requested()


def test_error_while_stopping_after_the_window_was_closed_still_stops(fake_zlint, open_database, monkeypatch):
    # e.g. the progress bar writing to the closed terminal while the stage stops: the program must not go on
    def write_to_the_closed_terminal(*args):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(zlint_utils, "_lint_certificates", write_to_the_closed_terminal)
    monkeypatch.setattr(zlint_utils, "stop_requested", lambda: True)
    _, dao = _insert_rows(open_database, 2)
    with pytest.raises(KeyboardInterrupt):
        zlint_utils.run_zlint_check(dao)
    assert _run_state(dao) == "interrupted"


def test_unexpected_error_is_logged_and_the_analysis_goes_on(fake_zlint, open_database, monkeypatch, caplog):
    def broken(*args):
        raise RuntimeError("broken")

    monkeypatch.setattr(zlint_utils, "_lint_certificates", broken)
    _, dao = _insert_rows(open_database, 2)
    zlint_utils.run_zlint_check(dao)
    assert "Error running run_zlint_check: broken" in caplog.text
    assert _run_state(dao) == "failed"
