"""End-to-end CLI tests and tests of the parallel ingestion engine against the single-row path."""
import copy
import errno
import json
import logging
import multiprocessing
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import ExitStack
from multiprocessing.process import BaseProcess
from pathlib import Path

import pytest
from helpers import Pki, success_row

from analysis import ingestion
from dao.certificate_dao import CertificateDAO
from db.database import Database, DatabaseType

PROJECT_DIR = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_DIR / "src" / "db" / "schema_db.sql"


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    """Copy of src/ and res/log_list.json plus a synthetic certs_polito.json (valid, error and invalid rows)."""
    root = tmp_path_factory.mktemp("project")
    ignore = shutil.ignore_patterns("__pycache__", "*.db", "*.csv", "plots", "app.log")
    shutil.copytree(PROJECT_DIR / "src", root / "src", ignore=ignore)
    (root / "res").mkdir()
    shutil.copy(PROJECT_DIR / "res" / "log_list.json", root / "res" / "log_list.json")
    with open(root / "res" / "certs_polito.json", "w") as certs_file:
        for row in Pki().rows(8):
            certs_file.write(json.dumps(row) + "\n")
        certs_file.write(json.dumps(success_row("null.example.test", None, [])) + "\n")
        certs_file.write("not json\n")
    return root


def run_cli(project, *flags):
    env = {**os.environ, "COLUMNS": "160"}
    return subprocess.run([sys.executable, "-m", "analysis.main", *flags], cwd=project / "src",
                          capture_output=True, text=True, timeout=600, env=env)


def count(database_path, table):
    with sqlite3.connect(database_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_analysis_and_plots(project):
    result = run_cli(project, "--leaf_analysis", "--intermediate_analysis", "--root_analysis", "--plot_all_results")
    assert result.returncode == 0, result.stdout + result.stderr

    analysis = project / "src" / "analysis"
    assert count(analysis / "leaf" / "leaf_certificates.db", "Certificates") == 8
    assert count(analysis / "leaf" / "leaf_certificates.db", "Errors") == 2
    assert count(analysis / "intermediate" / "intermediate_certificates.db", "Certificates") == 8
    assert count(analysis / "root" / "root_certificates.db", "Certificates") == 4
    for db_type, minimum in (("leaf", 20), ("intermediate", 15), ("root", 15)):
        assert len(list((analysis / db_type / "plots").glob("*.png"))) >= minimum

    log = (project / "src" / "app.log").read_text()
    assert "Error parsing line 12" in log
    assert "null server certificate" in log
    # No chart failed (language-independent: the file log names the module of each message)
    assert " - ERROR - plotter_utils.py:" not in log


def test_delete_without_analysis_skips_other_stages(project):
    result = run_cli(project, "--delete_root_db", "--plot_root_results")
    assert result.returncode == 0
    assert not (project / "src" / "analysis" / "root" / "root_certificates.db").exists()
    assert "are skipped" in (project / "src" / "app.log").read_text()


def test_missing_database(project):
    result = run_cli(project, "--root_ocsp_analysis")
    assert result.returncode == 0
    assert "The root database was not found" in (project / "src" / "app.log").read_text()


# ---------------------------------------------------------------- ingestion engine

# 'log0==' is in the list, the other SCT logs are added under the 'unknown' operator while ingesting
LOG_LIST = {"operators": [{"name": "Test Operator", "email": ["ct@example.test"], "logs": [
    {"description": "Test Log", "log_id": "log0==", "key": "k", "url": "https://ct.example.test/", "mmd": 86400,
     "state": {"usable": {"timestamp": "2024-01-01T00:00:00Z"}},
     "temporal_interval": {"start_inclusive": "2024-01-01T00:00:00Z", "end_exclusive": "2025-01-01T00:00:00Z"}}]}]}


def _server(row):
    return row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]


def _variant(row, change):
    row = copy.deepcopy(row)
    change(row)
    return json.dumps(row).encode() + b"\n"


def _scts(*log_ids):
    return [{"log_id": log_id, "timestamp": 1727000000, "version": 0, "signature": "AAAA"} for log_id in log_ids]


@pytest.fixture(scope="module")
def certificates_file(tmp_path_factory):
    """zgrab2 lines: valid and error rows plus every case the workers hand over to the single-row path."""
    rows = Pki().rows(12)
    with_root = rows[0]
    lines = [json.dumps(row).encode() + b"\n" for row in rows]
    lines[3:3] = [
        b"not json\n", b"\n", json.dumps(success_row("null.example.test", None, [])).encode() + b"\n",
        b'{"domain": "x", "data": null}\n',
        # Non-string SCT log id, integer too large for SQLite, chain certificate without raw
        _variant(with_root, lambda row: _server(row)["certificate"]["parsed"]["extensions"].__setitem__(
            "signed_certificate_timestamps", _scts(5))),
        _variant(with_root, lambda row: _server(row)["certificate"]["parsed"].__setitem__("version", 2 ** 64)),
        _variant(with_root, lambda row: _server(row)["chain"][0].pop("raw")),
    ]
    lines[9:9] = [
        # Value that cannot be bound in a column not stored for intermediates, invalid raw, new SCT logs
        _variant(with_root, lambda row: _server(row)["chain"][0]["parsed"].__setitem__("names", ["ok", "\ud800"])),
        _variant(with_root, lambda row: _server(row)["chain"][0].__setitem__("raw", "not base64!!")),
        _variant(with_root, lambda row: _server(row)["certificate"]["parsed"]["extensions"].__setitem__(
            "signed_certificate_timestamps", _scts("new1==", "log1==", "new1==", "log0=="))),
        _variant(with_root, lambda row: _server(row)["certificate"].pop("raw")),
    ]
    path = tmp_path_factory.mktemp("ingestion") / "certs.json"
    path.write_bytes(b"".join(lines) + json.dumps(rows[1]).encode())     # last line without newline
    return path


def _open_targets(directory):
    directory.mkdir()
    targets = []
    for db_type in DatabaseType:
        database = Database(directory / f"{db_type.value}.db", SCHEMA_PATH, db_type)
        database.connect(delete_database=True)
        dao = CertificateDAO(database.conn, db_type)
        with database.transaction():
            dao.insert_sct_logs(LOG_LIST)
        targets.append((database, dao))
    return targets


def _dump(targets):
    """Layout and rows of every table (sqlite_sequence included) of every database; closes the databases."""
    dump = {}
    for database, _ in targets:
        tables = [row[0] for row in database.conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in tables:
            layout = [tuple(row) for row in database.conn.execute(f"PRAGMA table_info({table})")]
            rows = [tuple(row) for row in database.conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2")]
            dump[f"{database.db_type.value}.{table}"] = (layout, rows)
        database.close()
    return dump


# Warnings of the engine only: the parallel processing failed or was restarted
FALLBACK = "Parallel processing failed"
NO_POOL = "Could not start the worker processes"
RESTART = "A worker process terminated abnormally"


def _messages(caplog):
    return [(record.levelno, record.getMessage()) for record in caplog.records
            if record.levelno != logging.INFO and not record.getMessage().startswith((FALLBACK, NO_POOL, RESTART))]


def _run(directory, ingest, prepare=None):
    targets = _open_targets(directory)
    try:
        if prepare is not None:
            prepare(targets)
        with ExitStack() as stack:
            for database, _ in targets:
                stack.enter_context(database.bulk_insert_mode())
            ingest(targets)
        return _dump(targets)
    finally:
        for database, _ in targets:
            database.close()


def _reference(directory, path, max_lines=None, prepare=None):
    """Databases and log messages of the single-row path (the sequential version), line by line."""
    def ingest(targets):
        with open(path, "rb") as reader:
            for line_number, line in enumerate(reader, start=1):
                if max_lines is not None and line_number > max_lines:
                    break
                ingestion.ingest_line(line_number, line, targets)
    return _run(directory, ingest, prepare)


def _engine(directory, path, progress=None, prepare=None):
    return _run(directory, lambda targets: ingestion.ingest_certificates(path, targets, progress or (lambda size: None)),
                prepare)


@pytest.fixture(scope="module")
def reference(certificates_file, tmp_path_factory):
    handler = _ListHandler()
    logging.getLogger().addHandler(handler)
    try:
        dump = _reference(tmp_path_factory.mktemp("reference") / "db", certificates_file)
    finally:
        logging.getLogger().removeHandler(handler)
    return dump, handler.messages


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        if record.levelno != logging.INFO:
            self.messages.append((record.levelno, record.getMessage()))


@pytest.mark.parametrize("chunk_size, workers", [(1 << 30, None), (8192, 2), (1, 1)])
def test_engine_matches_the_single_row_path(certificates_file, reference, tmp_path, monkeypatch, caplog,
                                            chunk_size, workers):
    """Same ids, rows and error messages (in file order) with one block, many blocks and one block per line."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", chunk_size)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", workers)
    progress = []
    dump = _engine(tmp_path / "db", certificates_file, progress.append)

    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert sum(progress) == certificates_file.stat().st_size
    assert any("Error processing line" in message for _, message in reference[1])
    assert any("Error parsing line" in message for _, message in reference[1])


def test_engine_fallbacks_store_the_same_rows(certificates_file, reference, tmp_path, monkeypatch, caplog):
    """A failed block, a staging file that cannot be attached and a failed copy go to the single-row path."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "worker_count", lambda size: 0)    # blocks processed in this process
    monkeypatch.delattr(os, "pread", raising=False)                   # as on Windows
    process, copy_rows = ingestion._ChunkProcessor.process, ingestion._Destination.copy
    calls = {"process": 0, "copy": 0}

    def failing_process(self, index, offset, length):
        calls["process"] += 1
        if index == 1:
            raise RuntimeError("worker failure")
        result = process(self, index, offset, length)
        if index == 2:
            result.staging_path = str(tmp_path / "missing" / "chunk.db")
        return result

    def failing_copy(self, segment):
        calls["copy"] += 1
        if self.spec.db_type is DatabaseType.ROOT and calls["copy"] == 3:
            raise sqlite3.OperationalError("database or disk is full")
        copy_rows(self, segment)

    monkeypatch.setattr(ingestion._ChunkProcessor, "process", failing_process)
    monkeypatch.setattr(ingestion._Destination, "copy", failing_copy)
    dump = _engine(tmp_path / "db", certificates_file)

    assert calls["process"] > 3 and calls["copy"] > 3
    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert FALLBACK in caplog.text


def _lines_in_blocks(path, chunk_size, blocks):
    return sum(path.read_bytes()[offset:offset + length].count(b"\n")
               for offset, length in list(ingestion._chunks(path, chunk_size))[:blocks])


def test_interrupt_keeps_the_stored_blocks_and_stops_the_workers(certificates_file, tmp_path, monkeypatch):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 2)
    stored = []

    def progress(size):
        stored.append(size)
        if len(stored) == 3:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _engine(tmp_path / "db", certificates_file, progress)
    assert multiprocessing.active_children() == []

    # Databases closed by _run() also on interrupt: reopen the stored rows and compare them with the first three blocks
    targets = []
    for db_type in DatabaseType:
        database = Database(tmp_path / "db" / f"{db_type.value}.db", SCHEMA_PATH, db_type)
        database.connect()
        targets.append((database, CertificateDAO(database.conn, db_type)))
    lines = _lines_in_blocks(certificates_file, 8192, 3)
    assert 0 < lines
    assert _dump(targets) == _reference(tmp_path / "reference", certificates_file, max_lines=lines)


def test_pool_that_cannot_start_leaves_the_blocks_to_this_process(certificates_file, reference, tmp_path, monkeypatch,
                                                                  caplog):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 2)

    def no_semaphores(*args, **kwargs):
        raise OSError(38, "Function not implemented")

    monkeypatch.setattr(ingestion, "ProcessPoolExecutor", no_semaphores)
    dump = _engine(tmp_path / "db", certificates_file)

    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert NO_POOL in caplog.text and FALLBACK not in caplog.text


def _no_processes():
    return OSError(errno.EAGAIN, "Resource temporarily unavailable")


@pytest.mark.parametrize("allowed", [0, 1])
def test_workers_that_cannot_start_leave_the_blocks_to_this_process(certificates_file, reference, tmp_path, monkeypatch,
                                                                    caplog, allowed):
    """submit() starts the workers: if one cannot start (e.g. too many processes), this process runs the block code."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 2)
    attempts, start = [], BaseProcess.start

    def failing_start(self):
        attempts.append(self)
        if len(attempts) > allowed:
            raise _no_processes()
        start(self)

    monkeypatch.setattr(BaseProcess, "start", failing_start)
    dump = _engine(tmp_path / "db", certificates_file)

    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert len(attempts) == allowed + 1, "no other start after the first failed one"
    assert f"{NO_POOL} ({_no_processes()!r}): the main process handles the file from line 1." in caplog.text
    assert FALLBACK not in caplog.text
    assert multiprocessing.active_children() == []


def _kill_a_worker(executor):
    next(iter(executor._processes.values())).kill()
    deadline = time.monotonic() + 30
    while not executor._broken:
        assert time.monotonic() < deadline, "the pool is not marked as broken"
        time.sleep(0.01)


@pytest.mark.parametrize("kills", [1, 2])
def test_broken_pool_is_restarted_once(certificates_file, reference, tmp_path, monkeypatch, caplog, kills):
    """A dead worker (e.g. killed for lack of memory) restarts the pool once; after that, the single-row path."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 1)
    executors, killed, stored = [], [], []
    start, apply = ingestion._WorkerPool._start, ingestion._Ingestion.apply

    def recording_start(self):
        executors.append(start(self))
        return executors[-1]

    def killing_apply(self, offset, length, result):
        # The first block received from each pool kills its worker, up to `kills` times
        stored.append((len(executors), isinstance(result, BaseException)))
        if len(killed) < kills and executors[-1] not in killed:
            _kill_a_worker(executors[-1])
            killed.append(executors[-1])
        apply(self, offset, length, result)

    monkeypatch.setattr(ingestion._WorkerPool, "_start", recording_start)
    monkeypatch.setattr(ingestion._Ingestion, "apply", killing_apply)
    dump = _engine(tmp_path / "db", certificates_file)

    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert len(executors) == 2 and caplog.text.count(RESTART) == 1
    assert (2, False) in stored, "the new pool processes the blocks"
    assert (FALLBACK in caplog.text) == (kills == 2)
    assert multiprocessing.active_children() == []


@pytest.mark.parametrize("failure", ["pool", "process"])
def test_workers_that_cannot_restart_leave_the_rest_to_this_process(certificates_file, reference, tmp_path, monkeypatch,
                                                                    caplog, failure):
    """After a worker died, the reason why new workers cannot start is logged and this process stores the rest."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 8192)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 1)
    executors, applied = [], []
    executor_class, start, apply = ingestion.ProcessPoolExecutor, BaseProcess.start, ingestion._Ingestion.apply
    reason = OSError(errno.EMFILE, "Too many open files") if failure == "pool" else _no_processes()

    def failing_executor(*args, **kwargs):
        if executors and failure == "pool":
            raise reason
        executors.append(executor_class(*args, **kwargs))
        return executors[-1]

    def failing_start(self):
        if applied and failure == "process":
            raise _no_processes()
        start(self)

    def killing_apply(self, offset, length, result):
        applied.append(isinstance(result, BaseException))
        if len(applied) == 1:
            _kill_a_worker(executors[0])
        apply(self, offset, length, result)

    monkeypatch.setattr(ingestion, "ProcessPoolExecutor", failing_executor)
    monkeypatch.setattr(BaseProcess, "start", failing_start)
    monkeypatch.setattr(ingestion._Ingestion, "apply", killing_apply)
    dump = _engine(tmp_path / "db", certificates_file)

    assert dump == reference[0]
    assert _messages(caplog) == reference[1]
    assert len(executors) == (1 if failure == "pool" else 2) and caplog.text.count(RESTART) == 1
    first_line = re.search(rf"{NO_POOL} \({re.escape(repr(reason))}\): .* from line (\d+)\.", caplog.text)
    assert first_line is not None and int(first_line.group(1)) > 1
    assert FALLBACK not in caplog.text and not any(applied)
    assert multiprocessing.active_children() == []


def _full_disk_on_log(log_id):
    """SQLite rolls back the whole leaf transaction, as on a full disk, when the SCT log is inserted."""
    def prepare(targets):
        leaf = targets[0][0]
        assert leaf.db_type is DatabaseType.LEAF
        leaf.conn.execute(f"CREATE TEMP TRIGGER full_disk BEFORE INSERT ON main.Logs WHEN NEW.log_id = '{log_id}' "
                          "BEGIN SELECT RAISE(ROLLBACK, 'database or disk is full'); END")
    return prepare


# Lines of unknown_log_file (from 0) that only log an error, and the one with a non-string SCT log id
UNKNOWN_LOG_ERROR_LINES = (4, 7)
UNKNOWN_LOG_LINE = 10


@pytest.fixture(scope="module")
def unknown_log_file(tmp_path_factory):
    """Valid lines and two lines that store nothing before the line inserted by the single-row path (unknown log)."""
    rows = Pki().rows(10)
    lines = [json.dumps(row).encode() + b"\n" for row in rows]
    null_certificate = json.dumps(success_row("null.example.test", None, [])).encode() + b"\n"
    unknown_log = _variant(rows[0], lambda row: _server(row)["certificate"]["parsed"]["extensions"].__setitem__(
        "signed_certificate_timestamps", _scts(7)))
    lines = lines[:4] + [b"not json\n"] + lines[4:6] + [null_certificate] + lines[6:8] + [unknown_log] + lines[8:]
    path = tmp_path_factory.mktemp("unknown_log") / "certs.json"
    path.write_bytes(b"".join(lines))
    return path


def test_whole_transaction_rollback_reports_the_lost_rows(unknown_log_file, tmp_path, monkeypatch, caplog):
    """The rows copied from the block and not yet committed are reported as lost, as by the sequential version.

    The lines that only log an error store nothing, so they are not counted.
    """
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 1 << 30)
    handler = _ListHandler()
    logging.getLogger().addHandler(handler)
    try:
        reference = _reference(tmp_path / "reference", unknown_log_file, prepare=_full_disk_on_log(7))
    finally:
        logging.getLogger().removeHandler(handler)
    caplog.clear()
    dump = _engine(tmp_path / "db", unknown_log_file, prepare=_full_disk_on_log(7))

    assert dump == reference
    assert _messages(caplog) == handler.messages
    assert (logging.ERROR, "Transaction rolled back by SQLite: the rows of 8 uncommitted lines were lost.") in handler.messages


def test_lost_rows_count_from_the_last_commit_of_the_block(unknown_log_file, tmp_path, monkeypatch, caplog):
    """With several blocks, the lost rows are those of the current block before the failing line."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 12000)
    monkeypatch.setattr(ingestion, "worker_count", lambda size: 0)
    lines = unknown_log_file.read_bytes().splitlines(keepends=True)
    starts = [sum(len(line) for line in lines[:index]) for index in range(len(lines))]
    block_start = max(offset for offset, _ in ingestion._chunks(unknown_log_file, 12000)
                      if offset <= starts[UNKNOWN_LOG_LINE])
    block_lines = range(starts.index(block_start), UNKNOWN_LOG_LINE)
    lost = len([index for index in block_lines if index not in UNKNOWN_LOG_ERROR_LINES])
    # The block also has a line that stores nothing before the failing line
    assert 0 < lost < len(block_lines) and lost < UNKNOWN_LOG_LINE - len(UNKNOWN_LOG_ERROR_LINES)

    dump = _engine(tmp_path / "db", unknown_log_file, prepare=_full_disk_on_log(7))
    assert f"the rows of {lost} uncommitted lines were lost" in caplog.text
    stored = len(dump["leaf.Certificates"][1]) + len(dump["leaf.Errors"][1])
    assert stored == len(lines) - len(UNKNOWN_LOG_ERROR_LINES) - 1 - lost


def test_staging_directory_is_next_to_the_databases_and_replaces_leftovers(certificates_file, reference, tmp_path,
                                                                           monkeypatch):
    """Staging directories left by a killed analysis are removed, so they never accumulate."""
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 1 << 30)
    directory = tmp_path / "db"
    created = []
    staging_directory = ingestion._staging_directory

    def staging_directories():
        return {path for path in directory.iterdir() if path.name.startswith("ingestion_staging_")}

    def recording_staging_directory(databases):
        created.append(Path(staging_directory(databases)))
        assert staging_directories() == {directory / "ingestion_staging_notes.txt", created[-1]}
        return str(created[-1])

    def killed_analysis(targets):
        (directory / "ingestion_staging_killed").mkdir()
        (directory / "ingestion_staging_killed" / "chunk_3.db").write_bytes(b"x" * 1000)
        (directory / "ingestion_staging_notes.txt").write_text("not a staging directory")

    monkeypatch.setattr(ingestion, "_staging_directory", recording_staging_directory)
    dump = _engine(directory, certificates_file, prepare=killed_analysis)

    assert dump == reference[0]
    assert len(created) == 1 and created[0].parent == directory
    assert staging_directories() == {directory / "ingestion_staging_notes.txt"}


def test_worker_count(monkeypatch):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 100)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 4)
    assert ingestion.worker_count(100) == 0
    assert ingestion.worker_count(250) == 3
    assert ingestion.worker_count(10_000) == 4
