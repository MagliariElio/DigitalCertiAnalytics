"""Parallel ingestion of the zgrab2 JSON lines into the leaf, intermediate and root databases.

Worker processes parse blocks of lines and write the rows of every database to a staging SQLite file per block,
numbered from 0 in file order. The main process stays the only writer of the real databases: it copies each staging
file with INSERT ... SELECT, offsetting the numbers by the ids already used, so the ids are the same as with one
insert per row. A line whose rows cannot be stored as they are (an error, a value that cannot be bound, an SCT log
id that is not a string) is processed again by the main process with the single-row code, which keeps the per-row
atomicity, the error messages and the ids of the sequential version.
"""
from __future__ import annotations

import io
import itertools
import json
import logging
import multiprocessing
import os
import shutil
import sqlite3
import tempfile
from collections import deque
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Sequence

from bean.certificate import Certificate
from dao.certificate_dao import (CERTIFICATE_PARAM_COLUMNS, ERROR_COLUMNS, EXTENSION_COLUMNS, ISSUER_COLUMNS,
                                 POLICY_COLUMNS, SUBJECT_COLUMNS, CertificateDAO, certificate_params, error_params,
                                 extension_params, issuer_params, policy_params, subject_params)
from db.database import Database, DatabaseType
from utils.chain_utils import find_root_certificate, intermediate_certificates
from utils.process_utils import init_worker_process, sigint_blocked

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Bytes of JSON lines per block processed by a worker
CHUNK_SIZE = 8 << 20

# Worker processes (the main process writes the databases); None: one per CPU but one
MAX_WORKERS: int | None = None

# Blocks in flight per worker, so the workers never wait for the main process to submit work
CHUNKS_IN_FLIGHT_PER_WORKER = 2

# Distinct intermediate/root certificates whose derived data are kept by each worker
CERTIFICATE_CACHE_SIZE = 8192

# Seconds to wait for a terminated worker to exit
_WORKER_EXIT_TIMEOUT = 10.0

# Page size of the staging files: large pages make them faster to write, copy and delete
_STAGING_PAGE_SIZE = 65536

# Staging directories are created next to the databases with this prefix
_STAGING_PREFIX = "ingestion_staging_"

# Times the worker processes are started again after one of them died
_POOL_RESTARTS = 1

_INT64_MIN, _INT64_MAX = -2 ** 63, 2 ** 63 - 1

# Position of issuer_id and subject_id in certificate_params(): computed by the main process from the row number
_ISSUER_ID_INDEX = CERTIFICATE_PARAM_COLUMNS.index("issuer_id")
_SUBJECT_ID_INDEX = CERTIFICATE_PARAM_COLUMNS.index("subject_id")

_PREFIXES = {DatabaseType.LEAF: "l", DatabaseType.INTERMEDIATE: "i", DatabaseType.ROOT: "r"}

# Tables with exactly one row per certificate record: the staging row number of each is the record number k
_RECORD_TABLES = ("Issuers", "Subjects", "Certificates", "Extensions")


# ---------------------------------------------------------------------------------------------- single-row path

def server_certificates(row: dict) -> tuple[dict | None, list[dict]]:
    """Server certificate and chain of a zgrab2 row; (None, []) if the scan failed."""
    tls = row.get("data", {}).get("tls", {})
    if tls.get("status", "") != "success":
        return None, []

    certificates = tls.get("result", {}).get("handshake_log", {}).get("server_certificates", {})
    certificate = certificates.get("certificate", {})
    if certificate is None:
        # None means a failed scan to the inserters: a null certificate makes the row invalid instead
        raise ValueError("null server certificate")
    return certificate, certificates.get("chain", [])


def _insert_leaf(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert the server certificate, or an error row if the scan failed."""
    if certificate is None:
        dao.insert_error_row(row)
    else:
        dao.process_insert_certificate(row, certificate, chain, 0)


def _insert_intermediates(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert every intermediate of the chain with its distance from the leaf."""
    if certificate is None:
        return

    for emitted_up_to, (intermediate, remaining_chain) in enumerate(intermediate_certificates(chain, certificate), start=1):
        dao.process_insert_certificate(row, intermediate, remaining_chain, emitted_up_to)


def _insert_root(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert the root certificate of the chain, if any."""
    if certificate is None:
        return

    root, emitted_up_to = find_root_certificate(chain, certificate)
    if root is not None:
        dao.process_insert_certificate(row, root, [], emitted_up_to)


_ROW_INSERTERS: dict[DatabaseType, Callable[[CertificateDAO, dict, dict | None, list[dict]], None]] = {
    DatabaseType.LEAF: _insert_leaf,
    DatabaseType.INTERMEDIATE: _insert_intermediates,
    DatabaseType.ROOT: _insert_root,
}


def ingest_line(line_number: int, line: bytes, targets: Sequence[tuple[Database, CertificateDAO]]) -> None:
    """Insert one JSON line into every database, each in its own transaction (single-row path)."""
    try:
        row = json.loads(line)
        certificate, chain = server_certificates(row)
    except json.JSONDecodeError:
        logging.error(f"Error parsing line {line_number}: {line.decode('utf-8', errors='replace').strip()}")
        return
    except Exception as e:
        logging.error(f"Error processing line {line_number}: {e}")
        return

    for database, dao in targets:
        try:
            with database.row_transaction():
                _ROW_INSERTERS[database.db_type](dao, row, certificate, chain)
        except Exception as e:
            logging.error(f"Error processing line {line_number}: {e}")


# ---------------------------------------------------------------------------------------------- staging layout

@dataclass(frozen=True)
class _TableSpec:
    """Staging table of one database: row number r, then the stored values.

    The value columns have no type affinity, so each value reaches the real table exactly as it was bound.
    """
    name: str
    values: tuple[str, ...]
    keys: tuple[str, ...] = ()          # extra integer columns (record number k of the certificate)
    not_null: tuple[str, ...] = ()

    def create_sql(self, prefix: str) -> str:
        columns = ["r INTEGER PRIMARY KEY"] + [f"{key} INTEGER NOT NULL" for key in self.keys]
        columns += [f"{value} NOT NULL" if value in self.not_null else value for value in self.values]
        return f"CREATE TABLE {prefix}_{self.name} ({', '.join(columns)})"

    def insert_sql(self, prefix: str) -> str:
        return f"INSERT INTO {prefix}_{self.name} VALUES ({', '.join('?' * (1 + len(self.keys) + len(self.values)))})"


def _staging_columns(count: int) -> tuple[str, ...]:
    return tuple(f"v{i}" for i in range(count))


@dataclass(frozen=True)
class _DatabaseSpec:
    """What a worker needs to build the rows of one database (picklable)."""
    db_type: DatabaseType
    certificate_kept: tuple[int, ...]       # certificate_params() positions stored in 'Certificates'
    certificate_dropped: tuple[int, ...]    # positions of the columns removed for this type: bound but not stored
    log_ids: dict[str, int]                 # SCT logs known when the ingestion starts

    @property
    def prefix(self) -> str:
        return _PREFIXES[self.db_type]

    @property
    def certificate_staged(self) -> tuple[int, ...]:
        return tuple(i for i in self.certificate_kept if i not in (_ISSUER_ID_INDEX, _SUBJECT_ID_INDEX))

    def tables(self) -> list[_TableSpec]:
        tables = [
            _TableSpec("Issuers", _staging_columns(len(ISSUER_COLUMNS))),
            _TableSpec("Subjects", _staging_columns(len(SUBJECT_COLUMNS))),
            _TableSpec("Certificates", _staging_columns(len(self.certificate_staged))),
            _TableSpec("Extensions", _staging_columns(len(EXTENSION_COLUMNS))),
            # log_ref is the Logs id, NULL for the logs still unknown (log_name) when the ingestion started
            _TableSpec("SignedCertificateTimestamps", ("log_ref", "log_name", "v0", "v1", "v2"), ("k",), ("v0", "v1", "v2")),
            _TableSpec("CertificatePolicies", _staging_columns(len(POLICY_COLUMNS)), ("k",)),
        ]
        if self.db_type is DatabaseType.LEAF:
            tables.append(_TableSpec("Errors", _staging_columns(len(ERROR_COLUMNS))))
        return tables


def _bindable(value: object) -> bool:
    """True if sqlite3 can bind the value (JSON values: None, bool, int, float, str, list, dict)."""
    kind = type(value)
    if value is None or kind is bool or kind is float:
        return True
    if kind is int:
        return _INT64_MIN <= value <= _INT64_MAX
    if kind is str:
        if value.isascii():
            return True
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    return False


class _NeedsSingleRowPath(Exception):
    """The line must be inserted by the main process with the single-row code."""


def _read(file: BinaryIO, offset: int, length: int) -> bytes:
    """Bytes of the file from offset (seek and read work everywhere, os.pread only on POSIX)."""
    file.seek(offset)
    return file.read(length)


# ---------------------------------------------------------------------------------------------- worker side

class _DatabaseRows:
    """Rows of one database for one block; row numbers count from 0 in file order."""

    def __init__(self, spec: _DatabaseSpec):
        self.spec = spec
        self.tables = spec.tables()
        self.rows: dict[str, list[tuple]] = {table.name: [] for table in self.tables}
        self.issuers, self.subjects = self.rows["Issuers"], self.rows["Subjects"]
        self.certificates, self.extensions = self.rows["Certificates"], self.rows["Extensions"]
        self.scts, self.policies = self.rows["SignedCertificateTimestamps"], self.rows["CertificatePolicies"]
        self.errors = self.rows.get("Errors", [])
        self.unresolved_logs = 0

    def lengths(self) -> tuple[int, ...]:
        return tuple(len(rows) for rows in self.rows.values())

    def truncate(self, lengths: tuple[int, ...]) -> None:
        for rows, length in zip(self.rows.values(), lengths):
            del rows[length:]

    def counts(self, start: tuple[int, ...], end: tuple[int, ...]) -> dict[str, tuple[int, int]]:
        """Row number range [lo, hi) of every table between two lengths() marks."""
        return {name: (lo, hi) for name, lo, hi in zip(self.rows, start, end)}


class _LogCapture(logging.Handler):
    """Collects the log records of a block, re-emitted by the main process in file order."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list = []

    def emit(self, record: logging.LogRecord) -> None:
        # As QueueHandler.prepare(): the message is formatted here, so the record pickles without its arguments
        record.msg = record.getMessage()
        record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        self.records.append(record)


@dataclass
class _Segment:
    """Consecutive lines of a block copied with one INSERT ... SELECT per table."""
    first_line: int                         # index of the first line in the block
    line_count: int
    byte_start: int                         # offsets in the block
    byte_end: int
    ranges: dict[DatabaseType, dict[str, tuple[int, int]]]
    unresolved_logs: dict[DatabaseType, int]
    logs: list                              # LogRecord, or (kind, line index, text) for the line errors

    @property
    def stored_lines(self) -> int:
        """Lines counted by Database.row_transaction() in the single-row path: all but the line errors."""
        return self.line_count - sum(1 for entry in self.logs if type(entry) is tuple)


@dataclass
class _ChunkResult:
    line_count: int
    byte_count: int
    staging_path: str | None
    items: list = field(default_factory=list)   # _Segment or (line index, line bytes) for the single-row path


class _ChunkProcessor:
    """Builds the rows of a block of lines for every database and writes them to a staging file."""

    def __init__(self, path: str, specs: Sequence[_DatabaseSpec], staging_dir: str, capture: _LogCapture):
        self._file = open(path, 'rb')
        self._specs = specs
        self._staging_dir = staging_dir
        self._capture = capture
        self._cache: dict[str, Certificate] = {}
        self._debug = logging.getLogger().isEnabledFor(logging.DEBUG)

    def close(self) -> None:
        self._file.close()

    def process(self, index: int, offset: int, length: int) -> _ChunkResult:
        data = _read(self._file, offset, length)
        excluded: set[int] = set()
        while True:
            builder = _ChunkBuilder(self, data, excluded)
            staging_path = os.path.join(self._staging_dir, f"chunk_{index}.db")
            failing = builder.write_staging(staging_path)
            if not failing:
                return builder.result(staging_path)
            # Lines whose values cannot be stored go to the single-row path: the block is rebuilt without them
            excluded |= failing

    def certificate(self, raw: object, db_type: DatabaseType) -> Certificate:
        """Certificate of an intermediate or root raw, shared by the rows that repeat it."""
        if db_type is DatabaseType.LEAF or type(raw) is not str:
            return Certificate(raw)
        certificate = self._cache.get(raw)
        if certificate is None:
            certificate = Certificate(raw)
            # An invalid certificate logs its parsing error on every row, so it is not shared
            if certificate.cert is not None:
                if len(self._cache) >= CERTIFICATE_CACHE_SIZE:
                    del self._cache[next(iter(self._cache))]
                self._cache[raw] = certificate
        return certificate


class _ChunkBuilder:
    """Rows and segments of one block."""

    def __init__(self, processor: _ChunkProcessor, data: bytes, excluded: set[int]):
        self._processor = processor
        self._data = data
        self._excluded = excluded
        self._databases = [_DatabaseRows(spec) for spec in processor._specs]
        self._logs = processor._capture.records
        self._logs.clear()
        self._line_marks: list[tuple[int, list[tuple[int, ...]]]] = []
        self.items: list = []
        self.line_count = 0
        self._build()

    # --------------------------------------------------------------- rows

    def _build(self) -> None:
        segment_start = None
        position = 0
        for index, line in enumerate(io.BytesIO(self._data)):
            if segment_start is None:
                segment_start = (index, position, self._marks(), len(self._logs))
            if index in self._excluded or not self._add_line(index, line):
                self._close_segment(segment_start, index, position)
                self.items.append((index, line))
                segment_start = None
            position += len(line)
            self.line_count = index + 1
        if segment_start is not None:
            self._close_segment(segment_start, self.line_count, position)

    def _marks(self) -> list[tuple[int, ...]]:
        return [database.lengths() for database in self._databases]

    def _close_segment(self, start: tuple, end_line: int, end_position: int) -> None:
        first_line, start_position, start_marks, start_logs = start
        if end_line == first_line:
            return
        end_marks = self._marks()
        self.items.append(_Segment(
            first_line=first_line, line_count=end_line - first_line, byte_start=start_position, byte_end=end_position,
            ranges={database.spec.db_type: database.counts(start_mark, end_mark)
                    for database, start_mark, end_mark in zip(self._databases, start_marks, end_marks)},
            unresolved_logs={database.spec.db_type: database.unresolved_logs for database in self._databases},
            logs=self._logs[start_logs:],
        ))
        for database in self._databases:
            database.unresolved_logs = 0

    def _add_line(self, index: int, line: bytes) -> bool:
        """Add the rows of a line; False if it needs the single-row path (nothing is added)."""
        try:
            row = json.loads(line)
            certificate, chain = server_certificates(row)
        except json.JSONDecodeError:
            self._logs.append(("parse", index, line.decode('utf-8', errors='replace').strip()))
            return True
        except Exception as e:
            self._logs.append(("row", index, str(e)))
            return True

        marks = self._marks()
        log_count = len(self._logs)
        unresolved = [database.unresolved_logs for database in self._databases]
        try:
            for database in self._databases:
                self._add_rows(database, row, certificate, chain)
        except Exception:
            for database, mark, count in zip(self._databases, marks, unresolved):
                database.truncate(mark)
                database.unresolved_logs = count
            del self._logs[log_count:]
            return False
        self._line_marks.append((index, marks))
        return True

    def _add_rows(self, database: _DatabaseRows, row: dict, certificate: dict | None, chain: list[dict]) -> None:
        """Same rows, in the same order, as the inserters of the single-row path."""
        db_type = database.spec.db_type
        if db_type is DatabaseType.LEAF:
            if certificate is None:
                database.errors.append((len(database.errors), *error_params(row)))
                if self._processor._debug:
                    logging.debug("Error row inserted for domain: %s", row.get("domain", ""))
            else:
                self._add_certificate(database, row, certificate, chain, 0)
        elif certificate is None:
            return
        elif db_type is DatabaseType.INTERMEDIATE:
            for emitted_up_to, (intermediate, remaining) in enumerate(intermediate_certificates(chain, certificate), start=1):
                self._add_certificate(database, row, intermediate, remaining, emitted_up_to)
        else:
            root, emitted_up_to = find_root_certificate(chain, certificate)
            if root is not None:
                self._add_certificate(database, row, root, [], emitted_up_to)

    def _add_certificate(self, database: _DatabaseRows, row: dict, certificate: dict, chain: list[dict],
                         emitted_up_to: int) -> None:
        """Rows of CertificateDAO.process_insert_certificate(), numbered by the certificate record number k."""
        spec = database.spec
        parsed = certificate.get("parsed", {})
        raw = certificate.get("raw") if spec.db_type is DatabaseType.LEAF else certificate["raw"]
        digital_certificate = self._processor.certificate(raw, spec.db_type)
        extensions = parsed.get("extensions", {})

        k = len(database.certificates)
        database.issuers.append((k, *issuer_params(parsed, chain)))
        database.subjects.append((k, *subject_params(parsed, digital_certificate)))
        params = certificate_params(row, certificate, parsed, chain, digital_certificate, spec.db_type, None, None,
                                    emitted_up_to)
        # The columns removed for this type are not stored, but a value that could not be bound fails the row
        if not all(_bindable(params[i]) for i in spec.certificate_dropped):
            raise _NeedsSingleRowPath()
        database.certificates.append((k, *[params[i] for i in spec.certificate_staged]))
        if self._processor._debug:
            logging.debug("Certificate inserted: %s", parsed.get("serial_number", ""))
        database.extensions.append((k, *extension_params(extensions, digital_certificate)))
        self._add_scts(database, k, extensions)

        policies = policy_params(digital_certificate)
        if policies is not None:
            for policy in policies:
                database.policies.append((len(database.policies), k, *policy))

    @staticmethod
    def _add_scts(database: _DatabaseRows, k: int, extensions: dict) -> None:
        log_ids = database.spec.log_ids
        for sct in extensions.get("signed_certificate_timestamps", []):
            log_id = sct.get("log_id", "")
            if type(log_id) is not str:
                # The single-row path looks it up with the SQL comparison rules
                raise _NeedsSingleRowPath()
            log_ref = log_ids.get(log_id)
            if log_ref is None:
                database.unresolved_logs += 1
            database.scts.append((len(database.scts), k, log_ref, None if log_ref is not None else log_id,
                                  sct.get("timestamp", ""), sct.get("version", ""), sct.get("signature", "")))

    # --------------------------------------------------------------- staging file

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        for database in self._databases:
            for table in database.tables:
                conn.execute(table.create_sql(database.spec.prefix))

    def _insert(self, conn: sqlite3.Connection, slices: list[tuple[int, ...]] | None = None,
                ends: list[tuple[int, ...]] | None = None) -> None:
        for position, database in enumerate(self._databases):
            for column, table in enumerate(database.tables):
                rows = database.rows[table.name]
                if slices is not None:
                    rows = rows[slices[position][column]:ends[position][column]]
                if rows:
                    conn.executemany(table.insert_sql(database.spec.prefix), rows)

    def write_staging(self, path: str) -> set[int]:
        """Write the rows to the staging file; return the lines whose values cannot be stored, if any."""
        if os.path.exists(path):
            os.remove(path)
        conn = sqlite3.connect(path, isolation_level=None)
        try:
            conn.execute(f"PRAGMA page_size = {_STAGING_PAGE_SIZE}")
            conn.execute("PRAGMA journal_mode = OFF")
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("BEGIN")
            self._create_tables(conn)
            self._insert(conn)
            conn.execute("COMMIT")
            return set()
        except Exception as e:
            failing = self._failing_lines()
            if not failing:
                raise e
            return failing
        finally:
            conn.close()

    def _failing_lines(self) -> set[int]:
        """Lines whose rows fail to bind or violate a NOT NULL constraint, tested one at a time."""
        conn = sqlite3.connect(":memory:", isolation_level=None)
        try:
            self._create_tables(conn)
            failing = set()
            ends = [marks for _, marks in self._line_marks[1:]] + [self._marks()]
            for (index, marks), end in zip(self._line_marks, ends):
                conn.execute("BEGIN")
                try:
                    self._insert(conn, marks, end)
                except Exception:
                    failing.add(index)
                conn.execute("ROLLBACK")
            return failing
        finally:
            conn.close()

    def result(self, staging_path: str) -> _ChunkResult:
        return _ChunkResult(line_count=self.line_count, byte_count=len(self._data), staging_path=staging_path,
                            items=self.items)


_WORKER: _ChunkProcessor | None = None


def _init_worker(path: str, specs: Sequence[_DatabaseSpec], log_level: int, staging_dir: str, parent_pid: int) -> None:
    global _WORKER
    init_worker_process(parent_pid)
    capture = _LogCapture()
    root = logging.getLogger()
    root.handlers = [capture]
    root.setLevel(log_level)
    _WORKER = _ChunkProcessor(path, specs, staging_dir, capture)


def _process_chunk(index: int, offset: int, length: int) -> _ChunkResult:
    return _WORKER.process(index, offset, length)


# ---------------------------------------------------------------------------------------------- main process side

class _Destination:
    """A database being populated: copies the staging rows with the next free ids."""

    def __init__(self, database: Database, dao: CertificateDAO, spec: _DatabaseSpec):
        self.database = database
        self.conn = database.conn
        self.dao = dao
        self.spec = spec
        self.tables = [table.name for table in spec.tables()]
        self.next_ids: dict[str, int] = {}
        self.log_ids: dict[str, int] = {}
        self._copy_sql = self._build_copy_sql()
        self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS ingestion_log_refs (r INTEGER PRIMARY KEY, log_ref)")
        self.refresh()

    def _build_copy_sql(self) -> dict[str, str]:
        p = f"chunk.{self.spec.prefix}"
        staged = [CERTIFICATE_PARAM_COLUMNS[i] for i in self.spec.certificate_staged]

        def values(count: int) -> str:
            return ", ".join(f"v{i}" for i in range(count))

        where = "WHERE r >= ? AND r < ?"
        sql = {
            "Issuers": f"INSERT INTO main.Issuers (issuer_id, {', '.join(ISSUER_COLUMNS)}) "
                       f"SELECT r + ?, {values(len(ISSUER_COLUMNS))} FROM {p}_Issuers {where}",
            "Subjects": f"INSERT INTO main.Subjects (subject_id, {', '.join(SUBJECT_COLUMNS)}) "
                        f"SELECT r + ?, {values(len(SUBJECT_COLUMNS))} FROM {p}_Subjects {where}",
            "Certificates": f"INSERT INTO main.Certificates (certificate_id, issuer_id, subject_id, {', '.join(staged)}, "
                            f"ocsp_check) SELECT r + ?, r + ?, r + ?, {values(len(staged))}, 'No Request Done' "
                            f"FROM {p}_Certificates {where}",
            "Extensions": f"INSERT INTO main.Extensions (extension_id, certificate_id, {', '.join(EXTENSION_COLUMNS)}, "
                          f"crl_revocation_status) SELECT r + ?, r + ?, {values(len(EXTENSION_COLUMNS))}, 'No Request Done' "
                          f"FROM {p}_Extensions {where}",
            "SignedCertificateTimestamps":
                f"INSERT INTO main.SignedCertificateTimestamps (id, certificate_id, log_id, timestamp, version, signature) "
                f"SELECT s.r + ?, s.k + ?, COALESCE(s.log_ref, (SELECT f.log_ref FROM temp.ingestion_log_refs AS f "
                f"WHERE f.r = s.r)), s.v0, s.v1, s.v2 FROM {p}_SignedCertificateTimestamps AS s WHERE s.r >= ? AND s.r < ?",
            "CertificatePolicies": f"INSERT INTO main.CertificatePolicies (policy_id, extension_id, "
                                   f"{', '.join(POLICY_COLUMNS)}) SELECT r + ?, k + ?, {values(len(POLICY_COLUMNS))} "
                                   f"FROM {p}_CertificatePolicies {where}",
            "Errors": f"INSERT INTO main.Errors (error_id, {', '.join(ERROR_COLUMNS)}) "
                      f"SELECT r + ?, {values(len(ERROR_COLUMNS))} FROM {p}_Errors {where}",
        }
        return {name: sql[name] for name in self.tables}

    def refresh(self) -> None:
        """Read the next free id of every table and the known SCT logs (after the single-row path ran)."""
        sequences = dict(self.conn.execute("SELECT name, seq FROM sqlite_sequence").fetchall())
        for table in self.tables:
            max_id = self.conn.execute(f"SELECT COALESCE(MAX(rowid), 0) FROM main.{table}").fetchone()[0]
            self.next_ids[table] = max(max_id, sequences.get(table) or 0) + 1
        self.log_ids = self.dao.log_row_ids()

    def _resolve_logs(self, lo: int, hi: int) -> None:
        """Logs id of the SCTs whose log was unknown to the workers, inserting the missing logs in file order."""
        table = f"chunk.{self.spec.prefix}_SignedCertificateTimestamps"
        rows = self.conn.execute(f"SELECT r, log_name FROM {table} WHERE r >= ? AND r < ? AND log_ref IS NULL ORDER BY r",
                                 (lo, hi)).fetchall()
        references = []
        for r, log_name in rows:
            log_ref = self.log_ids.get(log_name)
            if log_ref is None:
                log_ref = self.dao.insert_unknown_log(log_name)
                self.log_ids[log_name] = log_ref
            references.append((r, log_ref))
        self.conn.execute("DELETE FROM temp.ingestion_log_refs")
        self.conn.executemany("INSERT INTO temp.ingestion_log_refs VALUES (?, ?)", references)

    def copy(self, segment: _Segment) -> None:
        """Copy the rows of a segment; the caller rolls back on error."""
        ranges = segment.ranges[self.spec.db_type]
        record_lo = ranges["Certificates"][0]
        if segment.unresolved_logs[self.spec.db_type]:
            self._resolve_logs(*ranges["SignedCertificateTimestamps"])
        offsets = {name: self.next_ids[name] - ranges[name][0] for name in self.tables}
        # Foreign keys point to the record number k, the same in Issuers, Subjects, Certificates and Extensions
        record_offsets = {name: self.next_ids[name] - record_lo for name in _RECORD_TABLES}
        parameters = {
            "Certificates": (offsets["Certificates"], record_offsets["Issuers"], record_offsets["Subjects"]),
            "Extensions": (offsets["Extensions"], record_offsets["Certificates"]),
            "SignedCertificateTimestamps": (offsets["SignedCertificateTimestamps"], record_offsets["Certificates"]),
            "CertificatePolicies": (offsets["CertificatePolicies"], record_offsets["Extensions"]),
        }
        for name in self.tables:
            lo, hi = ranges[name]
            if hi > lo:
                self.conn.execute(self._copy_sql[name], (*parameters.get(name, (offsets[name],)), lo, hi))

    def advance(self, segment: _Segment) -> None:
        for name, (lo, hi) in segment.ranges[self.spec.db_type].items():
            self.next_ids[name] += hi - lo

    def begin(self) -> None:
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")


class _Ingestion:
    """Main process side: submits the blocks, copies their rows in file order and handles the fallbacks."""

    def __init__(self, path: Path, targets: Sequence[tuple[Database, CertificateDAO]], on_progress: Callable[[int], None]):
        self.path = path
        self.targets = list(targets)
        self.on_progress = on_progress
        self.destinations = [_Destination(database, dao, _database_spec(database, dao)) for database, dao in self.targets]
        self.next_line = 1
        self._file = open(path, 'rb')
        self._attached: list[_Destination] = []
        self._fallback_logged = False

    def close(self) -> None:
        try:
            self._detach()
        finally:
            for destination in self.destinations:
                destination.conn.execute("DROP TABLE IF EXISTS temp.ingestion_log_refs")
            self._file.close()

    @property
    def specs(self) -> list[_DatabaseSpec]:
        return [destination.spec for destination in self.destinations]

    # --------------------------------------------------------------- blocks

    def apply(self, offset: int, length: int, result: _ChunkResult | BaseException) -> None:
        """Store a processed block (or process it here with the single-row path if its worker failed)."""
        if not isinstance(result, BaseException):
            try:
                self._attach(result.staging_path)
            except Exception as e:
                _remove_file(result.staging_path)
                result = e
        if isinstance(result, BaseException):
            self._log_fallback(result)
            self.next_line += self._single_row_path(self.next_line, _read(self._file, offset, length))
            self.on_progress(length)
            return

        try:
            for item in result.items:
                if isinstance(item, _Segment):
                    self._apply_segment(offset, item)
                else:
                    index, line = item
                    self._single_row_path(self.next_line + index, line)
        finally:
            self._detach()
            _remove_file(result.staging_path)
        self.next_line += result.line_count
        self.on_progress(result.byte_count)

    def _log_fallback(self, error: BaseException) -> None:
        if not self._fallback_logged:
            logging.warning(f"Parallel processing failed ({error!r}): the affected lines are processed by the main "
                            "process.")
            self._fallback_logged = True

    def _apply_segment(self, offset: int, segment: _Segment) -> None:
        for destination in self.destinations:
            destination.begin()
            destination.conn.execute("SAVEPOINT ingestion_segment")
        try:
            for destination in self.destinations:
                destination.copy(segment)
        except BaseException as e:
            self._rollback_segment()
            if not isinstance(e, Exception):
                raise
            # e.g. disk full: the single-row path stores what it can and logs every failed row
            data = _read(self._file, offset + segment.byte_start, segment.byte_end - segment.byte_start)
            self._single_row_path(self.next_line + segment.first_line, data)
            return

        for destination in self.destinations:
            destination.conn.execute("RELEASE SAVEPOINT ingestion_segment")
            destination.advance(segment)
            # Counted as row_transaction() does, which reports them if SQLite rolls back the whole transaction
            destination.database.pending_rows += segment.stored_lines
        self._emit_logs(segment.logs)

    def _rollback_segment(self) -> None:
        for destination in self.destinations:
            if destination.conn.in_transaction:
                destination.conn.execute("ROLLBACK TO SAVEPOINT ingestion_segment")
                destination.conn.execute("RELEASE SAVEPOINT ingestion_segment")
            else:
                # SQLite already rolled back the whole transaction (e.g. disk full), as in Database.row_transaction()
                _log_lost_rows(destination.database)

    def _emit_logs(self, logs: list) -> None:
        for entry in logs:
            if isinstance(entry, logging.LogRecord):
                logging.getLogger(entry.name).handle(entry)
                continue
            kind, index, text = entry
            line_number = self.next_line + index
            if kind == "parse":
                logging.error(f"Error parsing line {line_number}: {text}")
            else:
                logging.error(f"Error processing line {line_number}: {text}")

    def _single_row_path(self, first_line: int, data: bytes) -> int:
        """Insert the lines one at a time as the sequential version did; return the number of lines."""
        count = 0
        try:
            for count, line in enumerate(io.BytesIO(data), start=1):
                ingest_line(first_line + count - 1, line, self.targets)
        finally:
            for destination in self.destinations:
                destination.refresh()
        return count

    # --------------------------------------------------------------- staging attachment

    def _attach(self, staging_path: str) -> None:
        """Attach the staging file to every database; on error none stays attached."""
        try:
            for destination in self.destinations:
                # ATTACH and DETACH are not allowed inside a transaction
                destination.conn.commit()
                destination.database.pending_rows = 0
                destination.conn.execute("ATTACH DATABASE ? AS chunk", (staging_path,))
                self._attached.append(destination)
                destination.conn.execute("DELETE FROM temp.ingestion_log_refs")
        except BaseException:
            self._detach()
            raise

    def _detach(self) -> None:
        """Commit the copied rows and detach the staging file."""
        while self._attached:
            destination = self._attached.pop()
            try:
                destination.conn.commit()
            except Exception as e:
                # e.g. disk full: the rows of the block are lost for this database, as in Database.row_transaction()
                logging.error(f"Transaction failed: {e}")
                _log_lost_rows(destination.database)
                destination.conn.rollback()
                destination.refresh()
            destination.database.pending_rows = 0
            destination.conn.execute("DETACH DATABASE chunk")

    # --------------------------------------------------------------- runs

    def run_sequential(self, chunks: Iterator[tuple[int, int]], staging_dir: str) -> None:
        """Process the blocks in this process (small files), with the same rows and logs as the workers."""
        capture = _LogCapture()
        processor = _ChunkProcessor(str(self.path), self.specs, staging_dir, capture)
        root = logging.getLogger()
        try:
            for index, (offset, length) in enumerate(chunks):
                handlers = root.handlers[:]
                root.handlers = [capture]
                try:
                    result = processor.process(index, offset, length)
                except Exception as e:
                    result = e
                finally:
                    root.handlers = handlers
                self.apply(offset, length, result)
        finally:
            processor.close()

    def run_parallel(self, chunks: Iterator[tuple[int, int]], staging_dir: str, workers: int) -> None:
        """Process the blocks in worker processes and store them here in file order.

        If a worker process cannot be started, at the beginning or after a restart (e.g. no working sem_open(), fork()
        failing with EAGAIN), every worker is stopped, also those already started, and run_sequential() processes the
        blocks not stored yet.
        """
        pending: deque[_Block] = deque()
        try:
            self._run_pool(chunks, staging_dir, workers, pending)
            return
        except _WorkersNotStarted as e:
            logging.warning(f"Could not start the worker processes ({e.__cause__!r}): the main process handles the file "
                            f"from line {self.next_line}.")
        self.run_sequential(itertools.chain(((block.offset, block.length) for block in pending), chunks), staging_dir)

    def _run_pool(self, chunks: Iterator[tuple[int, int]], staging_dir: str, workers: int, pending: deque[_Block]) -> None:
        pool = _WorkerPool(workers, (str(self.path), self.specs, logging.getLogger().getEffectiveLevel(), staging_dir,
                                     os.getpid()))
        try:
            for index, (offset, length) in enumerate(chunks):
                pending.append(_Block(index, offset, length))
                pool.submit(pending[-1])
                if len(pending) >= workers * CHUNKS_IN_FLIGHT_PER_WORKER:
                    self._apply_next(pending, pool)
            while pending:
                self._apply_next(pending, pool)
        except BaseException:
            pool.stop()
            raise
        finally:
            pool.shutdown()

    def _apply_next(self, pending: deque[_Block], pool: _WorkerPool) -> None:
        # The block stays pending until its result is known, so run_sequential() takes it if the workers cannot start
        block = pending[0]
        result = self._result(block, pending, pool)
        pending.popleft()
        self.apply(block.offset, block.length, result)

    def _result(self, block: _Block, pending: deque[_Block], pool: _WorkerPool) -> _ChunkResult | BaseException:
        try:
            return block.future.result()
        except BrokenProcessPool as e:
            # A worker died (e.g. killed for lack of memory): new workers process the blocks without a result, once
            if not pool.can_restart():
                return e
            logging.warning(f"A worker process terminated abnormally ({e!r}): the worker processes are restarted.")
            pool.restart()
            for retried in pending:
                if not _succeeded(retried.future):
                    pool.submit(retried)
            return self._result(block, pending, pool)
        except Exception as e:
            return e


@dataclass
class _Block:
    """A block submitted to the workers."""
    index: int
    offset: int
    length: int
    future: Future | None = None


class _WorkersNotStarted(Exception):
    """The worker processes cannot be started; the reason is the cause."""


class _WorkerPool:
    """Worker processes, started again once if one of them dies."""

    def __init__(self, workers: int, initargs: tuple):
        self._workers = workers
        self._initargs = initargs
        self._restarts = _POOL_RESTARTS
        self._executor = self._start()

    def _start(self) -> ProcessPoolExecutor:
        try:
            with sigint_blocked():
                return ProcessPoolExecutor(max_workers=self._workers, mp_context=multiprocessing.get_context("spawn"),
                                           initializer=_init_worker, initargs=self._initargs)
        except Exception as e:
            raise _WorkersNotStarted() from e

    def submit(self, block: _Block) -> None:
        """Set the future of the block; _WorkersNotStarted if a worker process cannot be started."""
        try:
            # submit() starts the worker processes on demand
            with sigint_blocked():
                block.future = self._executor.submit(_process_chunk, block.index, block.offset, block.length)
        except BrokenProcessPool as e:
            # The block is processed again by new workers or by the main process
            block.future = Future()
            block.future.set_exception(e)
        except Exception as e:
            raise _WorkersNotStarted() from e

    def can_restart(self) -> bool:
        return self._restarts > 0

    def restart(self) -> None:
        """Replace the broken workers; _WorkersNotStarted if the new ones cannot be started."""
        self._restarts -= 1
        # The old workers must be gone before others write the staging files of the same blocks
        self.stop()
        self.shutdown()
        self._executor = self._start()

    def stop(self) -> None:
        _stop_workers(self._executor)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)


def _succeeded(future: Future) -> bool:
    return future.done() and not future.cancelled() and future.exception() is None


def _log_lost_rows(database: Database) -> None:
    """Log the rows lost when SQLite rolled back the whole transaction, as Database.row_transaction() does."""
    logging.error(f"Transaction rolled back by SQLite: the rows of {database.pending_rows} uncommitted lines were lost.")
    database.pending_rows = 0


def _remove_file(path: str | None) -> None:
    if path is None:
        return
    for name in (path, f"{path}-journal"):
        try:
            os.remove(name)
        except FileNotFoundError:
            pass


def _stop_workers(executor: ProcessPoolExecutor) -> None:
    """Terminate the workers now instead of letting them finish their block, and wait for them to exit."""
    # shutdown() forgets the processes: read them first
    processes = list((getattr(executor, "_processes", None) or {}).values())
    terminate = getattr(executor, "terminate_workers", None)     # Python 3.14+
    if terminate is not None:
        terminate()
    else:
        executor.shutdown(wait=False, cancel_futures=True)
        for process in processes:
            process.terminate()
    for process in processes:
        process.join(_WORKER_EXIT_TIMEOUT)


def _database_spec(database: Database, dao: CertificateDAO) -> _DatabaseSpec:
    return _DatabaseSpec(db_type=database.db_type, certificate_kept=dao.certificate_kept,
                         certificate_dropped=dao.certificate_dropped, log_ids=dao.log_row_ids())


def _chunks(path: Path, chunk_size: int) -> Iterator[tuple[int, int]]:
    """(offset, length) of consecutive blocks of whole lines of about chunk_size bytes."""
    with open(path, 'rb') as reader:
        size = os.fstat(reader.fileno()).st_size
        start = 0
        while start < size:
            reader.seek(min(start + chunk_size, size) - 1)
            reader.readline()
            end = min(max(reader.tell(), start + 1), size)
            yield start, end - start
            start = end


def _staging_directory(databases: Sequence[Database]) -> str:
    """New staging directory next to the first database, after removing the old ones next to every database.

    Each analysis recreates its databases, so a staging directory found next to them was left by an analysis that was
    killed (SIGKILL, SIGTERM): unlike in the system temporary directory, shared with other analyses, it can be removed
    without checking its owner process (which os.kill(pid, 0) cannot do on Windows), and leftovers never accumulate.
    """
    directories = dict.fromkeys(os.path.dirname(database.db_path) for database in databases)
    for directory in directories:
        with os.scandir(directory) as entries:
            stale = [entry.path for entry in entries
                     if entry.name.startswith(_STAGING_PREFIX) and entry.is_dir(follow_symlinks=False)]
        for leftover in stale:
            shutil.rmtree(leftover, ignore_errors=True)
    return tempfile.mkdtemp(prefix=_STAGING_PREFIX, dir=next(iter(directories), None))


def worker_count(file_size: int) -> int:
    """Worker processes for a file: none (0) when it fits in one block."""
    blocks = -(-file_size // CHUNK_SIZE)
    if blocks <= 1:
        return 0
    available = MAX_WORKERS if MAX_WORKERS is not None else max(1, (os.cpu_count() or 2) - 1)
    return max(0, min(available, blocks))


def ingest_certificates(path: Path, targets: Sequence[tuple[Database, CertificateDAO]],
                        on_progress: Callable[[int], None]) -> None:
    """Insert every line of the zgrab2 file into the target databases (already in bulk insert mode)."""
    staging_dir = _staging_directory([database for database, _ in targets])
    try:
        ingestion = _Ingestion(path, targets, on_progress)
        try:
            workers = worker_count(os.path.getsize(path))
            chunks = _chunks(path, CHUNK_SIZE)
            if workers == 0:
                ingestion.run_sequential(chunks, staging_dir)
            else:
                logging.info(f"Processing the file in parallel with {workers} worker processes.")
                ingestion.run_parallel(chunks, staging_dir, workers)
        finally:
            ingestion.close()
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
