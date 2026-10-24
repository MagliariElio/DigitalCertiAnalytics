"""Parallel ingestion of the zgrab2 JSON lines into the leaf, intermediate and root databases.

Worker processes parse blocks of lines and write the rows of every database to a staging SQLite file per block. A
worker computes every value of every certificate occurrence, as the single-row code does (so the same messages are
logged), and stages each distinct raw, issuer, policy, policy set, certificate and lookup value once per block, under
a local number in order of first appearance, with the digest of its values.

The main process stays the only writer of the real databases. For each block, in file order, it maps every local
number to an id through a keys file (digest -> id) and inserts only the rows not seen before, numbered after the ids
already used: ids follow the first appearance in the file, exactly as when every line is inserted by the single-row
code. A line whose rows cannot be stored as they are (an error, a value that cannot be bound, an SCT log id that is
not a string) is processed by the main process with the single-row code, which keeps the per-row atomicity, the error
messages and the ids of the sequential version.
"""
from __future__ import annotations

import dataclasses
import hashlib
import io
import itertools
import json
import logging
import marshal
import multiprocessing
import os
import shutil
import sqlite3
import tempfile
import time
from collections import deque
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Sequence

from analysis.input_file import BlockSpec, InputSource, open_source, read_block
from bean.certificate import Certificate
from dao.certificate_dao import (ERROR_STORED, INLINE, ISSUER_COLUMNS, NUMERIC, TEXT, CertificateDAO, StorageLayout,
                                 certificate_key, certificate_params, error_params, extension_params, issuer_key,
                                 issuer_params, policy_key, policy_params, policy_set_key, raw_key, stored_lookup_value,
                                 subject_params)
from db.database import Database, DatabaseType
from db.raw_codec import DICTIONARY_SAMPLES, RawCodec, canonical_der, train_dictionary
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

# Text read from the start of the input to train the dictionary of the raw certificates
DICTIONARY_SAMPLE_BYTES = 64 << 20

# Seconds between the checks of a worker for the raw dictionary file
_DICTIONARY_POLL_SECONDS = 0.002

# Seconds to wait for a terminated worker to exit
_WORKER_EXIT_TIMEOUT = 10.0

# Page size of the staging files: large pages make them faster to write, copy and delete
_STAGING_PAGE_SIZE = 65536

# Page size and page cache (KiB, as a negative cache_size) of the keys file
_KEYS_PAGE_SIZE = 4096
# Keys kept in memory per database before they are moved to the keys file (about 40 bytes each)
RECENT_KEYS = 1_000_000
_KEYS_CACHE_KIB = 65536

# Staging directories are created next to the databases with this prefix
_STAGING_PREFIX = "ingestion_staging_"

# Times the worker processes are started again after one of them died
_POOL_RESTARTS = 1

_INT64_MIN, _INT64_MAX = -2 ** 63, 2 ** 63 - 1

_PREFIXES = {DatabaseType.LEAF: "l", DatabaseType.INTERMEDIATE: "i", DatabaseType.ROOT: "r"}

# Deduplicated kinds: local name, key table, main table, id column
_KEYED = (("Raw", "RawKeys", "RawCertificates", "raw_id"), ("Policy", "PolicyKeys", "PolicyData", "policy_id"),
          ("PolicySet", "PolicySetKeys", "PolicySets", "policy_set_id"), ("Issuer", "IssuerKeys", "IssuerData", "issuer_id"),
          ("Cert", "CertificateKeys", "CertificateData", "certificate_id"))
_LOOKUPS = (("Text", "TextValues"), ("Num", "NumericValues"))
_LOCAL_KINDS = ("Text", "Num", "Combo") + tuple(kind for kind, _, _, _ in _KEYED)
_KEYED_KINDS = frozenset(kind for kind, _, _, _ in _KEYED)
# Tables numbered by row: main table, id column
_ROW_TABLES = {"Occ": ("Occurrences", "occurrence_id"), "Errors": ("ErrorData", "error_id")}


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

def _columns(prefix: str, count: int) -> tuple[str, ...]:
    return tuple(f"{prefix}{i}" for i in range(count))


@dataclass(frozen=True)
class _DatabaseSpec:
    """What a worker needs to build the rows of one database (picklable)."""
    db_type: DatabaseType
    layout: StorageLayout
    log_ids: dict[str, int]                 # SCT logs known when the ingestion starts
    raw_dictionary: bytes | None = None     # zstd dictionary of the raw certificates

    @property
    def prefix(self) -> str:
        return _PREFIXES[self.db_type]

    def tables(self) -> dict[str, str]:
        """Staging tables: name -> column definitions. The value columns have no type affinity, so each value
        reaches the real table exactly as it was bound."""
        certificate = ", ".join(_columns("c", len(_inline_columns(self.layout))))
        combo = ", ".join(_columns("x", len(_lookup_columns(self.layout))))
        occurrence = ", ".join(_columns("o", len(self.layout.occurrence_columns)))
        tables = {
            "Text": "local INTEGER PRIMARY KEY, value",
            "Num": "local INTEGER PRIMARY KEY, value",
            # cert_local: the raw of that new certificate (stored with it), NULL: an issuer raw (deduplicated)
            "Raw": "local INTEGER PRIMARY KEY, digest, der_zstd, raw, cert_local",
            "Policy": "local INTEGER PRIMARY KEY, digest, v0, v1, v2, v3",
            "PolicySet": "local INTEGER PRIMARY KEY, digest, policy_count",
            # Integer keys, so the joins on them use the primary key
            "PolicySetMember": "set_local INTEGER NOT NULL, position INTEGER NOT NULL, policy_local, "
                               "PRIMARY KEY (set_local, position)",
            "Issuer": f"local INTEGER PRIMARY KEY, digest, {', '.join(_columns('v', 8))}, raw_local",
            "Combo": f"local INTEGER PRIMARY KEY, digest, {combo}",
            "Cert": f"local INTEGER PRIMARY KEY, digest, {certificate}, combo_local, raw_local, set_local",
            # log_ref is the Logs id, NULL for the logs still unknown (log_name) when the ingestion started
            "Sct": "cert_local INTEGER NOT NULL, position INTEGER NOT NULL, log_ref, log_name, v0 NOT NULL, v1 NOT NULL, "
                   "v2 NOT NULL, "
                   "PRIMARY KEY (cert_local, position)",
            "Occ": f"r INTEGER PRIMARY KEY, cert_local, issuer_local{', ' if occurrence else ''}{occurrence}",
        }
        if self.db_type is DatabaseType.LEAF:
            tables["Errors"] = f"r INTEGER PRIMARY KEY, {', '.join(_columns('e', len(ERROR_STORED)))}"
        return tables


_WITHOUT_ROWID = frozenset({"PolicySetMember", "Sct"})


def _inline_columns(layout: StorageLayout) -> list[int]:
    """Positions of the certificate values stored inline."""
    return [i for i, (_, kind) in enumerate(layout.certificate_columns) if kind == INLINE]


def _lookup_columns(layout: StorageLayout) -> list[int]:
    """Positions of the certificate values stored as TextValues/NumericValues references (one 'combo' per distinct
    combination in a block, so the main process maps each combination once)."""
    return [i for i, (_, kind) in enumerate(layout.certificate_columns) if kind != INLINE]


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


def _all_bindable(values) -> bool:
    """_bindable() of every value (inlined: it runs on every staged value)."""
    for value in values:
        kind = type(value)
        if kind is str:
            if not value.isascii():
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError:
                    return False
        elif kind is int:
            if not _INT64_MIN <= value <= _INT64_MAX:
                return False
        elif value is not None and kind is not float and kind is not bool:
            return False
    return True


def _storable_sct(sct: tuple) -> bool:
    """(log id, timestamp, version, signature) the workers can stage: a string log id (the single-row path compares
    other values with the SQL rules) and no NULL in the NOT NULL columns."""
    return type(sct[0]) is str and _all_bindable(sct) and None not in sct[1:]


class _NeedsSingleRowPath(Exception):
    """The line must be inserted by the main process with the single-row code."""


# ---------------------------------------------------------------------------------------------- worker side

class _Locals:
    """Distinct values of one kind in a block: key -> local number, rows numbered from 0 in first-seen order."""

    __slots__ = ("index", "keys", "rows")

    def __init__(self) -> None:
        self.index: dict = {}
        self.keys: list = []
        self.rows: list[tuple] = []

    def add(self, key, row: tuple) -> int:
        local = len(self.rows)
        self.index[key] = local
        self.keys.append(key)
        self.rows.append((local, *row))
        return local

    def truncate(self, length: int) -> None:
        for key in self.keys[length:]:
            del self.index[key]
        del self.keys[length:]
        del self.rows[length:]


class _DatabaseRows:
    """Rows of one database for one block."""

    def __init__(self, spec: _DatabaseSpec, encoded: dict[bytes, tuple]):
        self.spec = spec
        self._encoded = encoded
        self._shared: list[bool] = []       # per Raw local: repeated by many rows (its encoding is cached)
        self.combos_by_values: dict[tuple, int] = {}
        self._encoded_raws = 0              # Raw rows already encoded
        self.locals = {kind: _Locals() for kind in _LOCAL_KINDS}
        self.lists: dict[str, list[tuple]] = {"PolicySetMember": [], "Sct": [], "Occ": []}
        if spec.db_type is DatabaseType.LEAF:
            self.lists["Errors"] = []
        self.unresolved_logs = 0
        self._row_lists = [entries.rows for entries in self.locals.values()] + list(self.lists.values())

    def table_rows(self) -> dict[str, list[tuple]]:
        rows = {kind: entries.rows for kind, entries in self.locals.items()}
        rows.update(self.lists)
        return rows

    def lengths(self) -> tuple[int, ...]:
        return tuple(map(len, self._row_lists))

    def truncate(self, lengths: tuple[int, ...]) -> None:
        combos = lengths[_LOCAL_KINDS.index("Combo")]
        if len(self.locals["Combo"].rows) > combos:
            self.combos_by_values = {values: local for values, local in self.combos_by_values.items() if local < combos}
        for entries, length in zip(self.locals.values(), lengths):
            entries.truncate(length)
        for rows, length in zip(self.lists.values(), lengths[len(self.locals):]):
            del rows[length:]

    def counts(self, start: tuple[int, ...], end: tuple[int, ...]) -> dict[str, tuple[int, int]]:
        """Row number range [lo, hi) of every table between two lengths() marks."""
        names = [*self.locals, *self.lists]
        return {name: (lo, hi) for name, lo, hi in zip(names, start, end)}

    def lookup(self, kind: str, value: object) -> int | None:
        """Local number of a TextValues/NumericValues value; None for NULL."""
        value = stored_lookup_value(value)
        if value is None:
            return None
        entries = self.locals["Text" if kind == TEXT else "Num"]
        key = repr(value)
        local = entries.index.get(key)
        return entries.add(key, (value,)) if local is None else local

    def raw(self, value: object, digest: bytes) -> int:
        """Local number of an issuer raw (deduplicated); compressed by encode_raws(), when the dictionary is ready."""
        entries = self.locals["Raw"]
        local = entries.index.get(digest)
        if local is None:
            local = self._add_raw(digest, (digest, value, None), True)
        return local

    def certificate_raw(self, value: object, digest: bytes, cert_local: int, shared: bool) -> int:
        """Local number of the raw of a new certificate: one per certificate, as CertificateDAO._store() does."""
        return self._add_raw(("certificate", cert_local), (digest, value, cert_local), shared)

    def _add_raw(self, key, row: tuple, shared: bool) -> int:
        local = self.locals["Raw"].add(key, row)
        del self._shared[local:]
        self._shared.append(shared)
        return local

    def encode_raws(self, codec: RawCodec) -> None:
        """Turn the staged (digest, value) raws into (digest, der_zstd, raw); repeated raws use the cache."""
        rows = self.locals["Raw"].rows
        for position in range(self._encoded_raws, len(rows)):
            local, digest, value, cert_local = rows[position]
            shared = self._shared[position]
            encoded = self._encoded.get(digest) if shared else None
            if encoded is None:
                encoded = codec.encode(value)
                if shared:
                    if len(self._encoded) >= CERTIFICATE_CACHE_SIZE:
                        del self._encoded[next(iter(self._encoded))]
                    self._encoded[digest] = encoded
            rows[position] = (local, digest, *encoded, cert_local)
        self._encoded_raws = len(rows)


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
    """Consecutive lines of a block copied together."""
    first_line: int                         # index of the first line in the block
    line_count: int
    byte_start: int                         # offsets in the block
    byte_end: int
    ranges: dict[DatabaseType, dict[str, tuple[int, int]]]
    unresolved_logs: dict[DatabaseType, int]    # SCTs with an unknown log staged in the block up to the segment end
    logs: list                              # LogRecord, or (kind, line index, text) for the line errors

    @property
    def stored_lines(self) -> int:
        """Lines counted by Database.row_transaction() in the single-row path: all but the line errors."""
        return self.line_count - sum(1 for entry in self.logs if type(entry) is tuple)


@dataclass
class _ChunkResult:
    line_count: int
    staging_path: str | None
    items: list = field(default_factory=list)   # _Segment or (line index, line bytes) for the single-row path


class _ChunkProcessor:
    """Builds the rows of a block of lines for every database and writes them to a staging file."""

    def __init__(self, input_path: str, specs: Sequence[_DatabaseSpec], staging_dir: str, capture: _LogCapture,
                 dictionary_path: str | None = None):
        self._input_path = input_path
        self._file: BinaryIO | None = None
        self._specs = specs
        # Workers start before the dictionary is trained: they read it from its file with their first block
        self._dictionary_path = dictionary_path
        self._codecs: dict[DatabaseType, RawCodec] = {}
        self._staging_dir = staging_dir
        self._capture = capture
        self._cache: dict[str, Certificate] = {}
        self._raw_keys: dict[str, bytes] = {}
        self._encoded: dict[bytes, tuple] = {}
        self._debug = logging.getLogger().isEnabledFor(logging.DEBUG)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def read(self, block: BlockSpec) -> bytes:
        if block.path != self._input_path:
            return read_block(block)
        if self._file is None:
            self._file = open(self._input_path, 'rb')
        return read_block(block, self._file)

    def _load_codecs(self) -> None:
        if self._dictionary_path is None:
            dictionaries = {spec.db_type: spec.raw_dictionary for spec in self._specs}
        else:
            # Written (atomically) by the main process once trained; the blocks are parsed meanwhile
            while not os.path.exists(self._dictionary_path):
                time.sleep(_DICTIONARY_POLL_SECONDS)
            with open(self._dictionary_path, "rb") as file:
                dictionary = file.read() or None
            dictionaries = dict.fromkeys((spec.db_type for spec in self._specs), dictionary)
        self._codecs = {db_type: RawCodec(dictionary) for db_type, dictionary in dictionaries.items()}

    def codec(self, db_type: DatabaseType) -> RawCodec:
        if not self._codecs:
            self._load_codecs()
        return self._codecs[db_type]

    def process(self, block: BlockSpec) -> _ChunkResult:
        data = self.read(block)
        excluded: set[int] = set()
        while True:
            builder = _ChunkBuilder(self, data, excluded)
            staging_path = os.path.join(self._staging_dir, f"chunk_{block.index}.db")
            failing = builder.write_staging(staging_path)
            if not failing:
                return builder.result(staging_path)
            # Lines whose values cannot be stored go to the single-row path: the block is rebuilt without them
            excluded |= failing

    def rows(self, spec: _DatabaseSpec) -> _DatabaseRows:
        return _DatabaseRows(spec, self._encoded)

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

    def raw_key(self, raw: object, shared: bool) -> bytes:
        """Key of a raw value; the raws repeated by many rows (issuers, chain certificates) are cached."""
        if not shared or type(raw) is not str:
            return raw_key(raw)
        key = self._raw_keys.get(raw)
        if key is None:
            key = raw_key(raw)
            if len(self._raw_keys) >= CERTIFICATE_CACHE_SIZE:
                del self._raw_keys[next(iter(self._raw_keys))]
            self._raw_keys[raw] = key
        return key


class _ChunkBuilder:
    """Rows and segments of one block."""

    def __init__(self, processor: _ChunkProcessor, data: bytes, excluded: set[int]):
        self._processor = processor
        self._data = data
        self._excluded = excluded
        self._databases = [processor.rows(spec) for spec in processor._specs]
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
                self._add_error(database, row)
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

    def _add_error(self, database: _DatabaseRows, row: dict) -> None:
        params = error_params(row)
        if not _all_bindable(params):
            raise _NeedsSingleRowPath()
        database.lists["Errors"].append((len(database.lists["Errors"]), *[
            params[index] if kind == INLINE else database.lookup(kind, params[index]) for _, kind, index in ERROR_STORED]))
        if self._processor._debug:
            logging.debug("Error row inserted for domain: %s", params[0])

    def _add_certificate(self, database: _DatabaseRows, row: dict, certificate: dict, chain: list[dict],
                         emitted_up_to: int) -> None:
        """Values of CertificateDAO.process_insert_certificate(), computed in the same order (same logs)."""
        spec = database.spec
        parsed = certificate.get("parsed", {})
        raw = certificate.get("raw") if spec.db_type is DatabaseType.LEAF else certificate["raw"]
        digital_certificate = self._processor.certificate(raw, spec.db_type)
        extensions = parsed.get("extensions", {})

        issuer = issuer_params(parsed, chain)
        subject = subject_params(parsed, digital_certificate)
        params = certificate_params(row, certificate, parsed, chain, digital_certificate, spec.db_type, None, None,
                                    emitted_up_to)
        if self._processor._debug:
            logging.debug("Certificate inserted: %s", parsed.get("serial_number", ""))
        extension = extension_params(extensions, digital_certificate)
        scts = tuple((sct.get("log_id", ""), sct.get("timestamp", ""), sct.get("version", ""), sct.get("signature", ""))
                     for sct in extensions.get("signed_certificate_timestamps", []))
        policies = policy_params(digital_certificate) or ()
        self._stage(database, params, subject, extension, scts, policies, issuer)

    def _stage(self, database: _DatabaseRows, params: tuple, subject: tuple, extension: tuple, scts: tuple, policies,
               issuer: tuple) -> None:
        """Stage the occurrence and the rows new in the block, in the order of CertificateDAO._store()."""
        layout = database.spec.layout
        raw = params[-1]
        shared = database.spec.db_type is not DatabaseType.LEAF
        raw_digest = None if raw is None else self._processor.raw_key(raw, shared)
        values = layout.certificate_values(params, subject, extension)
        policies = tuple(policies)
        key = certificate_key(values, scts, policies, raw_digest)
        cert_local = database.locals["Cert"].index.get(key)
        if cert_local is None and not (_all_bindable(values) and _bindable(raw) and all(map(_storable_sct, scts))
                                       and all(_all_bindable(policy) for policy in policies)):
            raise _NeedsSingleRowPath()
        occurrence = layout.occurrence_values(params)
        if not (_all_bindable(params[i] for i in layout.dropped) and _all_bindable(occurrence)):
            raise _NeedsSingleRowPath()

        issuer_local = self._issuer(database, issuer)
        if cert_local is None:
            cert_local = self._new_certificate(database, key, values, raw, raw_digest, shared, scts, policies)
        occurrence = [value if kind != NUMERIC else database.lookup(kind, value)
                      for (_, kind), value in zip(layout.occurrence_columns, occurrence)]
        database.lists["Occ"].append((len(database.lists["Occ"]), cert_local, issuer_local, *occurrence))

    def _issuer(self, database: _DatabaseRows, issuer: tuple) -> int:
        values, raw = issuer[:-1], issuer[-1]
        raw_digest = None if raw is None else self._processor.raw_key(raw, True)
        key = issuer_key(values, raw_digest)
        entries = database.locals["Issuer"]
        local = entries.index.get(key)
        if local is None:
            if not _all_bindable(issuer):
                raise _NeedsSingleRowPath()
            raw_local = None if raw is None else database.raw(raw, raw_digest)
            local = entries.add(key, (key, *values, raw_local))
        return local

    @staticmethod
    def _new_certificate(database: _DatabaseRows, key: bytes, values: tuple, raw: object, raw_digest: bytes | None,
                         shared: bool, scts: tuple, policies: tuple) -> int:
        cert_local = len(database.locals["Cert"].rows)
        raw_local = None if raw is None else database.certificate_raw(raw, raw_digest, cert_local, shared)
        set_local = None
        if policies:
            policy_keys = tuple(policy_key(policy) for policy in policies)
            set_key = policy_set_key(policy_keys)
            sets = database.locals["PolicySet"]
            set_local = sets.index.get(set_key)
            if set_local is None:
                policy_locals = [_policy_local(database, policy_key_, policy)
                                 for policy_key_, policy in zip(policy_keys, policies)]
                set_local = sets.add(set_key, (set_key, len(policy_locals)))
                database.lists["PolicySetMember"].extend(
                    (set_local, position, local) for position, local in enumerate(policy_locals))
        layout = database.spec.layout
        inline = [value for (_, kind), value in zip(layout.certificate_columns, values) if kind == INLINE]
        lookups = tuple(value for (_, kind), value in zip(layout.certificate_columns, values) if kind != INLINE)
        # Strings compare exactly: a combination of strings already seen in the block is reused as it is
        known = database.combos_by_values.get(lookups) if all(type(value) is str for value in lookups) else None
        if known is not None:
            combo_local = known
        else:
            combo = tuple(database.lookup(kind, value) for (_, kind), value in zip(layout.certificate_columns, values)
                          if kind != INLINE)
            combos = database.locals["Combo"]
            combo_local = combos.index.get(combo)
            if combo_local is None:
                combo_local = combos.add(combo, (_combo_key(lookups), *combo))
            if all(type(value) is str for value in lookups):
                database.combos_by_values[lookups] = combo_local
        database.locals["Cert"].add(key, (key, *inline, combo_local, raw_local, set_local))
        log_ids = database.spec.log_ids
        for position, (log_id, timestamp, version, signature) in enumerate(scts):
            log_ref = log_ids.get(log_id)
            if log_ref is None:
                database.unresolved_logs += 1
            database.lists["Sct"].append((cert_local, position, log_ref, None if log_ref is not None else log_id,
                                          timestamp, version, signature))
        return cert_local

    # --------------------------------------------------------------- staging file

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        for database in self._databases:
            for name, columns in database.spec.tables().items():
                suffix = " WITHOUT ROWID" if name in _WITHOUT_ROWID else ""
                conn.execute(f"CREATE TABLE {database.spec.prefix}_{name} ({columns}){suffix}")

    def _insert(self, conn: sqlite3.Connection, slices: list[tuple[int, ...]] | None = None,
                ends: list[tuple[int, ...]] | None = None) -> None:
        for position, database in enumerate(self._databases):
            for column, (name, rows) in enumerate(database.table_rows().items()):
                if slices is not None:
                    rows = rows[slices[position][column]:ends[position][column]]
                if rows:
                    conn.executemany(f"INSERT INTO {database.spec.prefix}_{name} VALUES "
                                     f"({', '.join('?' * len(rows[0]))})", rows)

    def write_staging(self, path: str) -> set[int]:
        """Write the rows to the staging file; return the lines whose values cannot be stored, if any."""
        for database in self._databases:
            database.encode_raws(self._processor.codec(database.spec.db_type))
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
        return _ChunkResult(line_count=self.line_count, staging_path=staging_path, items=self.items)


def _combo_key(lookups: tuple) -> bytes:
    """Key of the lookup values of a certificate, shared by the blocks (the main process maps it once)."""
    return hashlib.blake2b(marshal.dumps(lookups, 2), digest_size=16).digest()


def _policy_local(database: _DatabaseRows, key: bytes, policy: tuple) -> int:
    entries = database.locals["Policy"]
    local = entries.index.get(key)
    return entries.add(key, (key, *policy)) if local is None else local


_WORKER: _ChunkProcessor | None = None


def _init_worker(input_path: str, specs: Sequence[_DatabaseSpec], log_level: int, staging_dir: str,
                 parent_pid: int) -> None:
    global _WORKER
    init_worker_process(parent_pid)
    capture = _LogCapture()
    root = logging.getLogger()
    root.handlers = [capture]
    root.setLevel(log_level)
    _WORKER = _ChunkProcessor(input_path, specs, staging_dir, capture, _dictionary_path(staging_dir))


def _process_chunk(block: BlockSpec) -> _ChunkResult:
    return _WORKER.process(block)


def _warm_up() -> None:
    """No-op task: makes the pool start a worker process (and import the modules) ahead of the first block."""


def _dictionary_path(staging_dir: str) -> str:
    return os.path.join(staging_dir, "raw_dictionary.bin")


# ---------------------------------------------------------------------------------------------- main process side

def _lookup_expression(kind: str, column: str) -> str:
    """Id of a staged lookup local through the block map."""
    if kind == INLINE:
        return f"s.{column}"
    table = "Text" if kind == TEXT else "Num"
    return f"(SELECT y.id FROM temp.dca_map_{table} AS y WHERE y.local = s.{column})"


def _map_expression(kind: str, column: str) -> str:
    return f"(SELECT y.id FROM temp.dca_map_{kind} AS y WHERE y.local = s.{column})"


class _Destination:
    """A database being populated: maps the staged rows of each segment to ids and inserts the new ones."""

    def __init__(self, database: Database, dao: CertificateDAO, spec: _DatabaseSpec):
        self.database = database
        self.conn = database.conn
        self.dao = dao
        self.spec = spec
        self.next_ids: dict[str, int] = {}
        self.mapped: dict[str, int] = dict.fromkeys(_LOCAL_KINDS, 0)
        self.log_ids: dict[str, int] = {}
        self._used: dict[str, int] = {}
        self.recent_keys = 0                # keys added to the in-memory tables since the last merge
        self._sql = self._build_sql()
        for kind in _LOCAL_KINDS:
            if kind != "Combo":
                self.conn.execute(f"CREATE TEMP TABLE IF NOT EXISTS dca_map_{kind} "
                                  "(local INTEGER PRIMARY KEY, id INTEGER NOT NULL)")
        # Lookup ids of every combination of lookup values seen by the ingestion
        lookups = ", ".join(f"i{n}" for n in range(len(_lookup_columns(spec.layout))))
        self.conn.execute(f"CREATE TEMP TABLE IF NOT EXISTS dca_combos (digest BLOB PRIMARY KEY, {lookups}) WITHOUT ROWID")
        self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS ingestion_log_refs (cert_local INTEGER NOT NULL, "
                          "position INTEGER NOT NULL, log_ref, PRIMARY KEY (cert_local, position)) WITHOUT ROWID")
        self.refresh()

    def _build_sql(self) -> dict[str, str]:
        p = f"chunk.{self.spec.prefix}"
        layout = self.spec.layout
        new = "FROM temp.dca_map_{0} AS m JOIN {1}_{0} AS s ON s.local = m.local WHERE m.local >= ? AND m.id >= ?"
        certificate_columns = [column for column, _ in layout.certificate_columns]
        inline, lookups = _inline_columns(layout), _lookup_columns(layout)
        certificate_values = [f"s.c{inline.index(i)}" if i in inline else f"q.i{lookups.index(i)}"
                              for i in range(len(certificate_columns))]
        combo_values = [_lookup_expression(layout.certificate_columns[i][1], f"x{n}") for n, i in enumerate(lookups)]
        occurrence_columns = [column for column, _ in layout.occurrence_columns]
        occurrence_values = [_lookup_expression(kind if kind == NUMERIC else INLINE, f"o{i}")
                             for i, (_, kind) in enumerate(layout.occurrence_columns)]
        error_values = [_lookup_expression(kind, f"e{i}") for i, (_, kind, _) in enumerate(ERROR_STORED)]
        sql = {
            "Raw": f"INSERT INTO main.RawCertificates (raw_id, der_zstd, raw) SELECT m.id, s.der_zstd, s.raw "
                   f"{new.format('Raw', p)}",
            "Policy": f"INSERT INTO main.PolicyData (policy_id, policy_identifier, cps, policy_qualifiers, is_cp_critical) "
                      f"SELECT m.id, s.v0, s.v1, s.v2, s.v3 {new.format('Policy', p)}",
            "PolicySet": f"INSERT INTO main.PolicySets (policy_set_id, policy_count) SELECT m.id, s.policy_count "
                         f"{new.format('PolicySet', p)}",
            "PolicySetMember": "INSERT INTO main.PolicySetMembers (policy_set_id, position, policy_id) SELECT m.id, "
                               "s.position, (SELECT y.id FROM temp.dca_map_Policy AS y WHERE y.local = s.policy_local) "
                               f"FROM temp.dca_map_PolicySet AS m CROSS JOIN {p}_PolicySetMember AS s ON s.set_local = "
                               "m.local WHERE m.local >= ? AND m.id >= ?",
            "Issuer": f"INSERT INTO main.IssuerData (issuer_id, {', '.join(ISSUER_COLUMNS[:8])}, raw_id) SELECT m.id, "
                      f"{', '.join(f's.v{i}' for i in range(8))}, {_map_expression('Raw', 'raw_local')} "
                      f"{new.format('Issuer', p)}",
            "Combo": f"INSERT INTO temp.dca_combos (digest{''.join(f', i{n}' for n in range(len(lookups)))}) SELECT "
                     f"s.digest{''.join(', ' + value for value in combo_values)} FROM {p}_Combo AS s "
                     "WHERE s.local >= ? AND s.local < ? AND NOT EXISTS (SELECT 1 FROM temp.dca_combos AS g "
                     "WHERE g.digest = s.digest)",
            "Cert": f"INSERT INTO main.CertificateData (certificate_id, {', '.join(certificate_columns)}, raw_id, "
                    f"policy_set_id) SELECT m.id, {', '.join(certificate_values)}, {_map_expression('Raw', 'raw_local')}, "
                    f"{_map_expression('PolicySet', 'set_local')} FROM temp.dca_map_Cert AS m JOIN {p}_Cert AS s ON "
                    f"s.local = m.local JOIN {p}_Combo AS x ON x.local = s.combo_local JOIN temp.dca_combos AS q ON "
                    "q.digest = x.digest WHERE m.local >= ? AND m.id >= ?",
            "UnknownLogs": f"SELECT s.cert_local, s.position, s.log_name FROM temp.dca_map_Cert AS m CROSS JOIN {p}_Sct AS s "
                           "ON s.cert_local = m.local WHERE m.local >= ? AND m.id >= ? AND s.log_ref IS NULL "
                           "ORDER BY m.local, s.position",
            "Sct": "INSERT INTO main.SctData (certificate_id, position, log_id, timestamp, version, signature) SELECT m.id, "
                   "s.position, COALESCE(s.log_ref, (SELECT f.log_ref FROM temp.ingestion_log_refs AS f WHERE "
                   "f.cert_local = s.cert_local AND f.position = s.position)), s.v0, s.v1, s.v2 FROM temp.dca_map_Cert "
                   f"AS m CROSS JOIN {p}_Sct AS s ON s.cert_local = m.local WHERE m.local >= ? AND m.id >= ?",
            "Occ": f"INSERT INTO main.Occurrences (occurrence_id, certificate_id, issuer_id"
                   f"{''.join(', ' + column for column in occurrence_columns)}) SELECT s.r + ?, "
                   f"{_map_expression('Cert', 'cert_local')}, {_map_expression('Issuer', 'issuer_local')}"
                   f"{''.join(', ' + value for value in occurrence_values)} FROM {p}_Occ AS s WHERE s.r >= ? AND s.r < ?",
            "Errors": f"INSERT INTO main.ErrorData (error_id, {', '.join(column for column, _, _ in ERROR_STORED)}) "
                      f"SELECT s.r + ?, {', '.join(error_values)} FROM {p}_Errors AS s WHERE s.r >= ? AND s.r < ?",
        }
        for kind, key_table, _, _ in _KEYED:
            # Keys: the recent ones in memory, the others in the keys file
            sql[f"map_{kind}"] = (f"INSERT INTO temp.dca_map_{kind} (local, id) SELECT s.local, COALESCE(r.id, k.id, ? - 1 + "
                                  f"SUM(r.id IS NULL AND k.id IS NULL) OVER (ORDER BY s.local)) FROM {p}_{kind} AS s "
                                  f"LEFT JOIN recent.{key_table} AS r ON r.digest = s.digest LEFT JOIN keys.{key_table} AS k "
                                  "ON r.id IS NULL AND k.digest = s.digest WHERE s.local >= ? AND s.local < ?")
            sql[f"keys_{kind}"] = (f"INSERT INTO recent.{key_table} (digest, id) SELECT s.digest, m.id FROM "
                                   f"temp.dca_map_{kind} AS m JOIN {p}_{kind} AS s ON s.local = m.local WHERE m.local >= ? "
                                   "AND m.id >= ?")
        # The raw of a certificate gets an id only if the certificate is new; issuer raws are looked up by key
        sql["map_Raw"] = ("INSERT INTO temp.dca_map_Raw (local, id) SELECT s.local, COALESCE(r.id, k.id, ? - 1 + "
                          "SUM(r.id IS NULL AND k.id IS NULL) OVER (ORDER BY s.local)) FROM "
                          f"{p}_Raw AS s LEFT JOIN temp.dca_map_Cert AS c ON c.local = s.cert_local "
                          "LEFT JOIN recent.RawKeys AS r ON s.cert_local IS NULL AND r.digest = s.digest "
                          "LEFT JOIN keys.RawKeys AS k ON s.cert_local IS NULL AND r.id IS NULL AND k.digest = s.digest "
                          "WHERE s.local >= ? AND s.local < ? AND (s.cert_local IS NULL OR c.id >= ?)")
        sql["keys_Raw"] = ("INSERT INTO recent.RawKeys (digest, id) SELECT s.digest, m.id FROM temp.dca_map_Raw AS m JOIN "
                           f"{p}_Raw AS s ON s.local = m.local WHERE m.local >= ? AND m.id >= ? AND s.cert_local IS NULL")
        for kind, table in _LOOKUPS:
            sql[f"add_{kind}"] = (f"INSERT OR IGNORE INTO main.{table} (value) SELECT value FROM {p}_{kind} "
                                  "WHERE local >= ? AND local < ? ORDER BY local")
            sql[f"map_{kind}"] = (f"INSERT INTO temp.dca_map_{kind} (local, id) SELECT s.local, t.value_id FROM {p}_{kind} "
                                  f"AS s JOIN main.{table} AS t ON t.value = s.value WHERE s.local >= ? AND s.local < ?")
        return sql

    def refresh(self) -> None:
        """Read the next free id of every table and the known SCT logs (after the single-row path ran)."""
        tables = [(kind, table) for kind, _, table, _ in _KEYED] + [(kind, table) for kind, (table, _) in _ROW_TABLES.items()]
        for kind, table in tables:
            if kind == "Errors" and self.spec.db_type is not DatabaseType.LEAF:
                continue
            self.next_ids[kind] = self.conn.execute(f"SELECT COALESCE(MAX(rowid), 0) + 1 FROM main.{table}").fetchone()[0]
        self.log_ids = self.dao.log_row_ids()

    def start_block(self) -> None:
        """A new staging file is attached: its local numbers start from 0."""
        for kind in _LOCAL_KINDS:
            if kind != "Combo":
                self.conn.execute(f"DELETE FROM temp.dca_map_{kind}")
        self.conn.execute("DELETE FROM temp.ingestion_log_refs")
        self.mapped = dict.fromkeys(_LOCAL_KINDS, 0)

    def copy(self, segment: _Segment) -> None:
        """Insert the rows of a segment (advance() then counts the ids used). The caller rolls back on error."""
        ranges = segment.ranges[self.spec.db_type]
        used = self._used = {}
        for kind, _ in _LOOKUPS:
            self._map_lookups(kind, ranges[kind][1])
        lo, hi = self.mapped["Combo"], ranges["Combo"][1]
        if hi > lo:
            self.conn.execute(self._sql["Combo"], (lo, hi))
            self.mapped["Combo"] = hi
        # Certificates and issuers first: the raws are mapped only for the new ones
        certificates = self._map_keyed("Cert", ranges["Cert"][1])
        issuers = self._map_keyed("Issuer", ranges["Issuer"][1])
        raws = self._map_keyed("Raw", ranges["Raw"][1], certificates[1])
        policies = self._map_keyed("Policy", ranges["Policy"][1])
        policy_sets = self._map_keyed("PolicySet", ranges["PolicySet"][1])
        self._insert_new("Raw", raws)
        self._insert_new("Issuer", issuers)
        self._insert_new("Policy", policies)
        if self._insert_new("PolicySet", policy_sets):
            self.conn.execute(self._sql["PolicySetMember"], policy_sets[:2])
        if self._insert_new("Cert", certificates):
            if segment.unresolved_logs[self.spec.db_type]:
                self._resolve_logs(*certificates[:2])
            self.conn.execute(self._sql["Sct"], certificates[:2])
        for kind, (_, _, count) in (("Cert", certificates), ("Issuer", issuers), ("Raw", raws), ("Policy", policies),
                                    ("PolicySet", policy_sets)):
            used[kind] = count
        for kind in _ROW_TABLES:
            if kind in ranges:
                lo, hi = ranges[kind]
                if hi > lo:
                    self.conn.execute(self._sql[kind], (self.next_ids[kind] - lo, lo, hi))
                used[kind] = hi - lo

    def _map_lookups(self, kind: str, hi: int) -> None:
        lo = self.mapped[kind]
        if hi > lo:
            self.conn.execute(self._sql[f"add_{kind}"], (lo, hi))
            if self.conn.execute(self._sql[f"map_{kind}"], (lo, hi)).rowcount != hi - lo:
                raise sqlite3.IntegrityError(f"staged {kind} values not found after their insert")
            self.mapped[kind] = hi

    def _map_keyed(self, kind: str, hi: int, *parameters: int) -> tuple[int, int, int]:
        """Map the locals [mapped, hi) to ids (the new ones numbered from the next free id, in local order) and store
        the keys of the new ones; return (first local, first new id, new rows)."""
        lo, first = self.mapped[kind], self.next_ids[kind]
        if hi <= lo:
            return lo, first, 0
        self.conn.execute(self._sql[f"map_{kind}"], (first, lo, hi, *parameters))
        self.mapped[kind] = hi
        new = self.conn.execute(f"SELECT COUNT(*) FROM temp.dca_map_{kind} WHERE local >= ? AND id >= ?",
                                (lo, first)).fetchone()[0]
        if new:
            self.conn.execute(self._sql[f"keys_{kind}"], (lo, first))
        return lo, first, new

    def _insert_new(self, kind: str, mapped: tuple[int, int, int]) -> bool:
        """Insert the rows of the new ids of a _map_keyed() result; False if there are none."""
        lo, first, new = mapped
        if new:
            self.conn.execute(self._sql[kind], (lo, first))
        return new > 0

    def _resolve_logs(self, lo: int, first: int) -> None:
        """Logs id of the SCTs whose log was unknown to the workers, inserting the missing logs in file order."""
        references = []
        for cert_local, position, log_name in self.conn.execute(self._sql["UnknownLogs"], (lo, first)).fetchall():
            log_ref = self.log_ids.get(log_name)
            if log_ref is None:
                log_ref = self.dao.insert_unknown_log(log_name)
                self.log_ids[log_name] = log_ref
            references.append((cert_local, position, log_ref))
        self.conn.executemany("INSERT OR REPLACE INTO temp.ingestion_log_refs VALUES (?, ?, ?)", references)

    def advance(self) -> None:
        for kind, count in self._used.items():
            self.next_ids[kind] += count
            if kind in _KEYED_KINDS:
                self.recent_keys += count
        self._used = {}

    def merge_recent_keys(self) -> None:
        """Move the recent keys (in memory) into the keys file once there are many: inserted in digest order, they
        update each page of the file once. Runs between blocks, in its own transaction."""
        if self.recent_keys < RECENT_KEYS:
            return
        self.conn.execute("BEGIN")
        try:
            for _, key_table, _, _ in _KEYED:
                self.conn.execute(f"INSERT INTO keys.{key_table} SELECT digest, id FROM recent.{key_table} ORDER BY digest")
                self.conn.execute(f"DELETE FROM recent.{key_table}")
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        self.recent_keys = 0

    def begin(self) -> None:
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")


class _Ingestion:
    """Main process side: submits the blocks, copies their rows in file order and handles the fallbacks."""

    def __init__(self, source: InputSource, targets: Sequence[tuple[Database, CertificateDAO]],
                 on_progress: Callable[[int], None], staging_dir: str):
        self.source = source
        self.targets = list(targets)
        self.on_progress = on_progress
        self.staging_dir = staging_dir
        self._keys_attached: list[_Destination] = []
        self.destinations = [_Destination(database, dao, _database_spec(database, dao)) for database, dao in self.targets]
        self.next_line = 1
        self._attached: list[_Destination] = []
        self._fallback_logged = False
        self._broken = False                # the rest of the current block goes to the single-row path
        self._train: Callable[[], bytes | None] | None = None
        self._threads = ThreadPoolExecutor(max(1, len(self.destinations)), thread_name_prefix="ingestion")
        try:
            self._attach_keys()
        except BaseException:
            self.close()
            raise

    def _attach_keys(self) -> None:
        """Attach a keys file (digest -> id of every deduplicated row) to every database."""
        for destination in self.destinations:
            conn = destination.conn
            conn.commit()
            path = os.path.join(self.staging_dir, f"keys_{destination.spec.db_type.value}.db")
            conn.execute("ATTACH DATABASE ? AS keys", (path,))
            self._keys_attached.append(destination)
            # The keys added since the last merge, in memory
            conn.execute("ATTACH DATABASE ':memory:' AS recent")
            # Small pages: the digests are random, so every block updates pages all over the file (each one is
            # copied to the journal and written at commit)
            conn.execute(f"PRAGMA keys.page_size = {_KEYS_PAGE_SIZE}")
            # A segment rolled back must roll back its keys too: the journal is kept in memory
            conn.execute("PRAGMA keys.journal_mode = MEMORY")
            conn.execute("PRAGMA keys.synchronous = OFF")
            conn.execute(f"PRAGMA keys.cache_size = {-_KEYS_CACHE_KIB}")
            destination.dao.use_keys("keys", "recent")

    def close(self) -> None:
        try:
            self._detach()
        finally:
            self._threads.shutdown(wait=True)
            for destination in self.destinations:
                conn = destination.conn
                for kind in _LOCAL_KINDS:
                    conn.execute(f"DROP TABLE IF EXISTS temp.dca_map_{kind}")
                conn.execute("DROP TABLE IF EXISTS temp.dca_combos")
                conn.execute("DROP TABLE IF EXISTS temp.ingestion_log_refs")
            while self._keys_attached:
                destination = self._keys_attached.pop()
                destination.conn.commit()
                destination.dao.use_keys()
                destination.conn.execute("DETACH DATABASE keys")
                destination.conn.execute("DETACH DATABASE recent")

    @property
    def specs(self) -> list[_DatabaseSpec]:
        return [destination.spec for destination in self.destinations]

    def set_raw_dictionary(self, dictionary: bytes | None) -> None:
        """Store the raw dictionary in every database before the first row, and in the file the workers read."""
        path = _dictionary_path(self.staging_dir)
        with open(f"{path}.tmp", "wb") as file:
            file.write(dictionary or b"")
        os.replace(f"{path}.tmp", path)
        for destination in self.destinations:
            destination.database.set_raw_dictionary(dictionary)
            destination.dao.raw_codec = destination.database.raw_codec()
            destination.spec = dataclasses.replace(destination.spec, raw_dictionary=dictionary)

    # --------------------------------------------------------------- blocks

    def apply(self, block: BlockSpec, result: _ChunkResult | BaseException) -> None:
        """Store a processed block (or process it here with the single-row path if its worker failed)."""
        if not isinstance(result, BaseException):
            try:
                self._attach(result.staging_path)
            except Exception as e:
                _remove_file(result.staging_path)
                result = e
        if isinstance(result, BaseException):
            self._log_fallback(result)
            self.next_line += self._single_row_path(self.next_line, self.source.read(block))
            self._done(block)
            return

        try:
            data = None
            self._broken = False
            for item in result.items:
                if isinstance(item, _Segment) and self._broken:
                    data = self.source.read(block) if data is None else data
                    self._single_row_path(self.next_line + item.first_line, data[item.byte_start:item.byte_end])
                elif isinstance(item, _Segment):
                    data = self._apply_segment(block, data, item)
                else:
                    index, line = item
                    self._single_row_path(self.next_line + index, line)
        finally:
            self._detach()
            _remove_file(result.staging_path)
        self.next_line += result.line_count
        self._done(block)

    def _done(self, block: BlockSpec) -> None:
        self.source.release(block)
        self.on_progress(block.progress_bytes)

    def _log_fallback(self, error: BaseException) -> None:
        if not self._fallback_logged:
            logging.warning(f"Parallel processing failed ({error!r}): the affected lines are processed by the main "
                            "process.")
            self._fallback_logged = True

    def _apply_segment(self, block: BlockSpec, data: bytes | None, segment: _Segment) -> bytes | None:
        """Copy a segment; on error store its lines with the single-row path. Returns the block text if read."""
        mapped = [dict(destination.mapped) for destination in self.destinations]
        for destination in self.destinations:
            destination.begin()
            destination.conn.execute("SAVEPOINT ingestion_segment")
        try:
            errors = self._each(lambda destination: destination.copy(segment), self.destinations)
            error = next((error for error in errors if error is not None), None)
            if error is not None:
                raise error
        except BaseException as e:
            self._rollback_segment(mapped)
            if not isinstance(e, Exception):
                raise
            # e.g. disk full: the single-row path stores what it can and logs every failed row. The later segments of
            # the block go to the single-row path too: their staged rows may refer to rows that were not stored.
            self._broken = True
            data = self.source.read(block) if data is None else data
            self._single_row_path(self.next_line + segment.first_line, data[segment.byte_start:segment.byte_end])
            return data

        for destination in self.destinations:
            destination.conn.execute("RELEASE SAVEPOINT ingestion_segment")
            destination.advance()
            # Counted as row_transaction() does, which reports them if SQLite rolls back the whole transaction
            destination.database.pending_rows += segment.stored_lines
        self._emit_logs(segment.logs)
        return data

    def _rollback_segment(self, mapped: list[dict[str, int]]) -> None:
        for destination, before in zip(self.destinations, mapped):
            destination.mapped = before
            if destination.conn.in_transaction:
                destination.conn.execute("ROLLBACK TO SAVEPOINT ingestion_segment")
                destination.conn.execute("RELEASE SAVEPOINT ingestion_segment")
            else:
                # SQLite already rolled back the whole transaction (e.g. disk full), as in Database.row_transaction()
                _log_lost_rows(destination.database)
                destination.start_block()
                destination.refresh()

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
        rollbacks = [destination.database.whole_rollbacks for destination in self.destinations]
        try:
            for count, line in enumerate(io.BytesIO(data), start=1):
                ingest_line(first_line + count - 1, line, self.targets)
        finally:
            for destination, before in zip(self.destinations, rollbacks):
                destination.refresh()
                # SQLite rolled back the whole transaction: the rows of the earlier segments of the block are lost
                if destination.database.whole_rollbacks != before:
                    self._broken = True
        return count

    # --------------------------------------------------------------- staging attachment

    def _attach(self, staging_path: str) -> None:
        """Attach the staging file to every database; on error none stays attached."""
        def attach(destination: _Destination) -> None:
            # ATTACH and DETACH are not allowed inside a transaction
            destination.conn.commit()
            destination.database.pending_rows = 0
            destination.conn.execute("ATTACH DATABASE ? AS chunk", (staging_path,))

        errors = self._each(attach, self.destinations)
        self._attached = [destination for destination, error in zip(self.destinations, errors) if error is None]
        try:
            for destination in self._attached:
                destination.start_block()
            error = next((error for error in errors if error is not None), None)
            if error is not None:
                raise error
        except BaseException:
            self._detach()
            raise

    def _detach(self) -> None:
        """Commit the copied rows and detach the staging file."""
        attached, self._attached = self._attached, []
        errors = self._each(lambda destination: destination.conn.commit(), attached)
        for destination, error in reversed(list(zip(attached, errors))):
            if error is not None:
                # e.g. disk full: the rows of the block are lost for this database, as in Database.row_transaction()
                logging.error(f"Transaction failed: {error}")
                _log_lost_rows(destination.database)
                destination.conn.rollback()
                destination.refresh()
            destination.database.pending_rows = 0
            destination.conn.execute("DETACH DATABASE chunk")
            destination.merge_recent_keys()

    def _each(self, function: Callable[[_Destination], object], destinations: list[_Destination]) -> list:
        """Run function on every database, in parallel threads (SQLite runs without the GIL); return the exception
        (or None) of each. Every thread has finished when it returns, also on Ctrl+C, so no connection stays in use."""
        def run(destination: _Destination) -> BaseException | None:
            try:
                function(destination)
            except Exception as e:
                return e
            return None

        if not self._threads or len(destinations) < 2:
            return [run(destination) for destination in destinations]
        futures = [self._threads.submit(run, destination) for destination in destinations]
        try:
            wait(futures)
        except BaseException:
            while not all(future.done() for future in futures):
                try:
                    wait(futures)
                except KeyboardInterrupt:
                    continue
            raise
        return [future.result() for future in futures]

    # --------------------------------------------------------------- runs

    def train_dictionary_later(self, train: Callable[[], bytes | None]) -> None:
        """Train the raw dictionary with train() just before the first block is stored (ensure_dictionary())."""
        self._train = train

    def ensure_dictionary(self) -> None:
        if self._train is not None:
            train, self._train = self._train, None
            self.set_raw_dictionary(train())

    def run_sequential(self, blocks: Iterator[BlockSpec]) -> None:
        """Process the blocks in this process (small files), with the same rows and logs as the workers."""
        self.ensure_dictionary()
        capture = _LogCapture()
        processor = _ChunkProcessor(str(self.source.path), self.specs, self.staging_dir, capture)
        root = logging.getLogger()
        try:
            for block in blocks:
                handlers = root.handlers[:]
                root.handlers = [capture]
                try:
                    result = processor.process(block)
                except Exception as e:
                    result = e
                finally:
                    root.handlers = handlers
                self.apply(block, result)
        finally:
            processor.close()

    def start_pool(self, workers: int) -> _WorkerPool | None:
        """Start the worker processes now (they import the modules while the main process trains the dictionary);
        None, with a warning, if they cannot be started."""
        try:
            pool = _WorkerPool(workers, (str(self.source.path), self.specs, logging.getLogger().getEffectiveLevel(),
                                         self.staging_dir, os.getpid()))
        except _WorkersNotStarted as e:
            self._log_not_started(e)
            return None
        try:
            pool.warm_up()
        except _WorkersNotStarted as e:
            pool.stop()
            pool.shutdown()
            self._log_not_started(e)
            return None
        except BaseException:
            pool.stop()
            pool.shutdown()
            raise
        return pool

    def _log_not_started(self, error: _WorkersNotStarted) -> None:
        logging.warning(f"Could not start the worker processes ({error.__cause__!r}): the main process handles the file "
                        f"from line {self.next_line}.")

    def run_parallel(self, blocks: Iterator[BlockSpec], pool: _WorkerPool) -> None:
        """Process the blocks in worker processes and store them here in file order.

        If a worker process cannot be started, at the beginning or after a restart (e.g. no working sem_open(), fork()
        failing with EAGAIN), every worker is stopped, also those already started, and run_sequential() processes the
        blocks not stored yet.
        """
        pending: deque[_Block] = deque()
        try:
            self._run_pool(blocks, pool, pending)
            return
        except _WorkersNotStarted as e:
            self._log_not_started(e)
        self.run_sequential(itertools.chain((block.spec for block in pending), blocks))

    def _run_pool(self, blocks: Iterator[BlockSpec], pool: _WorkerPool, pending: deque[_Block]) -> None:
        try:
            for spec in blocks:
                pending.append(_Block(spec))
                pool.submit(pending[-1])
                if len(pending) >= pool.workers * CHUNKS_IN_FLIGHT_PER_WORKER:
                    # The workers parse the first blocks while the dictionary is trained
                    self.ensure_dictionary()
                    self._apply_next(pending, pool)
            self.ensure_dictionary()
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
        self.apply(block.spec, result)

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
    spec: BlockSpec
    future: Future | None = None


class _WorkersNotStarted(Exception):
    """The worker processes cannot be started; the reason is the cause."""


class _WorkerPool:
    """Worker processes, started again once if one of them dies."""

    def __init__(self, workers: int, initargs: tuple):
        self.workers = workers
        self._initargs = initargs
        self._restarts = _POOL_RESTARTS
        self._executor = self._start()

    def _start(self) -> ProcessPoolExecutor:
        try:
            with sigint_blocked():
                return ProcessPoolExecutor(max_workers=self.workers, mp_context=multiprocessing.get_context("spawn"),
                                           initializer=_init_worker, initargs=self._initargs)
        except Exception as e:
            raise _WorkersNotStarted() from e

    def submit(self, block: _Block) -> None:
        """Set the future of the block; _WorkersNotStarted if a worker process cannot be started."""
        try:
            # submit() starts the worker processes on demand
            with sigint_blocked():
                block.future = self._executor.submit(_process_chunk, block.spec)
        except BrokenProcessPool as e:
            # The block is processed again by new workers or by the main process
            block.future = Future()
            block.future.set_exception(e)
        except Exception as e:
            raise _WorkersNotStarted() from e

    def warm_up(self) -> None:
        """Start every worker process now; _WorkersNotStarted if one cannot be started."""
        try:
            with sigint_blocked():
                for _ in range(self.workers):
                    self._executor.submit(_warm_up)
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
    return _DatabaseSpec(db_type=database.db_type, layout=dao.layout, log_ids=dao.log_row_ids())


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


def worker_count(file_size: int | None) -> int:
    """Worker processes for an input of that many bytes of text (None: unknown): none (0) when it fits in one block."""
    available = MAX_WORKERS if MAX_WORKERS is not None else max(1, (os.cpu_count() or 2) - 1)
    if file_size is None:
        return max(0, available)
    blocks = -(-file_size // CHUNK_SIZE)
    if blocks <= 1:
        return 0
    return max(0, min(available, blocks))


# ---------------------------------------------------------------------------------------------- raw dictionary

_RAW_KEY = b'"raw"'


def _sample_raws(data: bytes, samples: dict[bytes, bytes]) -> bool:
    """Add the distinct canonical DER certificates of "raw" JSON strings; True once DICTIONARY_SAMPLES are found."""
    position = data.find(_RAW_KEY)
    while position >= 0:
        start = position + len(_RAW_KEY)
        while data[start:start + 1] in (b" ", b":"):
            start += 1
        if data[start:start + 1] == b'"':
            end = data.find(b'"', start + 1)
            text = data[start + 1:end] if end > 0 else b""
            if text and text not in samples:
                der = canonical_der(text.decode("ascii", errors="replace"))
                if der is not None and der[:1] == b"\x30":
                    samples[text] = der
                    if len(samples) >= DICTIONARY_SAMPLES:
                        return True
        position = data.find(_RAW_KEY, start)
    return False


def _train_raw_dictionary(source: InputSource, blocks: Iterator[BlockSpec]) -> tuple[bytes | None, list[BlockSpec]]:
    """Dictionary trained on the distinct raw certificates of the first DICTIONARY_SAMPLE_BYTES of text (whatever the
    block layout, so every input format gives the same one), and the blocks read meanwhile."""
    samples: dict[bytes, bytes] = {}
    read: list[BlockSpec] = []
    remaining = DICTIONARY_SAMPLE_BYTES
    for block in blocks:
        read.append(block)
        data = source.read(block)[:remaining]
        remaining -= len(data)
        if _sample_raws(data, samples) or remaining <= 0:
            break
    return train_dictionary(list(samples.values())), read


def _run(ingestion: _Ingestion, source: InputSource, staging_dir: str) -> None:
    """Train the raw dictionary on the first blocks, then process every block, in parallel when worth it."""
    blocks = source.blocks(CHUNK_SIZE, staging_dir)
    if source.parallel:
        # Plain and line-indexed files: the workers start at once and the sample is read again on its own
        ingestion.train_dictionary_later(lambda: _train_raw_dictionary(source, source.blocks(CHUNK_SIZE, staging_dir))[0])
        workers = worker_count(source.uncompressed_size)
    else:
        # Streams: the sampled blocks are kept and processed first
        dictionary, first_blocks = _train_raw_dictionary(source, blocks)
        ingestion.set_raw_dictionary(dictionary)
        blocks = itertools.chain(first_blocks, blocks)
        workers = 0 if source.ended_in_first_block() else worker_count(None)
    pool = ingestion.start_pool(workers) if workers else None
    if pool is None:
        ingestion.run_sequential(blocks)
    else:
        logging.info(f"Processing the file in parallel with {workers} worker processes.")
        ingestion.run_parallel(blocks, pool)


def ingest_certificates(path: Path, targets: Sequence[tuple[Database, CertificateDAO]],
                        on_progress: Callable[[int], None]) -> None:
    """Insert every line of the zgrab2 file (plain or compressed) into the target databases (already in bulk insert
    mode). on_progress receives the bytes of the file accounted for by each stored block."""
    staging_dir = _staging_directory([database for database, _ in targets])
    try:
        source = open_source(path)
        try:
            ingestion = _Ingestion(source, targets, on_progress, staging_dir)
            try:
                _run(ingestion, source, staging_dir)
            finally:
                ingestion.close()
            if source.error is not None:
                logging.error(f"Error reading the input file '{source.path}': {source.error}. The lines read before the "
                              "error were stored.")
        finally:
            source.close()
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
