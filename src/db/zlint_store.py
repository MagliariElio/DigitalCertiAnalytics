"""ZLint results stored in the certificate database of the type (SQLite tables next to the certificates).

Each distinct raw certificate is linted once: ZlintResults has one row per RawCertificates row used by a certificate
(raw_id 0 stands for the certificates without a raw), pointing either to its ZLint output (ZlintBodies) or to the
error that stopped it. Equal outputs are stored once, zstd-compressed with the first output of the run as dictionary
(about 360 bytes instead of 19 KB each). ZlintIssuers keeps the issuer fields as they were when ZLint ran, as the
MongoDB documents of earlier versions did, even if the chart correction changes them later. The ZlintDocuments view
shows one row per certificate occurrence (the certificate_id of the other tables and of the logs), like the former
MongoDB documents.

A run starts by dropping and recreating these tables, so the results always belong to the certificates of the file.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, NamedTuple

try:
    import zstandard
except ImportError:          # reported by Database.connect() with a clear message
    zstandard = None

# Admin: Anuar Elio Magliari
# Politecnico di Torino

BODY_COMPRESSION_LEVEL = 9
BODY_DICTIONARY_ID = 1
# Digests of stored bodies kept in memory to skip their lookup; beyond this the cache restarts (memory stays bounded
# when nearly every certificate has its own output)
BODY_CACHE_SIZE = 200_000

ZLINT_TABLES = ("ZlintRun", "ZlintDictionaries", "ZlintBodies", "ZlintResults", "ZlintIssuers")
ZLINT_VIEW = "ZlintDocuments"

ZLINT_DDL = """
CREATE TABLE ZlintRun (key TEXT PRIMARY KEY NOT NULL, value) WITHOUT ROWID;
CREATE TABLE ZlintDictionaries (dictionary_id INTEGER PRIMARY KEY, zstd_dictionary BLOB NOT NULL);
CREATE TABLE ZlintBodies (body_id INTEGER PRIMARY KEY, sha256 BLOB NOT NULL UNIQUE, body_zstd BLOB NOT NULL);
CREATE TABLE ZlintResults (
    raw_id INTEGER PRIMARY KEY,
    body_id INTEGER REFERENCES ZlintBodies(body_id),
    error_message TEXT,
    error_timestamp TEXT,
    CHECK ((body_id IS NULL) <> (error_message IS NULL))
);
CREATE TABLE ZlintIssuers (issuer_id INTEGER PRIMARY KEY, common_name VARCHAR, organization VARCHAR, issuer_dn TEXT);
CREATE VIEW ZlintDocuments AS
SELECT o.occurrence_id AS certificate_id, o.leaf_domain, zi.common_name AS issuer_common_name,
       zi.organization AS issuer_organization, zi.issuer_dn, zr.body_id, zr.error_message, zr.error_timestamp
FROM Occurrences AS o JOIN CertificateData AS c ON c.certificate_id = o.certificate_id
JOIN ZlintResults AS zr ON zr.raw_id = COALESCE(c.raw_id, 0)
LEFT JOIN ZlintIssuers AS zi ON zi.issuer_id = o.issuer_id;
"""

# The distinct raw certificates of the certificates (raws used only by issuers are not linted), in raw_id order
_UNITS_TABLE = "zlint_units"
_UNITS_SQL = (f"CREATE TEMP TABLE {_UNITS_TABLE} (raw_id INTEGER PRIMARY KEY)",
              f"INSERT OR IGNORE INTO temp.{_UNITS_TABLE} SELECT COALESCE(raw_id, 0) FROM main.CertificateData")
_UNITS_BATCH_SQL = (f"SELECT u.raw_id, r.der_zstd, r.raw FROM temp.{_UNITS_TABLE} AS u "
                    "LEFT JOIN main.RawCertificates AS r ON r.raw_id = u.raw_id "
                    "WHERE u.raw_id > ? ORDER BY u.raw_id LIMIT ?")
_RESULT_INSERT = "INSERT INTO ZlintResults (raw_id, body_id, error_message, error_timestamp) VALUES (?, ?, ?, ?)"


class LintResult(NamedTuple):
    """Outcome of linting one raw certificate: a body and its digest, or an error message and its time."""
    raw_id: int
    digest: bytes | None
    body: bytes | None
    error_message: str | None
    error_timestamp: str | None


def encode_body(zlint_result: object) -> bytes:
    """The stored form of a ZLint output: compact JSON, which keeps the key order and the value types."""
    return json.dumps(zlint_result, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")


def decode_body(body: bytes) -> object:
    return json.loads(body.decode("utf-8", "surrogatepass"))


def body_digest(body: bytes) -> bytes:
    return hashlib.sha256(body).digest()


def timestamp() -> str:
    """Current time in the logging format (e.g. '2024-10-06 12:30:00,123')."""
    now = datetime.now()
    return f"{now:%Y-%m-%d %H:%M:%S},{now.microsecond // 1000:03d}"


def _body_codec(dictionary: bytes) -> tuple[zstandard.ZstdCompressor, zstandard.ZstdDecompressor]:
    data = zstandard.ZstdCompressionDict(dictionary, dict_type=zstandard.DICT_TYPE_RAWCONTENT)
    compressor = zstandard.ZstdCompressor(level=BODY_COMPRESSION_LEVEL, dict_data=data, write_checksum=False,
                                          write_content_size=True, write_dict_id=False)
    return compressor, zstandard.ZstdDecompressor(dict_data=data)


def has_tables(conn: sqlite3.Connection) -> bool:
    """Whether the database holds the ZLint tables (a run started on it)."""
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}
    return names.issuperset((*ZLINT_TABLES, ZLINT_VIEW))


@contextmanager
def _transaction(conn: sqlite3.Connection) -> Iterator[None]:
    if not conn.in_transaction:
        conn.execute("BEGIN")
    try:
        yield
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


class ZlintStore:
    """Writes the results of a ZLint run into the certificate database of the connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._compressor: zstandard.ZstdCompressor | None = None
        self._body_ids: dict[bytes, int] = {}
        self.started = False

    def start(self, zlint_version: str | None) -> None:
        """Replace the results of a previous run with empty tables and the issuers as they are now."""
        with _transaction(self._conn):
            self._conn.execute(f"DROP VIEW IF EXISTS {ZLINT_VIEW}")
            for table in reversed(ZLINT_TABLES):
                self._conn.execute(f"DROP TABLE IF EXISTS {table}")
            for statement in ZLINT_DDL.split(";"):
                if statement.strip():
                    self._conn.execute(statement)
            self._conn.execute("INSERT INTO ZlintIssuers (issuer_id, common_name, organization, issuer_dn) "
                               "SELECT issuer_id, common_name, organization, issuer_dn FROM IssuerData")
            self._set_run_values(zlint_version=zlint_version, started=timestamp(), state="running")
        self._compressor = None
        self._body_ids.clear()
        self.started = True

    def prepare_units(self) -> int:
        """Collect the distinct raw certificates to lint; return their number."""
        self._conn.execute(f"DROP TABLE IF EXISTS temp.{_UNITS_TABLE}")
        with _transaction(self._conn):
            for statement in _UNITS_SQL:
                self._conn.execute(statement)
        count = self._conn.execute(f"SELECT COUNT(*) FROM temp.{_UNITS_TABLE}").fetchone()[0]
        with _transaction(self._conn):
            self._set_run_values(units=count)
        return count

    def iter_units(self, batch_size: int) -> Iterator[list[tuple[int, bytes | None, object]]]:
        """Batches of (raw_id, der_zstd, raw) in raw_id order (keyset pagination: commits in between are safe)."""
        last = -1
        while True:
            cursor = self._conn.cursor()
            cursor.row_factory = None
            rows = cursor.execute(_UNITS_BATCH_SQL, (last, batch_size)).fetchall()
            if not rows:
                return
            yield rows
            last = rows[-1][0]

    def drop_units(self) -> None:
        self._conn.execute(f"DROP TABLE IF EXISTS temp.{_UNITS_TABLE}")

    def save(self, results: list[LintResult]) -> None:
        """Store the results in one transaction (all or none of them)."""
        if not results:
            return
        new_bodies: dict[bytes, int] = {}
        had_dictionary = self._compressor is not None
        try:
            with _transaction(self._conn):
                rows = [(result.raw_id, self._body_id(result, new_bodies) if result.digest is not None else None,
                         result.error_message, result.error_timestamp) for result in results]
                self._conn.executemany(_RESULT_INSERT, rows)
        except BaseException:
            if not had_dictionary:
                # The dictionary was rolled back with the bodies
                self._compressor = None
            raise
        if len(self._body_ids) + len(new_bodies) > BODY_CACHE_SIZE:
            self._body_ids.clear()
        self._body_ids.update(new_bodies)

    def finish(self, state: str) -> None:
        """Record how the run ended: 'finished', 'interrupted' or 'failed'."""
        with _transaction(self._conn):
            self._set_run_values(state=state, ended=timestamp())

    def error_occurrences(self) -> Iterator[tuple[int, str]]:
        """(certificate_id, error_message) of every occurrence whose certificate could not be linted, in id order."""
        if self._conn.execute("SELECT 1 FROM ZlintResults WHERE error_message IS NOT NULL LIMIT 1").fetchone() is None:
            return iter(())
        cursor = self._conn.cursor()
        cursor.row_factory = None
        return cursor.execute(f"SELECT certificate_id, error_message FROM {ZLINT_VIEW} "
                              "WHERE error_message IS NOT NULL ORDER BY certificate_id")

    def _body_id(self, result: LintResult, new_bodies: dict[bytes, int]) -> int:
        digest = result.digest
        body_id = self._body_ids.get(digest) or new_bodies.get(digest)
        if body_id is None:
            row = self._conn.execute("SELECT body_id FROM ZlintBodies WHERE sha256 = ?", (digest,)).fetchone()
            body_id = row[0] if row is not None else self._insert_body(digest, result.body)
            new_bodies[digest] = body_id
        return body_id

    def _insert_body(self, digest: bytes, body: bytes) -> int:
        if self._compressor is None:
            # The first output of the run is the dictionary of all of them: outputs differ in a few lints only
            self._conn.execute("INSERT INTO ZlintDictionaries (dictionary_id, zstd_dictionary) VALUES (?, ?)",
                               (BODY_DICTIONARY_ID, body))
            self._compressor = _body_codec(body)[0]
        return self._conn.execute("INSERT INTO ZlintBodies (sha256, body_zstd) VALUES (?, ?)",
                                  (digest, self._compressor.compress(body))).lastrowid

    def _set_run_values(self, **values: object) -> None:
        self._conn.executemany("INSERT OR REPLACE INTO ZlintRun (key, value) VALUES (?, ?)", values.items())


class ZlintReader:
    """Reads the stored ZLint results (read-only use)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        row = conn.execute("SELECT zstd_dictionary FROM ZlintDictionaries WHERE dictionary_id = ?",
                           (BODY_DICTIONARY_ID,)).fetchone()
        self._decompressor = _body_codec(bytes(row[0]))[1] if row is not None else None

    def has_results(self) -> bool:
        return self._conn.execute("SELECT 1 FROM ZlintResults WHERE body_id IS NOT NULL LIMIT 1").fetchone() is not None

    def run_values(self) -> dict[str, object]:
        return dict(self._conn.execute("SELECT key, value FROM ZlintRun"))

    def body(self, body_id: int) -> object:
        """The ZLint output (parsed JSON) of a stored body."""
        row = self._conn.execute("SELECT body_zstd FROM ZlintBodies WHERE body_id = ?", (body_id,)).fetchone()
        return decode_body(self._decompressor.decompress(row[0]))

    def documents(self, columns: str = "*", where: str = "") -> Iterator[tuple]:
        """Rows of ZlintDocuments (one per certificate occurrence that was linted) in certificate_id order."""
        cursor = self._conn.cursor()
        cursor.row_factory = None
        return cursor.execute(f"SELECT {columns} FROM {ZLINT_VIEW} {f'WHERE {where}' if where else ''} "
                              "ORDER BY certificate_id")
