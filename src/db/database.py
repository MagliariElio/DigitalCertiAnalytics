from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from enum import Enum
from typing import Iterator

from db import schema
from db.raw_codec import DICTIONARY_ID, RawCodec, zstandard
from db.schema import APPLICATION_ID, PAGE_SIZE, SCHEMA_VERSION  # noqa: F401 (PAGE_SIZE re-exported)

# Admin: Anuar Elio Magliari
# Politecnico di Torino


class DatabaseType(Enum):
    LEAF = "leaf"
    INTERMEDIATE = "intermediate"
    ROOT = "root"


# Rows per commit of row_transaction() in bulk insert mode (the single-row path: the ingestion engine commits once
# per block of lines)
ROWS_PER_COMMIT = 1000

# Oldest SQLite with the window functions used by the ingestion
MIN_SQLITE_VERSION = (3, 25, 0)

_INSTALLER_HINT = "Run the installer again (install.sh on macOS and Linux, install.bat on Windows) to repair the installation."


class OutdatedDatabaseError(Exception):
    """The database file was created by an older version of the program, with another layout."""

    def __init__(self, db_type: DatabaseType, path: str | os.PathLike):
        self.db_type = db_type
        self.path = os.fspath(path)
        name = db_type.value
        super().__init__(f"The {name} database '{self.path}' was created by an older version of DigitalCertiAnalytics: run "
                         f"the analysis again with --{name}_analysis to recreate it.")


def database_state(path: str | os.PathLike) -> str:
    """'missing' (no file, empty file or no table), 'current' (this layout) or 'outdated' (anything else)."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return "missing"
    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
    except sqlite3.Error:
        return "outdated"
    try:
        if (conn.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
                and conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION):
            return "current"
        has_tables = conn.execute("SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view')").fetchone() is not None
        return "outdated" if has_tables else "missing"
    except sqlite3.Error:
        return "outdated"
    finally:
        conn.close()


def _check_requirements() -> None:
    """Clear errors instead of tracebacks for an SQLite without window functions or a missing zstandard module."""
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise RuntimeError(f"SQLite {sqlite3.sqlite_version} is too old: DigitalCertiAnalytics needs SQLite 3.25 or "
                           f"newer. {_INSTALLER_HINT}")
    if zstandard is None:
        raise RuntimeError(f"The Python package 'zstandard' is not installed. {_INSTALLER_HINT}")


class Database:
    """SQLite certificate database of one type."""

    def __init__(self, db_path: str | os.PathLike, db_type: DatabaseType):
        self.db_path = os.path.abspath(db_path)
        self.db_type = db_type
        self.conn: sqlite3.Connection | None = None
        self._rows_per_commit = 1       # row_transaction() rows per commit
        self._pending_rows = 0
        self.whole_rollbacks = 0        # transactions rolled back by SQLite itself in row_transaction()
        self._codec: RawCodec | None = None

    def connect(self, delete_database: bool = False) -> None:
        """Connect, optionally deleting the file first; a missing or empty database gets the schema.

        A database of an older layout raises OutdatedDatabaseError (unless it is deleted first).
        """
        _check_requirements()
        if delete_database and os.path.exists(self.db_path):
            os.remove(self.db_path)
            logging.info(f"Database deleted: {self.db_path}")

        state = database_state(self.db_path)
        if state == "outdated":
            raise OutdatedDatabaseError(self.db_type, self.db_path)
        # The ingestion copies into the three databases from parallel threads (one connection each, never shared)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._codec = None
        if state == "missing":
            self._create_tables()
        logging.info(f"Connected to the existing database: 'file://{self.db_path}'")

    def close(self) -> None:
        """Close the connection."""
        if self.conn is None:
            return
        self.conn.close()
        self.conn = None
        logging.info(f"Connection to the {self.db_type.value.capitalize()} database closed: 'file://{self.db_path}'")

    @property
    def pending_rows(self) -> int:
        """Rows stored since the last commit, reported as lost if SQLite rolls back the whole transaction."""
        return self._pending_rows

    @pending_rows.setter
    def pending_rows(self, count: int) -> None:
        self._pending_rows = count

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run the block in one transaction: commit on success, rollback on error or interrupt."""
        # Explicit BEGIN so DDL (CREATE, DROP, ALTER) is part of the transaction too
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")
        try:
            yield
            self.conn.commit()
        except BaseException as e:
            # KeyboardInterrupt must roll back partial work too
            self.conn.rollback()
            if isinstance(e, Exception):
                logging.error(f"Transaction failed: {e}")
            raise

    @contextmanager
    def bulk_insert_mode(self) -> Iterator[None]:
        """No fsync and one commit every ROWS_PER_COMMIT rows of row_transaction().

        Acceptable because the database is rebuilt on every analysis. The journal stays on disk, so a killed process
        is rolled back on the next open (a power loss is not); completed rows are committed even on Ctrl+C.
        """
        self._set_journal("TRUNCATE", "OFF")
        self._rows_per_commit = ROWS_PER_COMMIT
        logging.info("Bulk insert mode enabled.")
        try:
            yield
        finally:
            self._rows_per_commit = 1
            self._set_journal("DELETE", "FULL")
            logging.info("Bulk insert mode disabled.")

    @contextmanager
    def row_transaction(self) -> Iterator[None]:
        """Run one row in a SAVEPOINT, so an error or interrupt discards only that row.

        Commits every ROWS_PER_COMMIT rows in bulk insert mode, otherwise after every row.
        """
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")
        self.conn.execute("SAVEPOINT row_transaction")
        try:
            yield
        except BaseException as e:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK TO SAVEPOINT row_transaction")
                self.conn.execute("RELEASE SAVEPOINT row_transaction")
            else:
                # SQLite already rolled back the whole transaction (e.g. disk full): the pending rows are lost too
                logging.error(f"Transaction rolled back by SQLite: the rows of {self._pending_rows} uncommitted lines "
                              "were lost.")
                self._pending_rows = 0
                self.whole_rollbacks += 1
            if isinstance(e, Exception):
                logging.error(f"Transaction failed: {e}")
            raise

        self.conn.execute("RELEASE SAVEPOINT row_transaction")
        self._pending_rows += 1
        if self._pending_rows >= self._rows_per_commit:
            self.conn.commit()
            self._pending_rows = 0

    def prepare_for_plots(self) -> None:
        """Apply the data corrections used by the charts."""
        logging.info("Applying the database corrections.")
        try:
            with self.transaction():
                self.conn.execute("UPDATE IssuerData SET organization = 'DigiCert Inc' "
                                  "WHERE organization = 'DigiCert, Inc.'")
            logging.info("Database corrections applied.")
        except Exception as e:
            logging.error(f"Error applying the corrections: {e}")

    def set_raw_dictionary(self, dictionary: bytes | None) -> None:
        """Store the zstd dictionary of the raw certificates (None: no dictionary); only before the first raw."""
        if self.conn.execute("SELECT 1 FROM RawCertificates LIMIT 1").fetchone() is not None:
            raise RuntimeError("The raw dictionary cannot change once raw certificates are stored.")
        with self.transaction():
            self.conn.execute("DELETE FROM SchemaInfo WHERE key = 'raw_dictionary_id'")
            self.conn.execute("DELETE FROM RawDictionaries")
            if dictionary is not None:
                self.conn.execute("INSERT INTO RawDictionaries (dictionary_id, zstd_dictionary) VALUES (?, ?)",
                                  (DICTIONARY_ID, dictionary))
                self.conn.execute("INSERT INTO SchemaInfo (key, value) VALUES ('raw_dictionary_id', ?)",
                                  (DICTIONARY_ID,))
        self._codec = None

    def raw_codec(self) -> RawCodec:
        """Codec of the raw certificates of this database."""
        if self._codec is None:
            self._codec = RawCodec.for_connection(self.conn)
        return self._codec

    def _set_journal(self, journal_mode: str, synchronous: str) -> None:
        """Commit first: journal_mode cannot change inside a transaction."""
        self.conn.commit()
        self._pending_rows = 0
        self.conn.execute(f"PRAGMA journal_mode = {journal_mode}")
        self.conn.execute(f"PRAGMA synchronous = {synchronous}")

    def _create_tables(self) -> None:
        """Create the tables and views of this database type."""
        logging.info("Creating the database tables...")
        schema.create(self.conn, self.db_type)
        logging.info("Tables created.")
