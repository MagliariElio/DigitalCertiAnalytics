from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from enum import Enum
from typing import Iterator

# Admin: Anuar Elio Magliari
# Politecnico di Torino


class DatabaseType(Enum):
    LEAF = "leaf"
    INTERMEDIATE = "intermediate"
    ROOT = "root"


# 'Certificates' columns not meaningful for each type, dropped when the database is created
_REMOVED_COLUMNS = {
    DatabaseType.LEAF: ("certificates_emitted_up_to",),
    DatabaseType.INTERMEDIATE: ("ocsp_stapling", "ocsp_must_stapling", "signature_valid", "SAN", "domain_matches_san"),
    DatabaseType.ROOT: ("ocsp_stapling", "ocsp_must_stapling", "certificates_up_to_root_count", "has_root_certificate",
                        "SAN", "domain_matches_san"),
}

# Index on certificate_id for databases of older versions without the 'Certificates' PRIMARY KEY, as (name,
# "Table(columns)")
_CERTIFICATE_ID_INDEX = ("idx_certificate_id_leaf_domain", "Certificates(certificate_id, leaf_domain)")
CERTIFICATE_ID_INDEX_SQL = "CREATE INDEX IF NOT EXISTS %s ON %s" % _CERTIFICATE_ID_INDEX
# Indexes built by prepare_for_plots(), as (name, "Table(columns)"). The statistics read the tables sequentially
# (StatisticsDAO.materialize), so they need no index; these two fix the plan, and so the order of equal counts, of the
# per-query SQL of get_issuer_certificate_count, which the materialized statistics reproduce.
# idx_issuers_organization also serves the WHERE of the DigiCert correction.
_PLOT_INDEXES = (
    ("idx_certificates_issuer_id", "Certificates(issuer_id)"),
    ("idx_issuers_organization", "Issuers(organization)"),
)

# Rows per commit of row_transaction() in bulk insert mode (the single-row path: the ingestion engine commits once
# per block of lines)
ROWS_PER_COMMIT = 1000

# Page size of new databases: fewer, larger pages make the ingestion commits, the full-table updates of the OCSP
# analysis, the index creation and the statistics queries faster
PAGE_SIZE = 65536

# Page cache (KiB, as a negative cache_size) and sorter threads while the chart indexes are built. A small cache makes
# the sorter write small runs, sorted by the threads in parallel: faster than 256 MiB and with less memory.
_INDEX_CACHE_KIB = 16384
_INDEX_SORTER_THREADS = 4

# Indexes kept by drop_secondary_indexes(): the OCSP analysis selects and updates through them
_OCSP_KEPT_INDEXES = frozenset({
    'idx_certificates_ocsp_check',
    'idx_certificates_authority_info_access',
    'idx_logs_log_id',
    'idx_certificate_id_leaf_domain',
})


def _column_definition(column: sqlite3.Row, single_primary_key: bool) -> str:
    """SQL column definition from a PRAGMA table_info row (cid, name, type, notnull, dflt_value, pk)."""
    _, name, column_type, not_null, default, primary_key = column
    definition = f"{name} {column_type}".strip()
    if single_primary_key and primary_key:
        definition += " PRIMARY KEY"
    if not_null:
        definition += " NOT NULL"
    if default is not None:
        definition += f" DEFAULT {default}"
    return definition


class Database:
    """SQLite certificate database of one type."""

    def __init__(self, db_path: str | os.PathLike, schema_path: str | os.PathLike, db_type: DatabaseType):
        self.db_path = os.path.abspath(db_path)
        self.schema_path = schema_path
        self.db_type = db_type
        self.conn: sqlite3.Connection | None = None
        self._rows_per_commit = 1       # row_transaction() rows per commit
        self._pending_rows = 0

    def connect(self, delete_database: bool = False) -> None:
        """Connect, optionally deleting the file first; an empty database gets the schema."""
        if delete_database and os.path.exists(self.db_path):
            os.remove(self.db_path)
            logging.info(f"Database deleted: {self.db_path}")

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        if self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone() is None:
            self._create_tables()
        else:
            self._ensure_certificate_id_index()
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
            if isinstance(e, Exception):
                logging.error(f"Transaction failed: {e}")
            raise

        self.conn.execute("RELEASE SAVEPOINT row_transaction")
        self._pending_rows += 1
        if self._pending_rows >= self._rows_per_commit:
            self.conn.commit()
            self._pending_rows = 0

    def finalize_analysis(self) -> None:
        """Drop the tables and columns not needed by this database type.

        New databases are created with the final layout, so this only rebuilds databases from older versions.
        """
        drop_errors = self.db_type in (DatabaseType.INTERMEDIATE, DatabaseType.ROOT) and self._table_exists("Errors")
        columns = {column[1] for column in self.conn.execute("PRAGMA table_info(Certificates)")}
        if not drop_errors and columns.isdisjoint(_REMOVED_COLUMNS[self.db_type]):
            return
        logging.info("Removing the unneeded tables and columns from the database...")
        try:
            with self.transaction():
                if drop_errors:
                    self.conn.execute("DROP TABLE IF EXISTS Errors")
                self._drop_columns("Certificates", _REMOVED_COLUMNS[self.db_type])
        except Exception as e:
            logging.error("Error removing the unneeded tables and columns: %s", e)
            return
        if drop_errors:
            logging.info("The 'Errors' table was dropped.")
        logging.info("The unneeded columns were removed from the 'Certificates' table.")

    def prepare_for_plots(self) -> None:
        """Create the chart indexes (_PLOT_INDEXES) and apply the data corrections.

        Indexes that databases of earlier versions already have are kept.
        """
        self._create_indexes()
        self._apply_database_corrections()

    def drop_secondary_indexes(self) -> None:
        """Drop the indexes that slow down bulk updates, keeping those used by the OCSP analysis."""
        logging.info("Removing the indexes from the database...")
        try:
            # Automatic UNIQUE/PRIMARY KEY indexes cannot be dropped
            indexes = [row[0] for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")]
            if not indexes:
                logging.info("No index found in the database.")
                return
            with self.transaction():
                for name in indexes:
                    if name not in _OCSP_KEPT_INDEXES:
                        self.conn.execute(f'DROP INDEX IF EXISTS "{name}"')
            logging.info("All the indexes except the ones kept for the OCSP analysis were removed from the database.")
        except Exception as e:
            logging.error(f"Error removing the indexes: {e}")

    def _set_journal(self, journal_mode: str, synchronous: str) -> None:
        """Commit first: journal_mode cannot change inside a transaction."""
        self.conn.commit()
        self._pending_rows = 0
        self.conn.execute(f"PRAGMA journal_mode = {journal_mode}")
        self.conn.execute(f"PRAGMA synchronous = {synchronous}")

    def _create_tables(self) -> None:
        """Create the schema with the final layout of this database type.

        The type-specific columns and the 'Errors' table are dropped now, on empty tables: dropping them after the
        analysis would copy the whole 'Certificates' table.
        """
        logging.info("Creating the database tables...")
        # Effective only before the first table is created
        self.conn.execute(f"PRAGMA page_size = {PAGE_SIZE}")
        with open(self.schema_path, 'r') as schema:
            self.conn.executescript(schema.read())
        with self.transaction():
            if self.db_type in (DatabaseType.INTERMEDIATE, DatabaseType.ROOT):
                self.conn.execute("DROP TABLE IF EXISTS Errors")
            self._drop_columns("Certificates", _REMOVED_COLUMNS[self.db_type])
        logging.info("Tables created.")

    def _table_exists(self, table: str) -> bool:
        return self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None

    def _ensure_certificate_id_index(self) -> None:
        """Index certificate_id on databases from older versions, whose column drop lost the 'Certificates' PRIMARY KEY."""
        columns = self.conn.execute("PRAGMA table_info(Certificates)").fetchall()
        if any(column[1] == 'certificate_id' and column[5] == 0 for column in columns):
            logging.info("Creating the index on 'certificate_id' for a database without a PRIMARY KEY...")
            with self.transaction():
                self.conn.execute(CERTIFICATE_ID_INDEX_SQL)

    def _create_indexes(self) -> None:
        logging.info("Creating the database indexes...")
        # A larger page cache and parallel sorting speed up building the indexes of large tables
        cache_size = self.conn.execute("PRAGMA cache_size").fetchone()[0]
        threads = self.conn.execute("PRAGMA threads").fetchone()[0]
        self.conn.execute(f"PRAGMA cache_size = {-_INDEX_CACHE_KIB}")
        self.conn.execute(f"PRAGMA threads = {min(_INDEX_SORTER_THREADS, os.cpu_count() or 1)}")
        try:
            with self.transaction():
                for index in _PLOT_INDEXES:
                    self.conn.execute("CREATE INDEX IF NOT EXISTS %s ON %s" % index)
        finally:
            self.conn.execute(f"PRAGMA cache_size = {cache_size}")
            self.conn.execute(f"PRAGMA threads = {threads}")
        logging.info("Indexes created.")

    def _apply_database_corrections(self) -> None:
        logging.info("Applying the database corrections.")
        try:
            with self.transaction():
                self.conn.execute("UPDATE Issuers SET organization = 'DigiCert Inc' WHERE organization = 'DigiCert, Inc.'")
            logging.info("Database corrections applied.")
        except Exception as e:
            logging.error(f"Error applying the corrections: {e}")

    def _drop_columns(self, table: str, removed_columns: tuple[str, ...]) -> None:
        """Recreate the table without the given columns; must run inside a transaction.

        Type, NOT NULL, DEFAULT and PRIMARY KEY of the other columns are kept, so certificate_id stays a rowid alias.
        """
        columns = [column for column in self.conn.execute(f"PRAGMA table_info({table})") if column[1] not in removed_columns]
        primary_keys = sorted((column for column in columns if column[5] > 0), key=lambda column: column[5])
        definitions = [_column_definition(column, len(primary_keys) == 1) for column in columns]
        if len(primary_keys) > 1:
            definitions.append(f"PRIMARY KEY ({', '.join(column[1] for column in primary_keys)})")

        names = ', '.join(column[1] for column in columns)
        new_table = f"{table}_new"
        self.conn.execute(f"DROP TABLE IF EXISTS {new_table}")
        self.conn.execute(f"CREATE TABLE {new_table} ({', '.join(definitions)})")
        self.conn.execute(f"INSERT INTO {new_table} ({names}) SELECT {names} FROM {table}")
        self.conn.execute(f"DROP TABLE {table}")
        self.conn.execute(f"ALTER TABLE {new_table} RENAME TO {table}")
