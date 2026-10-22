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


# 'Certificates' columns not meaningful for each type, dropped by finalize_analysis()
_REMOVED_COLUMNS = {
    DatabaseType.LEAF: ("certificates_emitted_up_to",),
    DatabaseType.INTERMEDIATE: ("ocsp_stapling", "ocsp_must_stapling", "signature_valid", "SAN", "domain_matches_san"),
    DatabaseType.ROOT: ("ocsp_stapling", "ocsp_must_stapling", "certificates_up_to_root_count", "has_root_certificate",
                        "SAN", "domain_matches_san"),
}

# Plot query indexes as (name, "Table(columns)")
_CERTIFICATE_ID_INDEX = ("idx_certificate_id_leaf_domain", "Certificates(certificate_id, leaf_domain)")
CERTIFICATE_ID_INDEX_SQL = "CREATE INDEX IF NOT EXISTS %s ON %s" % _CERTIFICATE_ID_INDEX
_COMMON_INDEXES = (
    _CERTIFICATE_ID_INDEX,
    ("idx_certificates_issuer_id", "Certificates(issuer_id)"),
    ("idx_certificates_subject_id", "Certificates(subject_id)"),
    ("idx_certificates_ocsp_check", "Certificates(ocsp_check)"),
    ("idx_certificates_authority_info_access", "Certificates(authority_info_access)"),
    ("idx_certificates_validity_end", "Certificates(validity_end)"),
    ("idx_certificates_version", "Certificates(version)"),
    ("idx_issuers_common_name", "Issuers(common_name)"),
    ("idx_issuers_organization", "Issuers(organization)"),
    ("idx_subjects_subject_dn", "Subjects(subject_dn)"),
    ("idx_subjects_common_name", "Subjects(common_name)"),
    ("idx_subjects_subject_key_id", "Subjects(subject_key_id)"),
    ("idx_extensions_certificate_id", "Extensions(certificate_id)"),
    ("idx_extensions_key_usage", "Extensions(key_usage)"),
    ("idx_extensions_extended_key_usage", "Extensions(extended_key_usage)"),
)
_TYPE_INDEXES = {
    DatabaseType.LEAF: (
        ("idx_certificates_self_signed", "Certificates(self_signed)"),
        ("idx_certificates_signature_valid", "Certificates(signature_valid)"),
        ("idx_signed_cert_timestamps_certificate_id", "SignedCertificateTimestamps(certificate_id)"),
        ("idx_signed_cert_timestamps_log_id", "SignedCertificateTimestamps(log_id)"),
        ("idx_errors_domain", "Errors(domain)"),
        ("idx_errors_status", "Errors(status)"),
        ("idx_logs_operator_id", "Logs(operator_id)"),
        ("idx_logs_log_id", "Logs(log_id)"),
    ),
    DatabaseType.INTERMEDIATE: (("idx_certificates_self_signed", "Certificates(self_signed)"),),
    DatabaseType.ROOT: (("idx_certificates_signature_valid", "Certificates(signature_valid)"),),
}

# JSON rows per commit in bulk insert mode
ROWS_PER_COMMIT = 1000

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
            logging.info(f"Database eliminato con successo: {self.db_path}")

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        if self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone() is None:
            self._create_tables()
        else:
            self._ensure_certificate_id_index()
        logging.info(f"Connessione al database esistente: 'file://{self.db_path}'")

    def close(self) -> None:
        """Close the connection."""
        if self.conn is None:
            return
        self.conn.close()
        self.conn = None
        logging.info(f"Connessione al database {self.db_type.value.capitalize()} chiusa con successo: 'file://{self.db_path}'")

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
                logging.error(f"Transazione fallita: {e}")
            raise

    @contextmanager
    def bulk_insert_mode(self) -> Iterator[None]:
        """No fsync and one commit every ROWS_PER_COMMIT rows of row_transaction().

        Acceptable because the database is rebuilt on every analysis. The journal stays on disk, so a killed process
        is rolled back on the next open (a power loss is not); completed rows are committed even on Ctrl+C.
        """
        self._set_journal("TRUNCATE", "OFF")
        self._rows_per_commit = ROWS_PER_COMMIT
        logging.info("Modalità di inserimento massivo attivata.")
        try:
            yield
        finally:
            self._rows_per_commit = 1
            self._set_journal("DELETE", "FULL")
            logging.info("Modalità di inserimento massivo disattivata.")

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
                logging.error(f"Transazione annullata da SQLite: perse le {self._pending_rows} righe non ancora confermate.")
                self._pending_rows = 0
            if isinstance(e, Exception):
                logging.error(f"Transazione fallita: {e}")
            raise

        self.conn.execute("RELEASE SAVEPOINT row_transaction")
        self._pending_rows += 1
        if self._pending_rows >= self._rows_per_commit:
            self.conn.commit()
            self._pending_rows = 0

    def finalize_analysis(self) -> None:
        """Drop the tables and columns not needed by this database type."""
        drop_errors = self.db_type in (DatabaseType.INTERMEDIATE, DatabaseType.ROOT)
        logging.info("Rimozione tabelle e colonne non necessarie dal database in corso...")
        try:
            with self.transaction():
                if drop_errors:
                    self.conn.execute("DROP TABLE IF EXISTS Errors")
                self._drop_columns("Certificates", _REMOVED_COLUMNS[self.db_type])
        except Exception as e:
            logging.error("Errore durante la rimozione delle tabelle e delle colonne non necessarie: %s", e)
            return
        if drop_errors:
            logging.info("La tabella 'Errors' è stata eliminata con successo.")
        logging.info("Colonne specificate rimosse dalla tabella 'Certificates'.")

    def prepare_for_plots(self) -> None:
        """Create the plot indexes and apply the data corrections."""
        self._create_indexes()
        self._apply_database_corrections()

    def drop_secondary_indexes(self) -> None:
        """Drop the indexes that slow down bulk updates, keeping those used by the OCSP analysis."""
        logging.info("Rimozione indici dal database in corso...")
        try:
            # Automatic UNIQUE/PRIMARY KEY indexes cannot be dropped
            indexes = [row[0] for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")]
            if not indexes:
                logging.info("Nessun indice trovato nel database.")
                return
            with self.transaction():
                for name in indexes:
                    if name not in _OCSP_KEPT_INDEXES:
                        self.conn.execute(f'DROP INDEX IF EXISTS "{name}"')
            logging.info("Tutti gli indici, eccetto quelli ignorati, sono stati rimossi dal database.")
        except Exception as e:
            logging.error(f"Errore nel rimuovere gli indici: {e}")

    def _set_journal(self, journal_mode: str, synchronous: str) -> None:
        """Commit first: journal_mode cannot change inside a transaction."""
        self.conn.commit()
        self._pending_rows = 0
        self.conn.execute(f"PRAGMA journal_mode = {journal_mode}")
        self.conn.execute(f"PRAGMA synchronous = {synchronous}")

    def _create_tables(self) -> None:
        logging.info("Creazione tabelle nel database in corso...")
        with open(self.schema_path, 'r') as schema:
            self.conn.executescript(schema.read())
        logging.info("Tabelle create con successo.")

    def _ensure_certificate_id_index(self) -> None:
        """Index certificate_id on databases from older versions, whose column drop lost the 'Certificates' PRIMARY KEY."""
        columns = self.conn.execute("PRAGMA table_info(Certificates)").fetchall()
        if any(column[1] == 'certificate_id' and column[5] == 0 for column in columns):
            logging.info("Creazione dell'indice su 'certificate_id' per un database senza PRIMARY KEY in corso...")
            with self.transaction():
                self.conn.execute(CERTIFICATE_ID_INDEX_SQL)

    def _create_indexes(self) -> None:
        logging.info("Creazione indici nel database in corso...")
        with self.transaction():
            for index in _COMMON_INDEXES + _TYPE_INDEXES[self.db_type]:
                self.conn.execute("CREATE INDEX IF NOT EXISTS %s ON %s" % index)
        logging.info("Indici creati con successo.")

    def _apply_database_corrections(self) -> None:
        logging.info("Inizio delle correzioni al database.")
        try:
            with self.transaction():
                self.conn.execute("UPDATE Issuers SET organization = 'DigiCert Inc' WHERE organization = 'DigiCert, Inc.'")
            logging.info("Correzioni al database applicate.")
        except Exception as e:
            logging.error(f"Errore nell'applicare le correzioni: {e}")

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
