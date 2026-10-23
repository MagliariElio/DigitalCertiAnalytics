"""Tests for Database, CertificateDAO and Certificate."""
import base64
import datetime
import logging
import sqlite3
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from helpers import error_row, raw, success_row, zgrab_certificate

from bean.certificate import Certificate
from dao.certificate_dao import CertificateDAO
from dao.statistics_dao import StatisticsDAO
from db.database import PAGE_SIZE, Database, DatabaseType
from utils.chain_utils import find_root_certificate, intermediate_certificates, verify_signature

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "src" / "db" / "schema_db.sql"
UPDATE_PLAN = "EXPLAIN QUERY PLAN UPDATE Certificates SET signature_valid='Valid' WHERE certificate_id=1"


def certificate_columns(database):
    return {row[1]: row for row in database.conn.execute("PRAGMA table_info(Certificates)")}


def ingest_leaf(database, dao, rows):
    for row in rows:
        with database.transaction():
            if row["data"]["tls"]["status"] == "success":
                server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
                dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
            else:
                dao.insert_error_row(row)


def test_leaf_ingestion_and_finalize_keeps_primary_key(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    rows = pki.rows(6)
    ingest_leaf(database, dao, rows)
    database.finalize_analysis()

    columns = certificate_columns(database)
    assert columns["certificate_id"][5] == 1, "certificate_id must remain the PRIMARY KEY"
    assert "certificates_emitted_up_to" not in columns
    assert dao.get_certificates_count() == 6
    assert database.conn.execute("SELECT COUNT(*) FROM Errors").fetchone()[0] == 2
    assert database.conn.execute("SELECT COUNT(*) FROM SignedCertificateTimestamps").fetchone()[0] == 12
    has_root = database.conn.execute(
        "SELECT has_root_certificate, COUNT(*) FROM Certificates GROUP BY 1 ORDER BY 1").fetchall()
    assert [tuple(r) for r in has_root] == [(0, 3), (1, 3)]
    plan = database.conn.execute(UPDATE_PLAN).fetchall()
    assert "PRIMARY KEY" in plan[0][-1]


def test_rows_are_not_mutated(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    row = pki.rows(1)[0]
    before = repr(row)
    ingest_leaf(database, dao, [row])
    assert repr(row) == before


def test_intermediate_and_root_ingestion(pki, open_database):
    intermediate_db, intermediate_dao = open_database(DatabaseType.INTERMEDIATE)
    root_db, root_dao = open_database(DatabaseType.ROOT)
    for row in pki.rows(4):
        if row["data"]["tls"]["status"] != "success":
            continue
        server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
        with intermediate_db.transaction():
            for emitted, (cert, remaining) in enumerate(intermediate_certificates(server["chain"], server["certificate"]), 1):
                intermediate_dao.process_insert_certificate(row, cert, remaining, emitted)
        root, count = find_root_certificate(server["chain"], server["certificate"])
        if root:
            with root_db.transaction():
                root_dao.process_insert_certificate(row, root, [], count)
    intermediate_db.finalize_analysis()
    root_db.finalize_analysis()

    assert intermediate_dao.get_certificates_count() == 4
    assert root_dao.get_certificates_count() == 2
    assert "SAN" not in certificate_columns(intermediate_db)
    assert "has_root_certificate" not in certificate_columns(root_db)
    assert StatisticsDAO(root_db.conn, DatabaseType.ROOT).get_signature_validity_distribution() == {"Valid": 1}
    tables = {row[0] for row in root_db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "Errors" not in tables


def test_transaction_rolls_back_on_keyboard_interrupt(open_database):
    database, _ = open_database()
    with pytest.raises(KeyboardInterrupt):
        with database.transaction():
            database.conn.execute("INSERT INTO Errors (domain) VALUES ('x')")
            raise KeyboardInterrupt
    assert database.conn.execute("SELECT COUNT(*) FROM Errors").fetchone()[0] == 0


def test_bulk_insert_mode_restores_journal(open_database):
    database, _ = open_database()
    with database.bulk_insert_mode():
        assert database.conn.execute("PRAGMA journal_mode").fetchone()[0] == "truncate"
    assert database.conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_legacy_database_gets_certificate_id_index(tmp_path, pki, open_database):
    database, dao = open_database(DatabaseType.LEAF, name="legacy.db")
    ingest_leaf(database, dao, pki.rows(2))
    database.close()
    # Simulate a database from older versions: Certificates without PRIMARY KEY
    conn = sqlite3.connect(tmp_path / "legacy.db")
    conn.executescript("""
        CREATE TABLE Certificates_old AS SELECT * FROM Certificates;
        DROP TABLE Certificates;
        ALTER TABLE Certificates_old RENAME TO Certificates;
    """)
    conn.close()
    database.connect()
    plan = database.conn.execute(UPDATE_PLAN).fetchall()
    assert "idx_certificate_id_leaf_domain" in plan[0][-1]


def test_iterators_and_updates(pki, open_database):
    database, dao = open_database()
    ingest_leaf(database, dao, pki.rows(7))
    batches = list(dao.iter_leaf_domains(batch_size=3))
    assert [len(batch) for batch in batches] == [3, 3, 1]
    ids = [certificate_id for batch in batches for certificate_id, _ in batch]
    assert ids == sorted(ids) and len(set(ids)) == 7
    assert sum(len(batch) for batch in dao.iter_raw_certificates(batch_size=2)) == 7
    with database.transaction():
        dao.update_signature_validity([("Not Valid", ids[0])])
    row = database.conn.execute("SELECT signature_valid FROM Certificates WHERE certificate_id=?", (ids[0],)).fetchone()
    assert row[0] == "Not Valid"


def test_statistics_count_certificates_without_ski_individually(pki, open_database):
    database, dao = open_database()
    rows = []
    for i in range(3):
        leaf = zgrab_certificate(pki.leaf(f"noski{i}.example.test", 7000 + i), with_ski=False)
        leaf["parsed"]["version"] = 1
        rows.append(success_row(f"noski{i}.example.test", leaf, []))
    rows += pki.rows(2) + [error_row("x.example.test")]
    ingest_leaf(database, dao, rows)
    statistics = StatisticsDAO(database.conn, DatabaseType.LEAF)
    assert statistics.get_certificate_version_distribution() == {1: 3, 3: 2}
    assert statistics.get_status_analysis() == {"success": 5, "connection-timeout": 2, "unknown-error": 1}
    assert statistics.get_sct_count_per_certificate() == {0: 3, 2: 2}


def test_row_transactions_are_batched_and_isolated(open_database):
    database, _ = open_database()
    with database.bulk_insert_mode():
        for i in range(5):
            try:
                with database.row_transaction():
                    database.conn.execute("INSERT INTO Errors (domain) VALUES (?)", (f"d{i}",))
                    if i == 2:
                        raise ValueError("invalid row")
            except ValueError:
                pass
        assert database.conn.in_transaction, "rows are committed in blocks"
    domains = [row[0] for row in database.conn.execute("SELECT domain FROM Errors ORDER BY error_id")]
    assert domains == ["d0", "d1", "d3", "d4"]
    assert not database.conn.in_transaction


def test_disk_full_reports_the_real_error_and_lost_rows(open_database, caplog):
    database, _ = open_database()
    page_count = database.conn.execute("PRAGMA page_count").fetchone()[0]
    database.conn.execute(f"PRAGMA max_page_count = {page_count + 2}")
    errors = set()
    with database.bulk_insert_mode():
        for i in range(2000):
            try:
                with database.row_transaction():
                    database.conn.execute("INSERT INTO Errors (domain, error_message) VALUES (?, ?)", (f"d{i}", "x" * 200))
            except sqlite3.OperationalError as e:
                errors.add(str(e))
    assert errors == {"database or disk is full"}
    assert "uncommitted lines were lost" in caplog.text


def test_whole_rollback_reports_the_pending_rows_added_by_the_caller(open_database, caplog):
    """The ingestion engine adds the rows it copies in bulk to pending_rows, so a lost transaction reports them too."""
    database, _ = open_database()
    database.conn.execute("CREATE TEMP TRIGGER full_disk BEFORE INSERT ON main.Errors WHEN NEW.domain = 'full' "
                          "BEGIN SELECT RAISE(ROLLBACK, 'database or disk is full'); END")
    with database.bulk_insert_mode():
        database.conn.execute("BEGIN")
        database.conn.executemany("INSERT INTO Errors (domain) VALUES (?)", [("copied",)] * 3)
        database.pending_rows += 3
        with database.row_transaction():
            database.conn.execute("INSERT INTO Errors (domain) VALUES ('row')")
        assert database.pending_rows == 4
        with pytest.raises(sqlite3.IntegrityError):
            with database.row_transaction():
                database.conn.execute("INSERT INTO Errors (domain) VALUES ('full')")
        assert database.pending_rows == 0
    assert "the rows of 4 uncommitted lines were lost" in caplog.text
    assert database.conn.execute("SELECT COUNT(*) FROM Errors").fetchone()[0] == 0


def test_interrupted_bulk_insert_keeps_completed_rows(open_database):
    database, _ = open_database()
    with pytest.raises(KeyboardInterrupt):
        with database.bulk_insert_mode():
            with database.row_transaction():
                database.conn.execute("INSERT INTO Errors (domain) VALUES ('completed')")
            with database.row_transaction():
                database.conn.execute("INSERT INTO Errors (domain) VALUES ('partial')")
                raise KeyboardInterrupt
    assert [row[0] for row in database.conn.execute("SELECT domain FROM Errors")] == ["completed"]


# ---------------------------------------------------------------- final layout at creation

def table_layouts(conn):
    """Columns (name, type, notnull, default, pk) of every table except sqlite_sequence."""
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {table: [tuple(row)[1:] for row in conn.execute(f"PRAGMA table_info({table})")] for table in tables}


def table_rows(conn):
    """Every row of every table, sqlite_sequence included."""
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    return {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")] for table in tables}


@pytest.fixture
def open_legacy(tmp_path):
    """Factory of databases with the full schema of previous versions (every column and the Errors table until
    finalize); all are closed on teardown."""
    databases = []

    def _open(db_type, name):
        conn = sqlite3.connect(tmp_path / name)
        conn.executescript(SCHEMA_PATH.read_text())
        conn.close()
        database = Database(tmp_path / name, SCHEMA_PATH, db_type)
        database.connect()
        databases.append(database)
        return database, CertificateDAO(database.conn, db_type)

    yield _open
    for database in databases:
        database.close()


def insert_rows(database, dao, rows):
    """Insert as the analysis does: leaf certificate or error, intermediates, root."""
    for row in rows:
        tls = row["data"]["tls"]
        with database.transaction():
            if tls["status"] != "success":
                if database.db_type is DatabaseType.LEAF:
                    dao.insert_error_row(row)
                continue
            server = tls["result"]["handshake_log"]["server_certificates"]
            certificate, chain = server["certificate"], server["chain"]
            if database.db_type is DatabaseType.LEAF:
                dao.process_insert_certificate(row, certificate, chain, 0)
            elif database.db_type is DatabaseType.INTERMEDIATE:
                for emitted, (cert, remaining) in enumerate(intermediate_certificates(chain, certificate), 1):
                    dao.process_insert_certificate(row, cert, remaining, emitted)
            else:
                root, count = find_root_certificate(chain, certificate)
                if root:
                    dao.process_insert_certificate(row, root, [], count)


@pytest.mark.parametrize("db_type", list(DatabaseType))
def test_new_database_matches_the_finalized_layout_and_rows(pki, open_database, open_legacy, db_type, caplog):
    """Final layout at creation: same schema and rows as the full schema finalized after the analysis."""
    rows = pki.rows(5)
    legacy, legacy_dao = open_legacy(db_type, "legacy.db")
    insert_rows(legacy, legacy_dao, rows)
    legacy.finalize_analysis()

    database, dao = open_database(db_type)
    insert_rows(database, dao, rows)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        database.finalize_analysis()
    assert "Removing the unneeded tables" not in caplog.text, "finalize_analysis() must not rebuild a new database"

    assert table_layouts(database.conn) == table_layouts(legacy.conn)
    assert table_rows(database.conn) == table_rows(legacy.conn)
    assert ("Errors" in table_layouts(database.conn)) == (db_type is DatabaseType.LEAF)
    assert database.conn.execute("PRAGMA page_size").fetchone()[0] == PAGE_SIZE


def test_dropped_column_value_that_cannot_be_bound_fails_the_row(pki, open_database, open_legacy):
    """SAN is not stored for intermediates, but a value that cannot be bound still invalidates the row."""
    row = pki.rows(1)[0]
    server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
    server["chain"][0]["parsed"]["names"] = ["ok", "\ud800"]
    errors = []
    for database, dao in (open_legacy(DatabaseType.INTERMEDIATE, "legacy.db"),
                          open_database(DatabaseType.INTERMEDIATE)):
        with pytest.raises(Exception) as error:
            insert_rows(database, dao, [row])
        errors.append(type(error.value))
        assert dao.get_certificates_count() == 0
        assert database.conn.execute("SELECT COUNT(*) FROM Issuers").fetchone()[0] == 0
    assert errors[0] is errors[1]


# ---------------------------------------------------------------- Certificate lookups

def certificate_with_broken_key_usage():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "broken.example.test")])
    now = datetime.datetime(2024, 10, 6, tzinfo=datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(4242).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
                   .add_extension(x509.UnrecognizedExtension(ExtensionOID.KEY_USAGE, b"\x01\x02garbage"), critical=True)
                   .sign(key, hashes.SHA256()))
    return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()


def reference_criticality(certificate, oid):
    try:
        return "Critical" if certificate.extensions.get_extension_for_oid(oid).critical else "Not Critical"
    except x509.ExtensionNotFound:
        return "Not Found"


def test_certificate_lookups_match_cryptography(pki):
    leaf = pki.leaf("lookup.example.test", 9100)
    certificate = Certificate(raw(leaf))
    for oid in (ExtensionOID.KEY_USAGE, ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.TLS_FEATURE, ExtensionOID.CRL_DISTRIBUTION_POINTS):
        assert certificate.extension_criticality(oid) == reference_criticality(leaf, oid)
    assert certificate.ocsp_must_staple() == "Not Found"
    policies = certificate.certificate_policies()
    assert [policy["policy_identifier"] for policy in policies] == ["2.23.140.1.2.1"]

    root = Certificate(raw(pki.root))
    assert root.self_signature_validity() == verify_signature(pki.root, pki.root) == "Valid"
    assert root.self_signature_validity() == "Valid"


def test_certificate_errors_are_logged_on_every_call(caplog):
    certificate = Certificate(certificate_with_broken_key_usage())
    caplog.clear()
    for _ in range(2):
        assert certificate.extension_criticality(ExtensionOID.KEY_USAGE) == "Error"
        assert certificate.certificate_policies() is None
    assert caplog.text.count("Unexpected error while checking the extension") == 2
    assert caplog.text.count("Unexpected error while reading the CERTIFICATE_POLICIES") == 2

    invalid = Certificate("bm90IGEgY2VydA==")
    assert invalid.cert is None
    assert invalid.self_signature_validity() == invalid.self_signature_validity() == "Error"
    assert caplog.text.count("Cannot verify the signature") == 2
