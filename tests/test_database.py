"""Tests for Database and CertificateDAO."""
import sqlite3

import pytest
from helpers import error_row, success_row, zgrab_certificate

from db.database import DatabaseType
from utils.chain_utils import find_root_certificate, intermediate_certificates


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
    assert columns["certificate_id"][5] == 1, "certificate_id deve restare PRIMARY KEY"
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
    assert root_dao.get_signature_validity_distribution() == {"Valid": 1}
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
    assert dao.get_certificate_version_distribution() == {1: 3, 3: 2}
    assert dao.get_status_analysis() == {"success": 5, "connection-timeout": 2, "unknown-error": 1}
    assert dao.get_sct_count_per_certificate() == {0: 3, 2: 2}


def test_row_transactions_are_batched_and_isolated(open_database):
    database, _ = open_database()
    with database.bulk_insert_mode():
        for i in range(5):
            try:
                with database.row_transaction():
                    database.conn.execute("INSERT INTO Errors (domain) VALUES (?)", (f"d{i}",))
                    if i == 2:
                        raise ValueError("riga non valida")
            except ValueError:
                pass
        assert database.conn.in_transaction, "le righe sono confermate a blocchi"
    domains = [row[0] for row in database.conn.execute("SELECT domain FROM Errors ORDER BY error_id")]
    assert domains == ["d0", "d1", "d3", "d4"]
    assert not database.conn.in_transaction


def test_disk_full_reports_the_real_error_and_lost_rows(open_database, caplog):
    database, _ = open_database()
    database.conn.execute("PRAGMA max_page_count = 40")
    errors = set()
    with database.bulk_insert_mode():
        for i in range(2000):
            try:
                with database.row_transaction():
                    database.conn.execute("INSERT INTO Errors (domain, error_message) VALUES (?, ?)", (f"d{i}", "x" * 200))
            except sqlite3.OperationalError as e:
                errors.add(str(e))
    assert errors == {"database or disk is full"}
    assert "righe non ancora confermate" in caplog.text


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
