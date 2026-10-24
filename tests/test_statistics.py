"""Tests for StatisticsDAO (new queries, the read-only connections used by the render processes) and for the
corrections of Database.prepare_for_plots."""
import json
import logging
import sqlite3
from pathlib import Path

import pytest
from test_statistics_facts import V2Database

from dao import statistics_dao
from dao.statistics_dao import READER_PRAGMAS, StatisticsDAO, temp_store
from db.database import Database, DatabaseType

DAY = 86400

# (organization, country, subject key id, validity in days or None, signature algorithm, key usage)
CERTIFICATES = [
    ("Alpha CA", "US", "ski01", 90, "ECDSA-SHA256", {"digital_signature": True, "value": 1}),
    ("Alpha CA", "US", "ski02", 91, "ECDSA-SHA256", {"digital_signature": True, "value": 1}),
    ("Alpha CA", "US", "ski03", 398, "RSA-SHA256", {"digital_signature": True, "key_encipherment": True, "value": 5}),
    ("Alpha CA", "US", "ski03", 398, "RSA-SHA256", {"digital_signature": True, "key_encipherment": True, "value": 5}),
    ("Beta Trust", "IT", "ski04", 399, "RSA-SHA256", {"digital_signature": True, "key_encipherment": True, "value": 5}),
    ("Beta Trust", "IT", "ski05", 825, "RSA-SHA1", {"key_cert_sign": True, "crl_sign": True, "value": 96}),
    ("Beta Trust", "IT", "", 826, "RSA-SHA1", {"key_cert_sign": True, "crl_sign": True, "value": 96}),
    ("Gamma", "DE", "", 1826, "RSA-MD5", {"key_cert_sign": True, "value": 32}),
    ("Gamma", "DE", "ski08", -1, "RSA-SHA256", {}),
    ("Gamma", "DE", "ski09", None, "RSA-SHA256", {}),
]


def create_database(path, certificates=CERTIFICATES):
    """Leaf schema (also read as intermediate and root) with one certificate, issuer and occurrence per entry; the
    open connection."""
    db = V2Database(path)
    for index, (organization, country, ski, days, algorithm, key_usage) in enumerate(certificates, start=1):
        db.add(organization=organization, country=country, ski=ski, raw=f"raw{index}", signature_algorithm=algorithm,
               validity_end="2025-01-01 00:00:00", validity_length=None if days is None else days * DAY,
               key_usage=json.dumps(key_usage))
    return db.finish()


@pytest.fixture
def database(tmp_path):
    connection = create_database(tmp_path / "leaf.db")
    yield connection
    connection.close()


def test_validity_days_classes_follow_the_cab_forum_limits(database):
    statistics = StatisticsDAO(database, DatabaseType.LEAF)
    # ski03 appears twice and counts once; certificates without SKI count by raw; NULL lengths are skipped
    assert statistics.get_validity_days_distribution() == {
        "negative": 1, "<=90": 1, "91-200": 1, "201-398": 1, "399-825": 2, "826-1825": 1, ">1825": 1}
    assert list(statistics.get_validity_days_distribution())[0] == "negative"


def test_validity_days_is_empty_without_validity_lengths(tmp_path):
    connection = create_database(tmp_path / "empty.db", [("A", "US", "s1", None, "RSA-SHA256", {})])
    try:
        assert StatisticsDAO(connection, DatabaseType.ROOT).get_validity_days_distribution() == {}
    finally:
        connection.close()


def test_validity_years_query_is_unchanged(database):
    statistics = StatisticsDAO(database, DatabaseType.ROOT)
    assert statistics.get_validity_duration_distribution() == {-1: 1, 0: 2, 1: 2, 2: 2, 5: 1}


def test_issuer_distribution_lists_every_issuer(database):
    statistics = StatisticsDAO(database, DatabaseType.LEAF)
    assert list(statistics.get_issuer_distribution().items()) == [("Alpha CA", 4), ("Beta Trust", 3), ("Gamma", 3)]
    top = statistics.get_issuer_certificate_count()
    assert {name: count for name, count in top.items() if name != "Others"} == statistics.get_issuer_distribution()


def test_thresholds_follow_the_certificate_type(database):
    assert StatisticsDAO(database, DatabaseType.LEAF).thresholds.top_countries == 5
    assert StatisticsDAO(database, DatabaseType.INTERMEDIATE).thresholds.top_countries == 4
    assert StatisticsDAO(database, DatabaseType.ROOT).thresholds.top_issuers == 20


def test_shared_database_file_and_reader_give_the_same_statistics(database, tmp_path):
    statistics = StatisticsDAO(database, DatabaseType.LEAF)
    path = statistics.shared_database_file()
    assert Path(path) == (tmp_path / "leaf.db").resolve()
    with StatisticsDAO.reading(path, DatabaseType.LEAF) as reader:
        assert all_statistics(reader) == all_statistics(statistics)
        assert reader._conn.execute("PRAGMA temp_store").fetchone()[0] == 2      # small file: in memory
        assert reader._conn.execute("PRAGMA cache_size").fetchone()[0] == -65536
        with pytest.raises(sqlite3.OperationalError):
            reader._conn.execute("DELETE FROM Occurrences")
    assert len(READER_PRAGMAS) == 2


def all_statistics(dao):
    """Every get_* result, with its order."""
    return {name: list(getattr(dao, name)().items()) for name in dir(StatisticsDAO) if name.startswith("get_")}


def test_large_databases_keep_temporary_tables_in_files(database, tmp_path, monkeypatch):
    path = str(tmp_path / "leaf.db")
    assert temp_store(path) == "MEMORY"
    assert temp_store(str(tmp_path / "missing.db")) == "FILE"
    # A file larger than the share of the physical memory: temporary b-trees and sorts spill to files
    monkeypatch.setattr(statistics_dao, "MEMORY_TEMP_STORE_SHARE", 1e-12)
    assert temp_store(path) == "FILE"
    with StatisticsDAO.reading(path, DatabaseType.LEAF) as reader:
        assert reader._conn.execute("PRAGMA temp_store").fetchone()[0] == 1
        assert all_statistics(reader) == all_statistics(StatisticsDAO(database, DatabaseType.LEAF))
    monkeypatch.delattr(statistics_dao.os, "sysconf")      # e.g. Windows: memory size unknown
    monkeypatch.setattr(statistics_dao, "MEMORY_TEMP_STORE_SHARE", 0.125)
    assert temp_store(path) == "FILE"


def test_reader_is_closed_on_exit(database):
    path = StatisticsDAO(database, DatabaseType.LEAF).shared_database_file()
    with StatisticsDAO.reading(path, DatabaseType.LEAF) as reader:
        pass
    with pytest.raises(sqlite3.ProgrammingError):
        reader._conn.execute("SELECT 1")


def test_no_shared_file_for_memory_databases_and_uncommitted_changes(database):
    memory = sqlite3.connect(":memory:")
    assert StatisticsDAO(memory, DatabaseType.LEAF).shared_database_file() is None
    memory.close()
    database.execute("BEGIN")
    database.execute("DELETE FROM ErrorData")
    assert StatisticsDAO(database, DatabaseType.LEAF).shared_database_file() is None
    database.rollback()


def test_no_shared_file_when_it_cannot_be_opened_read_only(tmp_path, caplog):
    path = tmp_path / "gone.db"
    connection = create_database(path)
    try:
        path.unlink()       # the open connection keeps working, a new one cannot open the file
        with caplog.at_level(logging.WARNING):
            assert StatisticsDAO(connection, DatabaseType.LEAF).shared_database_file() is None
        assert "Read-only connection to the database not available" in caplog.text
    finally:
        connection.close()


def test_prepare_for_plots_only_corrects_the_issuers(tmp_path):
    database = Database(tmp_path / "leaf.db", DatabaseType.LEAF)
    database.connect()

    def indexes():
        return {row[0] for row in database.conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}

    try:
        database.conn.execute("INSERT INTO IssuerData (issuer_id, organization) VALUES (1, 'DigiCert, Inc.')")
        database.conn.execute("INSERT INTO IssuerData (issuer_id, organization) VALUES (2, 'DigiCert Inc')")
        database.conn.commit()
        database.conn.execute("PRAGMA cache_size = -1234")
        before = indexes()
        database.prepare_for_plots()
        # The statistics need no index: the charts read each table once
        assert indexes() == before
        assert database.conn.execute("PRAGMA cache_size").fetchone()[0] == -1234
        assert [row[0] for row in database.conn.execute("SELECT organization FROM IssuerData ORDER BY issuer_id")] == [
            "DigiCert Inc", "DigiCert Inc"]
        assert database.conn.execute("SELECT organization FROM Issuers").fetchall() == []    # no occurrences
    finally:
        database.close()
