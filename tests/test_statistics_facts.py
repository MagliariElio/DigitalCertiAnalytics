"""Materialized statistics (StatisticsDAO.materialize) must equal the per-method queries: values, order, key types
and logged errors, including the identity edge cases of the DISTINCT subqueries."""
import json
import logging
import random
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path

import pytest

from dao import statistics_dao, statistics_facts
from dao.statistics_dao import StatisticsDAO, statistic_names
from db.database import Database, DatabaseType

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "src" / "db" / "schema_db.sql"
YEAR = 31536000


def results(dao, caplog):
    """Every get_* result as (items with types, logged errors)."""
    out = {}
    for name in statistic_names():
        caplog.clear()
        with caplog.at_level(logging.ERROR):
            result = getattr(dao, name)()
        out[name] = (_typed(result), [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR])
    return out


def _typed(value):
    if isinstance(value, dict):
        return [(_typed(k), _typed(v)) for k, v in value.items()]
    return (type(value).__name__, value)


def compare(path, certificate_type, caplog, executor=None, workers=1, monkeypatch=None):
    """Materialized results equal to the queries'; with `monkeypatch`, also check that every statistic but the
    ones the database cannot give (missing column or table) came from the materialized rows."""
    connection = sqlite3.connect(path)
    try:
        expected = results(StatisticsDAO(connection, certificate_type), caplog)
    finally:
        connection.close()
    queried = []
    if monkeypatch is not None:
        original = StatisticsDAO._materialized

        def materialized(dao, rows_key, *args, **kwargs):
            result = original(dao, rows_key, *args, **kwargs)
            if result is None:
                queried.append(rows_key)
            return result

        monkeypatch.setattr(StatisticsDAO, "_materialized", materialized)
    with StatisticsDAO.reading(str(path), certificate_type) as dao:
        assert dao.materialize(executor=executor, workers=workers)
        actual = results(dao, caplog)
    assert actual == expected
    failing = {name for name, (_, errors) in expected.items() if errors}
    assert not monkeypatch or len(queried) == len(failing)
    return expected


def insert(connection, table, **values):
    columns = ", ".join(values)
    connection.execute(f"INSERT INTO {table} ({columns}) VALUES ({', '.join('?' * len(values))})",
                       tuple(values.values()))


def certificate(connection, cid, ski="ski", raw="raw", subject=True, issuer=None, **columns):
    """One certificate with its subject (unless subject=False), issuer and extension."""
    if subject:
        insert(connection, "Subjects", subject_id=cid, subject_key_id=ski,
               subject_alt_name_is_critical=columns.pop("san", "Not Critical"))
    insert(connection, "Issuers", issuer_id=cid, organization=columns.pop("organization", "Alpha"),
           country=columns.pop("country", "US"))
    extension = {"key_usage": columns.pop("key_usage", '{"digital_signature": true, "value": 1}'),
                 "key_usage_is_critical": columns.pop("ku_critical", "Critical")}
    defaults = {"version": 3, "signature_algorithm": "RSA-SHA256", "key_algorithm": "RSA", "key_length": 2048,
                "validity_end": "2025-03-01 00:00:00", "validity_length": YEAR, "ocsp_check": "Good",
                "signature_valid": "Valid", "self_signed": 0, "authority_info_access_is_critical": "Not Critical",
                "validation_level": "DV"}
    insert(connection, "Certificates", certificate_id=cid, subject_id=cid if subject else 10 ** 6 + cid,
           issuer_id=cid if issuer is None else issuer, raw=raw, **{**defaults, **columns})
    insert(connection, "Extensions", extension_id=cid, certificate_id=cid, extended_key_usage='{"server_auth": true}',
           extended_key_usage_is_critical="Not Critical", basic_constraints='{"is_ca": false}',
           crl_distr_point_is_critical="Not Found", **extension)
    insert(connection, "CertificatePolicies", extension_id=cid, policy_identifier="2.23.140.1.2.1", is_cp_critical=0)


def schema(path):
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA_PATH.read_text())
    insert(connection, "LogsOperators", id=1, name="Google")
    insert(connection, "LogsOperators", id=2, name="Cloudflare")
    for log_id, operator, description in ((1, 1, "Argon"), (2, 1, "Xenon"), (3, 2, "Nimbus"), (4, 9, "Orphan")):
        insert(connection, "Logs", id=log_id, operator_id=operator, description=description, log_id=f"log{log_id}",
               key="k", url="u", mmd=86400, temporal_start="2024", temporal_end="2026")
    connection.commit()
    return connection


def sct(connection, cid, log, timestamp=1735689600):
    insert(connection, "SignedCertificateTimestamps", certificate_id=cid, log_id=log, timestamp=timestamp, version=0,
           signature="s")


@pytest.fixture
def edge_database(tmp_path):
    """Leaf database with the identity and join edge cases of the DISTINCT subqueries."""
    path = tmp_path / "edge.db"
    connection = schema(path)
    with connection:
        # Same SKI on three certificates (counted once per value), with different per-row values
        certificate(connection, 1, ski="dup", signature_valid="Valid", validity_length=YEAR)
        certificate(connection, 2, ski="dup", signature_valid="Error", validity_length=2 * YEAR)
        certificate(connection, 3, ski="dup", signature_valid="Valid", ocsp_check="Revoked")
        # Without SKI ('' or NULL): identity is the raw certificate; equal raws are one certificate
        certificate(connection, 4, ski="", raw="raw-A", version=1, key_length="")
        certificate(connection, 5, ski=None, raw="raw-A", version=1, self_signed=1)
        certificate(connection, 6, ski="", raw=b"raw-A", version=1)         # blob: another identity
        certificate(connection, 7, ski=None, raw=None, version=1, validity_length=-5)    # NULL identity
        certificate(connection, 8, ski="", raw="dup")      # raw equal to a SKI: the same certificate as 1-3
        certificate(connection, 9, ski=b"dup", raw="x")     # blob SKI: not equal to the text 'dup'
        certificate(connection, 10, ski="", raw=7)          # numeric raw
        certificate(connection, 11, ski="", raw=7.0)        # equal to 7 for SQLite
        # Certificate without subject: only in the occurrence counts
        certificate(connection, 12, ski="nosub", subject=False, ocsp_check="Unknown")
        # Two certificates sharing one subject row
        certificate(connection, 13, ski="shared", validation_level="OV")
        insert(connection, "Certificates", certificate_id=14, subject_id=13, issuer_id=None, raw="r14", version=3,
               validation_level="EV", self_signed="x", key_algorithm=None, validity_end=None, validity_length=None)
        # Values of every kind
        certificate(connection, 15, ski="s15", signature_algorithm=None, key_algorithm="", validity_length=None,
                    organization=None, country="--", self_signed=None, version=None, san="Critical")
        certificate(connection, 16, ski="s16", organization="DigiCert, Inc.", country=" ", key_length=None,
                    validity_length=826 * 86400, validity_end="2031-07-15 10:00:00", key_usage='{"value": 0}')
        certificate(connection, 17, ski="s17", organization="  ", country=None, validity_length=10 * YEAR,
                    signature_algorithm="ECDSA-SHA256", key_algorithm="ECDSA", key_length=256)
        certificate(connection, 18, ski="s18", issuer=999, validity_length=YEAR + 0.5)
        # Extensions: a second row for certificate 1, rows without certificate
        insert(connection, "Extensions", extension_id=50, certificate_id=1, key_usage='{"key_cert_sign": true}',
               key_usage_is_critical="Not Critical", extended_key_usage='{"client_auth": true}')
        insert(connection, "Extensions", extension_id=51, certificate_id=777, key_usage='{"crl_sign": true}')
        insert(connection, "Extensions", extension_id=52, certificate_id="abc", key_usage='{"crl_sign": true}')
        insert(connection, "Extensions", extension_id=53, certificate_id=None, key_usage='{"crl_sign": true}')
        # Policies: several per extension, missing extension, NULL criticality
        insert(connection, "CertificatePolicies", extension_id=1, policy_identifier="1.2", is_cp_critical=1)
        insert(connection, "CertificatePolicies", extension_id=2, policy_identifier="1.2", is_cp_critical=None)
        insert(connection, "CertificatePolicies", extension_id=888, policy_identifier="1.2", is_cp_critical=1)
        insert(connection, "CertificatePolicies", extension_id=None, policy_identifier="1.2", is_cp_critical=1)
        # SCTs: text log ids, unknown log, unknown certificate, log without operator, repeated log
        for cid in (1, 2, 4, 5, 8, 13, 14, 15):
            sct(connection, cid, 1)
            sct(connection, cid, "2", 1704067200)
        sct(connection, 1, 1)
        sct(connection, 3, 3, 1706745600)
        sct(connection, 9, 4)
        sct(connection, 12, 3)
        sct(connection, 16, 99)
        sct(connection, 999, 1)
        sct(connection, 17, "x")
        # Issuer rows not referenced by any certificate
        insert(connection, "Issuers", issuer_id=500, organization="Unused", country="IT")
        for status in ("connection-timeout", "unknown-error", "connection-timeout", None):
            insert(connection, "Errors", domain="d", status=status)
    connection.close()
    return path


def test_edge_cases_match_the_queries(edge_database, caplog, monkeypatch):
    expected = compare(edge_database, DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)
    assert not any(errors for name, (_, errors) in expected.items() if name != "get_status_analysis")
    # Certificates 1-3 and 8 are one certificate (SKI 'dup', raw 'dup'); 13 and 14 share their subject
    assert dict(expected["get_signature_validity_distribution"][0])[("str", "Error")] == ("int", 2)


@pytest.mark.parametrize("bitmap", [True, False])
def test_tasks_split_in_many_ranges(edge_database, caplog, monkeypatch, bitmap):
    monkeypatch.setattr(statistics_facts, "_TASK_SECONDS", 1e-9)      # one task per few rows
    monkeypatch.setattr(statistics_facts, "_CHUNK", 3)                 # lookups and deduplication in buckets
    monkeypatch.setattr(statistics_facts, "_GROUP_SIZE", 3)            # more value groups
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 2)          # identities numbered in buckets
    if not bitmap:
        monkeypatch.setattr(statistics_facts, "_BITMAP_CELLS", 0)      # deduplication by sorting
    compare(edge_database, DatabaseType.LEAF, caplog)


def test_random_database_without_bitmaps(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db", seed=11)
    monkeypatch.setattr(statistics_facts, "_BITMAP_CELLS", 0)
    monkeypatch.setattr(statistics_facts, "_CHUNK", 50)
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 40)
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog)


# Chart indexes built by earlier versions, which their databases keep
_EARLIER_INDEXES = (
    "Certificates(certificate_id, leaf_domain)", "Certificates(subject_id)", "Certificates(ocsp_check)",
    "Certificates(authority_info_access)", "Certificates(validity_end)", "Certificates(version)", "Issuers(common_name)",
    "Subjects(subject_dn)", "Subjects(common_name)", "Subjects(subject_key_id)", "Extensions(certificate_id)",
    "Extensions(key_usage)", "Extensions(extended_key_usage)", "Certificates(self_signed)",
    "Certificates(signature_valid)", "SignedCertificateTimestamps(certificate_id)", "SignedCertificateTimestamps(log_id)",
    "Errors(domain)", "Errors(status)", "Logs(operator_id)", "Logs(log_id)")


def ties_database(path, earlier_indexes):
    """Issuers with equal counts, after prepare_for_plots; optionally with the indexes of earlier versions too."""
    connection = schema(path)
    with connection:
        for cid, organization in enumerate(["Zeta", "Alpha", "Mid", "Alpha", "Zeta", "Beta", "DigiCert, Inc."], start=1):
            certificate(connection, cid, ski=f"s{cid}", organization=organization)
        for number, columns in enumerate(_EARLIER_INDEXES if earlier_indexes else ()):
            connection.execute(f"CREATE INDEX IF NOT EXISTS idx_earlier_{number} ON {columns}")
    connection.close()
    database = Database(path, SCHEMA_PATH, DatabaseType.LEAF)
    database.connect()
    try:
        database.prepare_for_plots()
    finally:
        database.close()


@pytest.mark.parametrize("earlier_indexes", [False, True])
def test_equal_issuer_counts_keep_the_order_of_the_indexed_plan(tmp_path, caplog, earlier_indexes):
    ties_database(tmp_path / "ties.db", earlier_indexes)
    expected = compare(tmp_path / "ties.db", DatabaseType.LEAF, caplog)
    # Ordered by count, then as the index on Issuers(organization) gives them
    assert [key for (_, key), _ in expected["get_issuer_certificate_count"][0]] == [
        "Alpha", "Zeta", "Beta", "DigiCert Inc", "Mid"]


def test_null_key_usage_logs_the_same_error(tmp_path, caplog):
    path = tmp_path / "null.db"
    connection = schema(path)
    with connection:
        certificate(connection, 1, key_usage=None)
        certificate(connection, 2)
    connection.close()
    expected = compare(path, DatabaseType.LEAF, caplog)
    assert expected["get_key_usage_distribution"][0] == [] and expected["get_key_usage_distribution"][1]


def random_database(path, rows=400, seed=7):
    """Random values with many repeated identities."""
    rng = random.Random(seed)
    connection = schema(path)
    with connection:
        for cid in range(1, rows + 1):
            ski = rng.choice(["", None, f"k{rng.randrange(rows // 3)}", f"k{rng.randrange(rows // 3)}"])
            raw = rng.choice([None, f"r{rng.randrange(rows // 4)}", f"r{rng.randrange(rows // 4)}".encode()])
            certificate(connection, cid, ski=ski, raw=raw, subject=rng.random() > 0.05,
                        issuer=rng.choice([cid, cid, rng.randrange(rows), None]),
                        organization=rng.choice(["Alpha", "Beta", "DigiCert Inc", None, ""]),
                        country=rng.choice(["US", "IT", "--", None, ""]),
                        version=rng.choice([1, 3, 3, None]), validity_length=rng.choice(
                            [None, -1, 30 * 86400, 90 * 86400, YEAR, 398 * 86400, 3 * YEAR, rng.randrange(10 ** 9)]),
                        validity_end=rng.choice([None, "2025-01-31 00:00:00", "2026-02-01 00:00:00", "bad"]),
                        signature_algorithm=rng.choice(["RSA-SHA256", "ECDSA-SHA384", "RSA-SHA1", None]),
                        key_length=rng.choice([2048, 4096, 256, "", None]), self_signed=rng.choice([0, 1, None]),
                        signature_valid=rng.choice(["Valid", "Not Valid", "Error"]),
                        ocsp_check=rng.choice(["Good", "Revoked", "No Request Done"]),
                        validation_level=rng.choice(["DV", "OV", "EV", None]),
                        key_usage=json.dumps({"digital_signature": rng.random() > 0.3, "value": rng.randrange(3)}),
                        ku_critical=rng.choice(["Critical", "Not Critical", None]))
            for _ in range(rng.randrange(4)):
                sct(connection, rng.choice([cid, cid, rng.randrange(rows + 20)]), rng.choice([1, 2, 3, 4, 5, "1"]),
                    rng.choice([1704067200, 1706745600, 1735689600]))
    connection.close()


def test_random_database_matches_the_queries(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db")
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)


def test_render_processes_run_the_scans(tmp_path, caplog):
    random_database(tmp_path / "random.db", rows=300, seed=3)
    with ProcessPoolExecutor(2, mp_context=get_context("spawn")) as executor:
        compare(tmp_path / "random.db", DatabaseType.LEAF, caplog, executor, workers=2)


@pytest.mark.parametrize("certificate_type", [DatabaseType.INTERMEDIATE, DatabaseType.ROOT])
def test_final_layouts_and_missing_tables(tmp_path, caplog, monkeypatch, certificate_type):
    path = tmp_path / f"{certificate_type.value}.db"
    database = Database(path, SCHEMA_PATH, certificate_type)
    database.connect()
    with database.conn:
        columns = {row[1] for row in database.conn.execute("PRAGMA table_info(Certificates)")}
        for cid, ski in ((1, "a"), (2, "a"), (3, "b"), (4, "")):
            insert(database.conn, "Subjects", subject_id=cid, subject_key_id=ski)
            insert(database.conn, "Issuers", issuer_id=cid, organization="Alpha", country="US")
            insert(database.conn, "Certificates", certificate_id=cid, subject_id=cid, issuer_id=cid, raw=f"r{cid}",
                   version=3, **({"signature_valid": "Valid"} if "signature_valid" in columns else {}))
    database.close()
    expected = compare(path, certificate_type, caplog, monkeypatch=monkeypatch)
    assert expected["get_status_analysis"] == ([], ["Statistics query failed: no such table: Errors"])
    if certificate_type is DatabaseType.INTERMEDIATE:
        assert expected["get_signature_validity_distribution"] == (
            [], ["Statistics query failed: no such column: signature_valid"])


def test_empty_database(tmp_path, caplog):
    path = tmp_path / "empty.db"
    schema(path).close()
    compare(path, DatabaseType.LEAF, caplog)


def test_not_materialized_without_a_shared_file(tmp_path, caplog):
    memory = sqlite3.connect(":memory:")
    assert not StatisticsDAO(memory, DatabaseType.LEAF).materialize()
    memory.close()
    path = tmp_path / "busy.db"
    connection = schema(path)
    connection.execute("BEGIN")
    connection.execute("DELETE FROM Logs")
    assert not StatisticsDAO(connection, DatabaseType.LEAF).materialize()
    connection.rollback()
    connection.close()


def test_a_failure_falls_back_to_the_queries(edge_database, caplog, monkeypatch):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(statistics_facts, "collect", broken)
    with StatisticsDAO.reading(str(edge_database), DatabaseType.LEAF) as dao:
        with caplog.at_level(logging.WARNING):
            assert not dao.materialize()
        assert "Statistics not materialized" in caplog.text
        connection = sqlite3.connect(edge_database)
        try:
            assert results(dao, caplog) == results(StatisticsDAO(connection, DatabaseType.LEAF), caplog)
        finally:
            connection.close()


def test_databases_of_earlier_versions_without_the_rowid_key_use_the_queries(edge_database, caplog):
    """'Certificates' rebuilt without its PRIMARY KEY by earlier versions: certificate_id is not the rowid, so it
    cannot be read in rowid ranges."""
    connection = sqlite3.connect(edge_database)
    connection.executescript("""
        CREATE TABLE Certificates_old AS SELECT * FROM Certificates;
        DROP TABLE Certificates;
        ALTER TABLE Certificates_old RENAME TO Certificates;
        DELETE FROM Certificates WHERE certificate_id = 2;
        UPDATE Certificates SET certificate_id = certificate_id + 1000 WHERE certificate_id > 15;
    """)
    connection.close()
    with StatisticsDAO.reading(str(edge_database), DatabaseType.LEAF) as dao:
        with caplog.at_level(logging.WARNING):
            assert not dao.materialize()
        assert "Certificates.certificate_id is not the rowid of the table" in caplog.text
        connection = sqlite3.connect(edge_database)
        try:
            assert results(dao, caplog) == results(StatisticsDAO(connection, DatabaseType.LEAF), caplog)
        finally:
            connection.close()


def _uses_the_queries(path, message, caplog):
    with StatisticsDAO.reading(str(path), DatabaseType.LEAF) as dao:
        with caplog.at_level(logging.WARNING):
            assert not dao.materialize()
        assert message in caplog.text
        connection = sqlite3.connect(path)
        try:
            assert results(dao, caplog) == results(StatisticsDAO(connection, DatabaseType.LEAF), caplog)
        finally:
            connection.close()


@pytest.mark.parametrize("table, column", [("Certificates", "certificate_id"), ("Extensions", "extension_id"),
                                           ("Logs", "id"), ("Issuers", "issuer_id")])
def test_a_key_equal_to_the_no_key_marker_uses_the_queries(edge_database, caplog, table, column):
    """NO_KEY marks join keys that match no row: a real key with that value would join wrongly."""
    connection = sqlite3.connect(edge_database)
    with connection:
        connection.execute(f"UPDATE {table} SET {column} = ? WHERE {column} = (SELECT MIN({column}) FROM {table})",
                           (statistics_facts.NO_KEY,))
    connection.close()
    _uses_the_queries(edge_database, f"{table}.{column} has a row whose key is", caplog)


def test_an_integer_primary_key_desc_is_not_the_rowid(edge_database, caplog):
    connection = sqlite3.connect(edge_database)
    create = connection.execute("SELECT sql FROM sqlite_master WHERE name = 'Certificates'").fetchone()[0]
    with connection:
        connection.execute(create.replace("Certificates", "Certificates_desc", 1).replace(
            "certificate_id INTEGER PRIMARY KEY AUTOINCREMENT", "certificate_id INTEGER PRIMARY KEY DESC"))
        connection.execute("INSERT INTO Certificates_desc SELECT * FROM Certificates")
        connection.execute("DROP TABLE Certificates")
        connection.execute("ALTER TABLE Certificates_desc RENAME TO Certificates")
    connection.close()
    _uses_the_queries(edge_database, "Certificates.certificate_id is not the rowid of the table", caplog)


def test_rows_without_their_certificates_or_extensions_match_the_queries(tmp_path, caplog, monkeypatch):
    path = tmp_path / "orphans.db"
    connection = schema(path)
    with connection:
        insert(connection, "Extensions", extension_id=1, certificate_id=5, key_usage='{"value": 1}',
               key_usage_is_critical="Critical")
        insert(connection, "CertificatePolicies", extension_id=1, policy_identifier="2.23.140.1.2.1")
        sct(connection, 5, 1)
    connection.close()
    compare(path, DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)
    connection = sqlite3.connect(path)
    with connection:
        connection.execute("DELETE FROM Extensions")
    connection.close()
    compare(path, DatabaseType.LEAF, caplog)


def test_identities_numbered_in_more_than_256_buckets(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db", rows=1200, seed=5)
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 1)
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog)


def test_failed_scans_are_cancelled(edge_database, monkeypatch):
    """A failure stops the scans that have not started, so the queries that replace them start at once."""
    monkeypatch.setattr(statistics_facts, "_TASK_SECONDS", 1e-9)

    class Pending:
        cancelled = 0

        def __init__(self, function, *args):
            self.error = function is statistics_facts.query

        def result(self):
            if self.error:
                raise RuntimeError("worker lost")

        def cancel(self):
            Pending.cancelled += 1
            return True

    class Executor:
        @staticmethod
        def submit(function, *args):
            return Pending(function, *args)

    request = statistics_dao._facts_request(set(statistic_names()))
    with pytest.raises(RuntimeError):
        statistics_facts.collect(str(edge_database), request, Executor(), workers=2)
    assert Pending.cancelled > 5
