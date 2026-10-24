"""Materialized statistics (StatisticsDAO.materialize, over the base tables) must equal the per-method queries (over
the views of the old tables): values, order, key types and logged errors, including the identity and join edge cases
of the DISTINCT subqueries and rows the ingestion never writes (missing certificates, issuers, codes, logs)."""
import base64
import json
import logging
import random
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context

import pytest
from helpers import Pki

from dao import statistics_dao, statistics_facts
from dao.statistics_dao import StatisticsDAO, Thresholds, statistic_names
from db import schema
from db.database import DatabaseType
from db.raw_codec import DICTIONARY_ID, RawCodec, train_dictionary

YEAR = 31536000
# DER-like samples: their base64 texts are stored as compressed DER (canonical raws)
SAMPLES = [b"0\x82\x01\x00" + (b"CN=site%d.example.test,O=Example Org,C=IT;" % i) * 8 + bytes(range(i % 50, i % 50 + 60))
           for i in range(80)]
CANONICAL = [base64.b64encode(sample).decode() for sample in SAMPLES]
# Kind of every CertificateData column (db.schema): inline, or a TextValues / NumericValues reference
_KINDS = {name: kind for name, _, kind in schema.CERTIFICATE_COLUMNS}
_KINDS.update({column: kind for _, _, kind, column in schema.SUBJECT_COLUMNS})
_KINDS.update({name: kind for name, _, kind in schema.EXTENSION_COLUMNS})
DEFAULTS = {"version": 3, "signature_algorithm": "RSA-SHA256", "key_algorithm": "RSA", "key_length": 2048,
            "validity_end": "2025-03-01 00:00:00", "validity_length": YEAR, "self_signed": 0,
            "authority_info_access_is_critical": "Not Critical", "validation_level": "DV",
            "subject_alt_name_is_critical": "Not Critical", "key_usage": '{"digital_signature": true, "value": 1}',
            "key_usage_is_critical": "Critical", "extended_key_usage": '{"server_auth": true}',
            "extended_key_usage_is_critical": "Not Critical", "basic_constraints": '{"is_ca": false}',
            "crl_distr_point_is_critical": "Not Found"}
DEFAULT_POLICIES = (("2.23.140.1.2.1", 0),)
# Thresholds low enough for every statistic to return rows on the small test databases
LOW_THRESHOLDS = Thresholds(top_countries=2, min_validity_count=1, expiration_above=0, sct_above=0, top_issuers=3,
                            top_sct_logs_above=0)


class V2Database:
    """A schema v2 database written row by row in its base tables, including rows the ingestion never writes."""

    def __init__(self, path, db_type=DatabaseType.LEAF, dictionary=None):
        self.connection = sqlite3.connect(path)
        schema.create(self.connection, db_type)
        self.codec = RawCodec(dictionary)
        self.columns = {table: {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})")}
                        for table in ("CertificateData", "Occurrences")}
        self.positions: dict[int, int] = {}
        self.connection.execute("BEGIN")
        if dictionary is not None:
            self.insert("RawDictionaries", dictionary_id=DICTIONARY_ID, zstd_dictionary=dictionary)
            self.insert("SchemaInfo", key="raw_dictionary_id", value=DICTIONARY_ID)
        self.insert("LogsOperators", id=1, name="Google")
        self.insert("LogsOperators", id=2, name="Cloudflare")
        for log_id, operator, description in ((1, 1, "Argon"), (2, 1, "Xenon"), (3, 2, "Nimbus"), (4, 9, "Orphan")):
            self.insert("Logs", id=log_id, operator_id=operator, description=description, log_id=f"log{log_id}",
                        key="k", url="u", mmd=86400, temporal_start="2024", temporal_end="2026")

    def insert(self, table, **values) -> int:
        return self.connection.execute(f"INSERT INTO {table} ({', '.join(values)}) VALUES "
                                       f"({', '.join('?' * len(values))})", tuple(values.values())).lastrowid

    def lookup(self, kind, value):
        """TextValues ('tv') or NumericValues ('nv') reference of a value, as the ingestion stores it."""
        if value is None:
            return None
        table = "TextValues" if kind == "tv" else "NumericValues"
        self.connection.execute(f"INSERT OR IGNORE INTO {table} (value) VALUES (?)", (value,))
        return self.connection.execute(f"SELECT value_id FROM {table} WHERE value = ?", (value,)).fetchone()[0]

    def raw(self, value):
        """A new RawCertificates row (compressed DER for canonical base64 texts, else the value itself)."""
        if value is None:
            return None
        der_zstd, raw = self.codec.encode(value)
        return self.insert("RawCertificates", der_zstd=der_zstd, raw=raw)

    def issuer(self, organization="Alpha", country="US"):
        return self.insert("IssuerData", common_name="CA", organization=organization, country=country)

    def policy_set(self, policies):
        """Policy set of (identifier, critical) policies; None in the list: a member without its PolicyData row."""
        set_id = self.insert("PolicySets", policy_count=len(policies))
        for position, policy in enumerate(policies):
            policy_id = 10 ** 6 if policy is None else self.insert(
                "PolicyData", policy_identifier=policy[0], cps="[]", policy_qualifiers="[]", is_cp_critical=policy[1])
            self.insert("PolicySetMembers", policy_set_id=set_id, position=position, policy_id=policy_id)
        return set_id

    def certificate(self, ski="ski", raw="raw", policies=DEFAULT_POLICIES, policy_set_id=None, **columns) -> int:
        row = {"subject_key_id": ski, "raw_id": self.raw(raw),
               "policy_set_id": self.policy_set(policies) if policies is not None else policy_set_id}
        for name, value in {**DEFAULTS, **columns}.items():
            if name in self.columns["CertificateData"]:
                row[name] = self.lookup(_KINDS[name], value) if _KINDS[name] in ("tv", "nv") else value
        return self.insert("CertificateData", **row)

    def occurrence(self, certificate_id, issuer_id, ocsp="Good", signature="Valid",
                   download_date="2025-01-01 00:00:00", **columns) -> int:
        row = {"certificate_id": certificate_id, "issuer_id": issuer_id,
               "ocsp_check": ocsp if isinstance(ocsp, int) else schema.OCSP_CODES[ocsp],
               "download_date": self.lookup("nv", download_date), **columns}
        if "signature_valid" in self.columns["Occurrences"]:
            row["signature_valid"] = signature if isinstance(signature, int) else schema.SIGNATURE_CODES[signature]
        return self.insert("Occurrences", **{k: v for k, v in row.items() if k in self.columns["Occurrences"]})

    def sct(self, certificate_id, log, timestamp=1735689600):
        position = self.positions.get(certificate_id, 0)
        self.positions[certificate_id] = position + 1
        self.insert("SctData", certificate_id=certificate_id, position=position, log_id=log, timestamp=timestamp,
                    version=0, signature="s")

    def add(self, occurrences=({},), organization="Alpha", country="US", issuer=None, scts=(), **columns) -> int:
        """A certificate with its occurrences (dicts of occurrence values; 'issuer': an IssuerData id) and SCTs."""
        certificate_id = self.certificate(**columns)
        issuer = self.issuer(organization, country) if issuer is None else issuer
        for values in occurrences:
            values = dict(values)
            self.occurrence(certificate_id, values.pop("issuer", issuer), **values)
        for log, timestamp in scts:
            self.sct(certificate_id, log, timestamp)
        return certificate_id

    def error(self, status, protocol="tls", timestamp="2025-01-01 00:00:00"):
        self.insert("ErrorData", domain="d", status=self.lookup("tv", status), protocol=self.lookup("tv", protocol),
                    timestamp=self.lookup("nv", timestamp), error_message="boom")

    def finish(self) -> sqlite3.Connection:
        self.connection.commit()
        return self.connection

    def close(self) -> None:
        self.finish().close()


@pytest.fixture(autouse=True)
def low_thresholds(monkeypatch):
    for certificate_type in DatabaseType:
        monkeypatch.setitem(statistics_dao._THRESHOLDS, certificate_type, LOW_THRESHOLDS)


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
    failing = {name for name, (_, errors) in expected.items() if any("no such" in error for error in errors)}
    assert not monkeypatch or len(queried) == len(failing)
    return expected


def value(expected, name, key):
    return dict(expected[name][0])[_typed(key)][1]


@pytest.fixture
def edge_database(tmp_path):
    """Leaf database with the identity and join edge cases of the DISTINCT subqueries."""
    path = tmp_path / "edge.db"
    db = V2Database(path, dictionary=train_dictionary(SAMPLES))
    # Same SKI on two certificates with different values, occurrences with their own values (one with an OCSP code
    # that is not in OcspStatuses: not in the Certificates view, but in the Issuers and SCT views)
    db.add(ski="dup", validity_length=YEAR, scts=((1, 1735689600), (2, 1704067200), (1, 1735689600)),
           occurrences=({"signature": "Valid"}, {"signature": "Error", "ocsp": "Revoked"}, {"ocsp": 42}))
    db.add(ski="dup", validity_length=2 * YEAR, occurrences=({"signature": "Error"}, {"signature": "Not Valid"}))
    # Without SKI ('' or NULL): the identity is the raw, equal raws are one certificate (each has its own raw row)
    db.add(ski="", raw="raw-A", version=1, key_length="", scts=((1, 1735689600), (2, 1704067200)))
    db.add(ski=None, raw="raw-A", version=1, self_signed=1, occurrences=({}, {"issuer": 777}),
           scts=((1, 1735689600),))
    db.add(ski="", raw=b"raw-A", version=1)        # blob: another identity
    db.add(ski=None, raw=None, version=1, validity_length=-5, scts=((3, 1706745600),))      # NULL identity
    db.add(ski="", raw="dup", scts=((1, 1735689600),))     # raw equal to a SKI: the same certificate as 'dup'
    db.add(ski=b"dup", raw="x", scts=((4, 1735689600),))   # blob SKI: not equal to the text 'dup'
    db.add(ski="", raw=7)           # numeric raw
    db.add(ski="", raw=7.0)         # equal to 7 for SQLite
    # Compressed DER: the identity is the original text, also across raw rows
    db.add(ski=None, raw=CANONICAL[0], version=2, scts=((2, 1704067200),))
    db.add(ski="", raw=CANONICAL[0], version=1, occurrences=({}, {"signature": "Error"}))
    db.add(ski=None, raw=CANONICAL[1], version=2)
    # A certificate without occurrences counts nowhere
    db.certificate(ski="unseen", signature_algorithm="UNSEEN", policies=(("9.9", 1),), key_usage='{"value": 9}')
    # Occurrences of a certificate that does not exist (their SCTs are rows of the SCT view), codes not in the tables
    ghost = db.issuer("Ghost", "GH")
    db.occurrence(999, ghost, ocsp="Unknown")
    db.occurrence(999, ghost)
    db.sct(999, 1)
    db.sct(999, 3, 1706745600)
    db.add(ski="badcode", occurrences=({"ocsp": 42}, {"signature": 9}, {"ocsp": "Unknown", "issuer": 778}))
    # Values of every kind
    db.add(ski="s15", signature_algorithm=None, key_algorithm="", validity_length=None, organization=None,
           country="--", self_signed=None, version=None, subject_alt_name_is_critical="Critical")
    db.add(ski="s16", organization="DigiCert, Inc.", country=" ", key_length=None, validity_length=826 * 86400,
           validity_end="2031-07-15 10:00:00", key_usage='{"value": 0}', scts=((99, 1735689600),))
    db.add(ski="s17", organization="  ", country=None, validity_length=10 * YEAR, signature_algorithm="ECDSA-SHA256",
           key_algorithm="ECDSA", key_length=256, validation_level="OV")
    db.add(ski="s18", issuer=999, validity_length=YEAR + 0.5, validity_end=None, validation_level="EV")
    db.add(ski="s19", organization="Beta", key_usage=None, validity_end="bad", self_signed="x")
    # Policies: several (one repeated), NULL criticality, a member without its policy, a missing set, none
    db.add(ski="p1", policies=(("1.2", 1), ("1.3", None), ("1.2", 1)), organization="Beta")
    db.add(ski="p2", policies=(("1.4", 0), None), occurrences=({}, {}, {}))
    db.add(ski="p3", policies=None, policy_set_id=12345)
    db.add(ski="p4", policies=None, occurrences=({"ocsp": "Revoked"}, {}))
    # SCTs of a certificate id without certificate nor occurrences
    db.sct(5000, 1)
    db.issuer("Unused", "IT")       # without occurrences
    for status in ("connection-timeout", "unknown-error", "connection-timeout", None):
        db.error(status)
    db.close()
    return path


def test_edge_cases_match_the_queries(edge_database, caplog, monkeypatch):
    expected = compare(edge_database, DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)
    assert not any(errors for name, (_, errors) in expected.items() if name != "get_key_usage_distribution")
    # 'dup' (two certificates, the raw 'dup') is one certificate, also per occurrence; CANONICAL[0] is one more
    assert value(expected, "get_signature_validity_distribution", "Error") == 2
    assert value(expected, "get_signature_validity_distribution", "Not Valid") == 1
    # raw-A (text, twice), b'raw-A', CANONICAL[0] (twice) are three certificates of version 1; 7 and 7.0 one more
    assert value(expected, "get_certificate_version_distribution", 1) == 3
    assert value(expected, "get_certificate_version_distribution", 2) == 2
    # Occurrences with a code not in its table are not certificates; those of a missing certificate neither
    assert value(expected, "get_status_analysis", "success") == 30
    assert value(expected, "get_ocsp_status_distribution", "Unknown") == 1
    assert ("str", "UNSEEN") not in dict(expected["get_signature_algorithm_distribution"][0])
    # The SCT view repeats the SCTs of a certificate per occurrence, the ghost certificate's included
    assert value(expected, "get_top_sct_log_operators", "Google") == 3 * 3 + 2 + 2 * 1 + 1 + 1 + 2 * 1
    # Countries count every row of the Issuers view (occurrences with an issuer row, those of a missing certificate
    # included), organizations only the rows of the Certificates view
    assert value(expected, "get_certificates_per_country", "GH") == 2
    assert ("str", "Ghost") not in dict(expected["get_issuer_distribution"][0])


@pytest.mark.parametrize("bitmap", [True, False])
def test_tasks_split_in_many_ranges(edge_database, caplog, monkeypatch, bitmap):
    monkeypatch.setattr(statistics_facts, "_TASK_SECONDS", 1e-9)      # one task per few rows
    monkeypatch.setattr(statistics_facts, "_CHUNK", 3)                 # lookups and deduplication in buckets
    monkeypatch.setattr(statistics_facts, "_GROUP_SIZE", 3)            # more value groups
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 2)          # identities numbered in buckets
    if not bitmap:
        monkeypatch.setattr(statistics_facts, "_BITMAP_CELLS", 0)      # deduplication by sorting
    compare(edge_database, DatabaseType.LEAF, caplog)


def random_database(path, rows=400, seed=7, db_type=DatabaseType.LEAF):
    """Random values with many repeated identities, occurrences and references to missing rows."""
    rng = random.Random(seed)
    db = V2Database(path, db_type, dictionary=train_dictionary(SAMPLES))
    issuers = [db.issuer(rng.choice(["Alpha", "Beta", "DigiCert Inc", None, ""]),
                         rng.choice(["US", "IT", "--", None, ""])) for _ in range(rows // 10)]
    for _ in range(rows):
        ski = rng.choice(["", None, f"k{rng.randrange(rows // 3)}", f"k{rng.randrange(rows // 3)}"])
        raw = rng.choice([None, f"r{rng.randrange(rows // 4)}", f"r{rng.randrange(rows // 4)}".encode(),
                          rng.choice(CANONICAL[:20])])
        occurrences = [{"issuer": rng.choice(issuers + [10 ** 6]),
                        "signature": rng.choice(["Valid", "Not Valid", "Error", "Valid"]),
                        "ocsp": rng.choice(["Good", "Revoked", "No Request Done", "Good", 77])}
                       for _ in range(rng.choice([0, 1, 1, 1, 2, 3]))]
        policies = rng.choice([None, DEFAULT_POLICIES, (("1.2", 1), ("1.3", None)), (("1.4", None),)])
        certificate_id = db.add(
            occurrences, ski=ski, raw=raw, policies=policies,
            version=rng.choice([1, 3, 3, None]), validity_length=rng.choice(
                [None, -1, 30 * 86400, 90 * 86400, YEAR, 398 * 86400, 3 * YEAR, rng.randrange(10 ** 9)]),
            validity_end=rng.choice([None, "2025-01-31 00:00:00", "2026-02-01 00:00:00", "bad"]),
            signature_algorithm=rng.choice(["RSA-SHA256", "ECDSA-SHA384", "RSA-SHA1", None]),
            key_length=rng.choice([2048, 4096, 256, "", None]), self_signed=rng.choice([0, 1, None]),
            validation_level=rng.choice(["DV", "OV", "EV", None]),
            key_usage=json.dumps({"digital_signature": rng.random() > 0.3, "value": rng.randrange(3)}),
            key_usage_is_critical=rng.choice(["Critical", "Not Critical", None]))
        for _ in range(rng.randrange(4)):
            db.sct(rng.choice([certificate_id, certificate_id, rng.randrange(rows + 20)]), rng.choice([1, 2, 3, 4, 5]),
                   rng.choice([1704067200, 1706745600, 1735689600]))
    for _ in range(rows // 20):     # occurrences of missing certificates
        db.occurrence(rows + rng.randrange(1, 30), rng.choice(issuers))
    for _ in range(rows // 10 if db_type is DatabaseType.LEAF else 0):
        db.error(rng.choice(["connection-timeout", "unknown-error", None]))
    db.close()


def test_random_database_matches_the_queries(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db")
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)


def test_random_database_without_bitmaps(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db", seed=11)
    monkeypatch.setattr(statistics_facts, "_BITMAP_CELLS", 0)
    monkeypatch.setattr(statistics_facts, "_CHUNK", 50)
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 40)
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog)


@pytest.mark.parametrize("certificate_type", [DatabaseType.INTERMEDIATE, DatabaseType.ROOT])
def test_random_intermediate_and_root_databases(tmp_path, caplog, monkeypatch, certificate_type):
    random_database(tmp_path / "random.db", rows=200, seed=13, db_type=certificate_type)
    compare(tmp_path / "random.db", certificate_type, caplog, monkeypatch=monkeypatch)


def test_render_processes_run_the_scans(tmp_path, caplog):
    random_database(tmp_path / "random.db", rows=300, seed=3)
    with ProcessPoolExecutor(2, mp_context=get_context("spawn")) as executor:
        compare(tmp_path / "random.db", DatabaseType.LEAF, caplog, executor, workers=2)


def test_identities_numbered_in_more_than_256_buckets(tmp_path, caplog, monkeypatch):
    random_database(tmp_path / "random.db", rows=1200, seed=5)
    monkeypatch.setattr(statistics_facts, "_DIGEST_CHUNK", 1)
    compare(tmp_path / "random.db", DatabaseType.LEAF, caplog)


def test_ingested_database_matches_the_queries(open_database, caplog, monkeypatch):
    """A database written by the ingestion's single-row path, with repeated certificates and updated codes."""
    pki = Pki()
    rows = pki.rows(5)
    for db_type in (DatabaseType.LEAF, DatabaseType.INTERMEDIATE):
        database, dao = open_database(db_type)
        with database.transaction():
            for row in rows + rows[:3]:     # the first rows twice: certificates with two occurrences
                tls = row["data"]["tls"]
                if tls["status"] != "success":
                    if db_type is DatabaseType.LEAF:
                        dao.insert_error_row(row)
                    continue
                server = tls["result"]["handshake_log"]["server_certificates"]
                if db_type is DatabaseType.LEAF:
                    dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
                else:
                    dao.process_insert_certificate(row, server["chain"][0], server["chain"][1:], 1)
            database.conn.execute("UPDATE Occurrences SET ocsp_check = occurrence_id % 3")
            if db_type is DatabaseType.LEAF:
                database.conn.execute("UPDATE Occurrences SET signature_valid = 1 WHERE occurrence_id IN (2, 6)")
        database.prepare_for_plots()
        expected = compare(database.db_path, db_type, caplog, monkeypatch=monkeypatch)
        if db_type is DatabaseType.LEAF:
            assert value(expected, "get_status_analysis", "success") == 8
        assert value(expected, "get_certificate_version_distribution", 3) == (5 if db_type is DatabaseType.LEAF else 1)


def test_equal_issuer_counts_are_in_organization_order(tmp_path, caplog):
    path = tmp_path / "ties.db"
    db = V2Database(path)
    for number, organization in enumerate(["Zeta", "Alpha", "Mid", "Alpha", "Zeta", "Beta", "DigiCert, Inc."], 1):
        db.add(ski=f"s{number}", organization=organization)
    db.close()
    for top, expected_keys in ((3, ["Alpha", "Zeta", "Beta", "Others"]),
                               (10, ["Alpha", "Zeta", "Beta", "DigiCert, Inc.", "Mid"])):
        statistics_dao._THRESHOLDS[DatabaseType.LEAF] = Thresholds(1, 1, 1, 1, top_issuers=top)
        expected = compare(path, DatabaseType.LEAF, caplog)
        assert [key for (_, key), _ in expected["get_issuer_certificate_count"][0]] == expected_keys


def test_null_key_usage_logs_the_same_error(tmp_path, caplog):
    path = tmp_path / "null.db"
    db = V2Database(path)
    db.add(key_usage=None)
    db.add(ski="other")
    db.close()
    expected = compare(path, DatabaseType.LEAF, caplog)
    assert expected["get_key_usage_distribution"][0] == [] and expected["get_key_usage_distribution"][1]


@pytest.mark.parametrize("certificate_type", [DatabaseType.INTERMEDIATE, DatabaseType.ROOT])
def test_final_layouts_and_missing_tables(tmp_path, caplog, monkeypatch, certificate_type):
    path = tmp_path / f"{certificate_type.value}.db"
    db = V2Database(path, certificate_type)
    for ski in ("a", "a", "b", ""):
        db.add(ski=ski, raw=f"r{ski}", occurrences=({}, {"signature": "Error"}))
    db.close()
    expected = compare(path, certificate_type, caplog, monkeypatch=monkeypatch)
    assert expected["get_status_analysis"] == ([], ["Statistics query failed: no such table: Errors"])
    if certificate_type is DatabaseType.INTERMEDIATE:
        assert expected["get_signature_validity_distribution"] == (
            [], ["Statistics query failed: no such column: signature_valid"])
    else:
        assert value(expected, "get_signature_validity_distribution", "Error") == 3


def test_empty_database(tmp_path, caplog):
    V2Database(tmp_path / "empty.db").close()
    compare(tmp_path / "empty.db", DatabaseType.LEAF, caplog)


def test_only_rows_without_their_certificates_match_the_queries(tmp_path, caplog, monkeypatch):
    path = tmp_path / "orphans.db"
    db = V2Database(path)
    db.certificate(ski="alone")     # no occurrences
    db.occurrence(5, db.issuer())   # no certificate
    db.sct(5, 1)
    db.sct(6, 2)
    db.close()
    compare(path, DatabaseType.LEAF, caplog, monkeypatch=monkeypatch)


def test_not_materialized_without_a_shared_file(tmp_path, caplog):
    memory = sqlite3.connect(":memory:")
    assert not StatisticsDAO(memory, DatabaseType.LEAF).materialize()
    memory.close()
    path = tmp_path / "busy.db"
    connection = V2Database(path).finish()
    connection.execute("BEGIN")
    connection.execute("DELETE FROM Logs")
    assert not StatisticsDAO(connection, DatabaseType.LEAF).materialize()
    connection.rollback()
    connection.close()


def _uses_the_queries(path, message, caplog):
    with StatisticsDAO.reading(str(path), DatabaseType.LEAF) as dao:
        with caplog.at_level(logging.WARNING):
            assert not dao.materialize()
        assert "Statistics not materialized" in caplog.text and message in caplog.text
        connection = sqlite3.connect(path)
        try:
            assert results(dao, caplog) == results(StatisticsDAO(connection, DatabaseType.LEAF), caplog)
        finally:
            connection.close()


def test_a_failure_falls_back_to_the_queries(edge_database, caplog, monkeypatch):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(statistics_facts, "collect", broken)
    _uses_the_queries(edge_database, "disk I/O error", caplog)


def test_a_key_that_is_not_an_integer_uses_the_queries(edge_database, caplog):
    connection = sqlite3.connect(edge_database)
    with connection:
        connection.execute("UPDATE SctData SET log_id = 'x' WHERE certificate_id = 1 AND position = 0")
    connection.close()
    _uses_the_queries(edge_database, "", caplog)


def test_databases_without_the_base_tables_use_the_queries(tmp_path, caplog):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    with connection:
        connection.execute("CREATE TABLE Certificates (certificate_id INTEGER PRIMARY KEY, ocsp_check VARCHAR(36))")
        connection.executemany("INSERT INTO Certificates (ocsp_check) VALUES (?)", [("Good",), ("Revoked",)])
    connection.close()
    _uses_the_queries(path, "the database has no CertificateData table", caplog)


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


def test_identity_is_the_original_raw_text(tmp_path):
    """As in the old tables, a certificate without SKI is identified by the text of its raw, also when another
    certificate has that text as its SKI; the views show the raw as stored (compressed), so their DISTINCT does not."""
    path = tmp_path / "text.db"
    db = V2Database(path)
    db.add(ski=CANONICAL[2], raw="other", version=9)
    db.add(ski=None, raw=CANONICAL[2], version=9)
    db.close()
    with StatisticsDAO.reading(str(path), DatabaseType.LEAF) as dao:
        assert dao.get_certificate_version_distribution() == {9: 2}
        assert dao.materialize()
        assert dao.get_certificate_version_distribution() == {9: 1}
