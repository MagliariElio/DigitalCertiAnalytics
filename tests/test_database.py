"""Tests for Database (schema version 2), the raw codec, CertificateDAO and Certificate."""
import base64
import copy
import datetime
import sqlite3

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID
from helpers import raw

from bean.certificate import Certificate
from dao.certificate_dao import certificate_key
from db import database as database_module
from db import schema
from db.database import PAGE_SIZE, Database, DatabaseType, OutdatedDatabaseError, database_state
from db.raw_codec import RawCodec, canonical_der, register_sql_functions, train_dictionary
from utils.chain_utils import find_root_certificate, intermediate_certificates, verify_signature

# Columns of the old tables, in their order (the views keep them)
OLD_CERTIFICATE_COLUMNS = [
    "certificate_id", "serial_number", "leaf_domain", "issuer_id", "subject_id", "version", "signature_algorithm",
    "key_algorithm", "key_length", "validity_start", "validity_end", "validity_length", "SAN", "domain_matches_san",
    "authority_info_access_is_critical", "authority_info_access", "ocsp_check", "ocsp_stapling", "ocsp_must_stapling",
    "validation_level", "signature_valid", "self_signed", "redacted", "certificates_emitted_up_to",
    "certificates_up_to_root_count", "has_root_certificate", "download_date", "raw"]
REMOVED = {
    DatabaseType.LEAF: {"certificates_emitted_up_to"},
    DatabaseType.INTERMEDIATE: {"ocsp_stapling", "ocsp_must_stapling", "signature_valid", "SAN", "domain_matches_san"},
    DatabaseType.ROOT: {"ocsp_stapling", "ocsp_must_stapling", "certificates_up_to_root_count", "has_root_certificate",
                        "SAN", "domain_matches_san"},
}
OLD_TABLES = {
    "Issuers": ["issuer_id", "common_name", "organization", "issuer_dn", "country", "province", "locality",
                "organizational_unit", "authority_key_id", "raw"],
    "Subjects": ["subject_id", "common_name", "subject_dn", "subject_key_id", "subject_alt_name",
                 "subject_alt_name_is_critical"],
    "Extensions": ["extension_id", "certificate_id", "key_usage", "key_usage_is_critical", "extended_key_usage",
                   "extended_key_usage_is_critical", "basic_constraints", "max_path_length", "crl_distribution_points",
                   "crl_distr_point_is_critical", "crl_revocation_status"],
    "SignedCertificateTimestamps": ["id", "certificate_id", "log_id", "timestamp", "version", "signature"],
    "CertificatePolicies": ["policy_id", "extension_id", "policy_identifier", "cps", "policy_qualifiers", "is_cp_critical"],
}
ERRORS_COLUMNS = ["error_id", "domain", "status", "protocol", "timestamp", "error_message", "download_date"]


def columns(conn, table):
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def insert_rows(database, dao, rows):
    """Insert as the analysis does: leaf certificate or error, intermediates, root (one transaction per row)."""
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


def count(database, table):
    return database.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# ---------------------------------------------------------------- layout and views

@pytest.mark.parametrize("db_type", list(DatabaseType))
def test_new_database_has_the_v2_header_and_the_old_tables_as_views(open_database, db_type):
    database, _ = open_database(db_type)
    conn = database.conn
    assert conn.execute("PRAGMA application_id").fetchone()[0] == schema.APPLICATION_ID
    assert conn.execute("PRAGMA user_version").fetchone()[0] == schema.SCHEMA_VERSION == 2
    assert conn.execute("PRAGMA page_size").fetchone()[0] == PAGE_SIZE
    info = dict(conn.execute("SELECT key, value FROM SchemaInfo"))
    assert info == {"schema_version": 2, "database_type": db_type.value}
    assert [tuple(row) for row in conn.execute("SELECT * FROM OcspStatuses ORDER BY code")] == list(
        enumerate(schema.OCSP_STATUSES))
    assert schema.OCSP_CODES["No Request Done"] == schema.NO_REQUEST_DONE == 0
    assert schema.SIGNATURE_CODES["Unsupported Key Type"] == 3

    views = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'view'")}
    assert views == set(OLD_TABLES) | {"Certificates"} | ({"Errors"} if db_type is DatabaseType.LEAF else set())
    assert columns(conn, "Certificates") == [name for name in OLD_CERTIFICATE_COLUMNS if name not in REMOVED[db_type]]
    for table, names in OLD_TABLES.items():
        assert columns(conn, table) == names
    if db_type is DatabaseType.LEAF:
        assert columns(conn, "Errors") == ERRORS_COLUMNS
    assert schema.ddl(db_type) == schema.ddl(db_type.value)


def test_leaf_rows_through_the_views(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    rows = pki.rows(6)
    insert_rows(database, dao, rows)

    assert dao.get_certificates_count() == 6 == count(database, "Certificates")
    assert count(database, "Errors") == 2
    assert count(database, "SignedCertificateTimestamps") == 12
    has_root = database.conn.execute("SELECT has_root_certificate, COUNT(*) FROM Certificates GROUP BY 1 ORDER BY 1")
    assert [tuple(row) for row in has_root] == [(0, 3), (1, 3)]
    first = database.conn.execute("SELECT * FROM Certificates WHERE certificate_id = 1").fetchone()
    parsed = rows[0]["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["parsed"]
    assert first["serial_number"] == parsed["serial_number"] and first["leaf_domain"] == "site0.example.test"
    assert first["ocsp_check"] == "No Request Done" and first["signature_valid"] == "Valid"
    assert first["issuer_id"] == first["subject_id"] == 1 and first["ocsp_stapling"] == 1

    # The raw columns of the views are the stored values: the original text through the codec
    codec = database.raw_codec()
    stored = database.conn.execute("SELECT der_zstd, raw FROM RawCertificates AS r JOIN CertificateData AS c "
                                   "ON c.raw_id = r.raw_id WHERE c.certificate_id = 1").fetchone()
    assert codec.decode(*stored) == rows[0]["data"]["tls"]["result"]["handshake_log"]["server_certificates"][
        "certificate"]["raw"]
    extension = database.conn.execute("SELECT * FROM Extensions WHERE extension_id = 1").fetchone()
    assert extension["crl_revocation_status"] == "No Request Done"
    assert extension["key_usage"] == '{"digital_signature": true, "value": 1}'
    error = database.conn.execute("SELECT * FROM Errors ORDER BY error_id").fetchone()
    assert tuple(error)[1:] == ("down.example.test", "connection-timeout", "tls", error["timestamp"], "boom",
                                error["timestamp"])


def test_repeated_certificates_and_issuers_are_stored_once(pki, open_database):
    """Every occurrence keeps its own values in the views; certificates, issuers and raws are stored once."""
    database, dao = open_database(DatabaseType.INTERMEDIATE)
    rows = [row for row in pki.rows(6) if row["data"]["tls"]["status"] == "success"]
    insert_rows(database, dao, rows)
    assert count(database, "Occurrences") == 6 and count(database, "Certificates") == 6
    assert count(database, "CertificateData") == 1
    # The issuer raw (the root) is in the chain of the even rows only: two issuer rows
    assert count(database, "IssuerData") == 2
    assert count(database, "RawCertificates") == 2       # the intermediate (its own raw) and the root (issuer raw)
    emitted = [row[0] for row in database.conn.execute("SELECT certificates_emitted_up_to FROM Certificates")]
    assert emitted == [1] * 6
    domains = [row[0] for row in database.conn.execute("SELECT leaf_domain FROM Certificates ORDER BY certificate_id")]
    assert domains == [f"site{i}.example.test" for i in range(6)]


def test_intermediate_and_root_ingestion(pki, open_database):
    intermediate_db, intermediate_dao = open_database(DatabaseType.INTERMEDIATE)
    root_db, root_dao = open_database(DatabaseType.ROOT)
    rows = pki.rows(4)
    insert_rows(intermediate_db, intermediate_dao, rows)
    insert_rows(root_db, root_dao, rows)

    assert intermediate_dao.get_certificates_count() == 4
    assert root_dao.get_certificates_count() == 2
    assert "SAN" not in columns(intermediate_db.conn, "Certificates")
    assert "has_root_certificate" not in columns(root_db.conn, "Certificates")
    validity = root_db.conn.execute("SELECT signature_valid, COUNT(*) FROM Certificates GROUP BY 1").fetchall()
    assert [tuple(row) for row in validity] == [("Valid", 2)]
    tables = {row[0] for row in root_db.conn.execute("SELECT name FROM sqlite_master")}
    assert "Errors" not in tables and "ErrorData" not in tables


def test_rows_are_not_mutated(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    row = pki.rows(1)[0]
    before = repr(row)
    insert_rows(database, dao, [row])
    assert repr(row) == before


def test_prepare_for_plots_corrects_the_issuer_organization(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    rows = pki.rows(2)
    for row in rows[:2]:
        server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
        server["certificate"]["parsed"]["issuer"]["organization"] = ["DigiCert, Inc."]
    insert_rows(database, dao, rows)
    database.prepare_for_plots()
    organizations = {row[0] for row in database.conn.execute("SELECT organization FROM Issuers")}
    assert organizations == {"DigiCert Inc"}


# ---------------------------------------------------------------- single-row path: same failures as before

def _leaf_row(pki, change):
    row = copy.deepcopy(pki.rows(1)[0])
    change(row["data"]["tls"]["result"]["handshake_log"]["server_certificates"])
    return row


@pytest.mark.parametrize("change, message", [
    (lambda server: server["certificate"]["parsed"].__setitem__("version", 2 ** 64),
     "Python int too large to convert to SQLite INTEGER"),
    (lambda server: server["certificate"]["parsed"]["subject"].__setitem__("common_name", ["ok\udcff"]),
     "'utf-8' codec can't encode character '\\udcff' in position 2: surrogates not allowed"),
    (lambda server: server["certificate"]["parsed"]["extensions"]["signed_certificate_timestamps"][1].__setitem__(
        "signature", None), "NOT NULL constraint failed: SignedCertificateTimestamps.signature"),
    (lambda server: server["certificate"]["parsed"]["extensions"]["signed_certificate_timestamps"][0].__setitem__(
        "timestamp", None), "NOT NULL constraint failed: SignedCertificateTimestamps.timestamp"),
    (lambda server: server["certificate"]["parsed"].__setitem__("serial_number", ["1"]), None),
])
def test_values_that_cannot_be_stored_fail_the_row_with_the_old_error(pki, open_database, change, message):
    database, dao = open_database(DatabaseType.LEAF)
    with pytest.raises(Exception) as error:
        insert_rows(database, dao, [_leaf_row(pki, change)])
    if message is None:
        # The binding error of the old Certificates insert (its text depends on the Python version)
        with pytest.raises(Exception) as expected:
            sqlite3.connect(":memory:").execute(f"SELECT {', '.join('?' * 26)}", (["1"],) + (None,) * 25)
        message = str(expected.value)
    assert str(error.value) == message
    for table in ("Occurrences", "CertificateData", "IssuerData", "RawCertificates", "SctData"):
        assert count(database, table) == 0, table


def test_chain_certificate_without_raw_fails_the_row(pki, open_database):
    database, dao = open_database(DatabaseType.INTERMEDIATE)
    with pytest.raises(KeyError, match="'raw'"):
        insert_rows(database, dao, [_leaf_row(pki, lambda server: server["chain"][0].pop("raw"))])
    assert count(database, "Occurrences") == 0


def test_dropped_column_value_that_cannot_be_bound_fails_the_row(pki, open_database):
    """SAN is not stored for intermediates, but a value that cannot be bound still invalidates the row."""
    database, dao = open_database(DatabaseType.INTERMEDIATE)
    with pytest.raises(UnicodeEncodeError):
        insert_rows(database, dao, [_leaf_row(pki, lambda server: server["chain"][0]["parsed"].__setitem__(
            "names", ["ok", "\ud800"]))])
    assert count(database, "Occurrences") == 0 and count(database, "IssuerData") == 0


def test_unknown_sct_logs_are_added_under_the_unknown_operator(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    with database.transaction():
        dao.insert_sct_logs({"operators": []})
    insert_rows(database, dao, pki.rows(1)[:1])
    logs = database.conn.execute("SELECT l.log_id, o.name FROM Logs AS l JOIN LogsOperators AS o "
                                 "ON o.id = l.operator_id ORDER BY l.id").fetchall()
    assert [tuple(row) for row in logs] == [("log0==", "unknown"), ("log1==", "unknown")]
    stored = database.conn.execute("SELECT log_id, typeof(log_id) FROM SignedCertificateTimestamps ORDER BY id")
    assert [tuple(row) for row in stored] == [("1", "text"), ("2", "text")]


def test_certificate_keys_keep_the_value_types_apart():
    keys = {certificate_key((value,), (), (), None) for value in (1, 1.0, "1", True, None, -0.0, 0.0, b"1")}
    assert len(keys) == 8
    one, other = "Not Critical", "".join(["Not ", "Critical"])
    assert certificate_key((one, one), (), (), None) == certificate_key((one, other), (), (), None)
    assert certificate_key(("a\ud800",), (), (), None) != certificate_key(("a",), (), (), None)


# ---------------------------------------------------------------- transactions

def test_transaction_rolls_back_on_keyboard_interrupt(open_database):
    database, _ = open_database()
    with pytest.raises(KeyboardInterrupt):
        with database.transaction():
            database.conn.execute("INSERT INTO ErrorData (domain) VALUES ('x')")
            raise KeyboardInterrupt
    assert count(database, "ErrorData") == 0


def test_bulk_insert_mode_restores_journal(open_database):
    database, _ = open_database()
    with database.bulk_insert_mode():
        assert database.conn.execute("PRAGMA journal_mode").fetchone()[0] == "truncate"
    assert database.conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_row_transactions_are_batched_and_isolated(open_database):
    database, _ = open_database()
    with database.bulk_insert_mode():
        for i in range(5):
            try:
                with database.row_transaction():
                    database.conn.execute("INSERT INTO ErrorData (domain) VALUES (?)", (f"d{i}",))
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
                    database.conn.execute("INSERT INTO ErrorData (domain, error_message) VALUES (?, ?)",
                                          (f"d{i}", "x" * 200))
            except sqlite3.OperationalError as e:
                errors.add(str(e))
    assert errors == {"database or disk is full"}
    assert "uncommitted lines were lost" in caplog.text


def test_whole_rollback_reports_the_pending_rows_added_by_the_caller(open_database, caplog):
    """The ingestion engine adds the rows it copies in bulk to pending_rows, so a lost transaction reports them too."""
    database, _ = open_database()
    database.conn.execute("CREATE TEMP TRIGGER full_disk BEFORE INSERT ON main.ErrorData WHEN NEW.domain = 'full' "
                          "BEGIN SELECT RAISE(ROLLBACK, 'database or disk is full'); END")
    with database.bulk_insert_mode():
        database.conn.execute("BEGIN")
        database.conn.executemany("INSERT INTO ErrorData (domain) VALUES (?)", [("copied",)] * 3)
        database.pending_rows += 3
        with database.row_transaction():
            database.conn.execute("INSERT INTO ErrorData (domain) VALUES ('row')")
        assert database.pending_rows == 4
        with pytest.raises(sqlite3.IntegrityError):
            with database.row_transaction():
                database.conn.execute("INSERT INTO ErrorData (domain) VALUES ('full')")
        assert database.pending_rows == 0
    assert "the rows of 4 uncommitted lines were lost" in caplog.text
    assert count(database, "ErrorData") == 0


def test_interrupted_bulk_insert_keeps_completed_rows(open_database):
    database, _ = open_database()
    with pytest.raises(KeyboardInterrupt):
        with database.bulk_insert_mode():
            with database.row_transaction():
                database.conn.execute("INSERT INTO ErrorData (domain) VALUES ('completed')")
            with database.row_transaction():
                database.conn.execute("INSERT INTO ErrorData (domain) VALUES ('partial')")
                raise KeyboardInterrupt
    assert [row[0] for row in database.conn.execute("SELECT domain FROM Errors")] == ["completed"]


# ---------------------------------------------------------------- old databases and requirements

def test_database_state_and_outdated_databases(tmp_path, open_database):
    assert database_state(tmp_path / "missing.db") == "missing"
    (tmp_path / "empty.db").write_bytes(b"")
    assert database_state(tmp_path / "empty.db") == "missing"
    database, _ = open_database(DatabaseType.ROOT, name="current.db")
    assert database_state(database.db_path) == "current"

    old = tmp_path / "root_certificates.db"
    with sqlite3.connect(old) as conn:
        conn.execute("CREATE TABLE Certificates (certificate_id INTEGER PRIMARY KEY, raw BLOB)")
    conn.close()
    assert database_state(old) == "outdated"
    (tmp_path / "garbage.db").write_bytes(b"not a database" * 100)
    assert database_state(tmp_path / "garbage.db") == "outdated"

    outdated = Database(old, DatabaseType.ROOT)
    with pytest.raises(OutdatedDatabaseError) as error:
        outdated.connect()
    assert str(error.value) == (f"The root database '{old}' was created by an older version of DigitalCertiAnalytics: "
                                "run the analysis again with --root_analysis to recreate it.")
    assert outdated.conn is None
    outdated.connect(delete_database=True)
    try:
        assert database_state(old) == "current"
    finally:
        outdated.close()


def test_old_sqlite_and_missing_zstandard_give_clear_errors(tmp_path, monkeypatch):
    database = Database(tmp_path / "leaf.db", DatabaseType.LEAF)
    monkeypatch.setattr(database_module.sqlite3, "sqlite_version_info", (3, 24, 0))
    with pytest.raises(RuntimeError, match="needs SQLite 3.25 or newer. Run the installer again"):
        database.connect()
    monkeypatch.undo()
    monkeypatch.setattr(database_module, "zstandard", None)
    with pytest.raises(RuntimeError, match="'zstandard' is not installed. Run the installer again"):
        database.connect()
    assert not (tmp_path / "leaf.db").exists()


# ---------------------------------------------------------------- raw codec

def test_raw_codec_round_trip_and_verbatim_values(pki):
    canonical = raw(pki.root)
    samples = [base64.b64decode(raw(pki.leaf(f"s{i}.example.test", 100 + i))) for i in range(80)]
    dictionary = train_dictionary(samples)
    assert dictionary is not None and train_dictionary(samples[:10]) is None
    assert train_dictionary(samples) == dictionary, "deterministic"
    for codec in (RawCodec(None), RawCodec(dictionary)):
        der_zstd, verbatim = codec.encode(canonical)
        assert verbatim is None and der_zstd != base64.b64decode(canonical)
        assert codec.decode(der_zstd, None) == canonical
        assert codec.der(der_zstd, None) == base64.b64decode(canonical)
        wrapped = canonical[:64] + "\n" + canonical[64:]
        for value in ("", wrapped, "not base64!!", "QUJD\n", 5, 2.5, "\ud800"):
            assert codec.encode(value) == (None, value)
            assert codec.decode(None, value) == value
            assert codec.der(None, value) is None
    assert canonical_der("QUJD") == b"ABC" and canonical_der("QUJ D") is None and canonical_der(b"QUJD") is None


def test_raw_dictionary_is_stored_once_before_the_raws(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    samples = [base64.b64decode(raw(pki.leaf(f"s{i}.example.test", 100 + i))) for i in range(80)]
    dictionary = train_dictionary(samples)
    database.set_raw_dictionary(dictionary)
    dao.raw_codec = database.raw_codec()
    assert RawCodec.for_connection(database.conn).dictionary == dictionary
    assert database.conn.execute("SELECT value FROM SchemaInfo WHERE key = 'raw_dictionary_id'").fetchone()[0] == 1
    rows = pki.rows(2)
    insert_rows(database, dao, rows)
    with pytest.raises(RuntimeError, match="cannot change once raw certificates are stored"):
        database.set_raw_dictionary(None)

    register_sql_functions(database.conn)
    stored = database.conn.execute("SELECT dca_raw(r.der_zstd, r.raw) FROM CertificateData AS c JOIN RawCertificates "
                                   "AS r ON r.raw_id = c.raw_id ORDER BY c.certificate_id").fetchall()
    assert [row[0] for row in stored] == [row["data"]["tls"]["result"]["handshake_log"]["server_certificates"][
        "certificate"]["raw"] for row in rows[:2]]


def test_raw_values_keep_their_storage_class(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    rows = []
    for value in ("", "QUJD\n", 7):
        row = copy.deepcopy(pki.rows(1)[0])
        row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["raw"] = value
        rows.append(row)
    insert_rows(database, dao, rows)
    stored = database.conn.execute("SELECT raw, typeof(raw) FROM Certificates ORDER BY certificate_id").fetchall()
    assert [tuple(row) for row in stored] == [("", "text"), ("QUJD\n", "text"), (7, "integer")]


def test_lookup_values_keep_the_old_affinity(pki, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    row = copy.deepcopy(pki.rows(1)[0])
    parsed = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["parsed"]
    parsed["validation_level"] = 5                     # VARCHAR: stored as the text '5'
    row["data"]["tls"]["timestamp"] = "1727000000"     # TIMESTAMP: stored as the integer
    other = copy.deepcopy(row)
    other["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["parsed"][
        "validation_level"] = "5"
    insert_rows(database, dao, [row, other])
    stored = database.conn.execute("SELECT validation_level, typeof(validation_level), download_date, "
                                   "typeof(download_date) FROM Certificates").fetchall()
    assert [tuple(r) for r in stored] == [("5", "text", 1727000000, "integer")] * 2
    assert count(database, "TextValues") == len({r[0] for r in database.conn.execute("SELECT value FROM TextValues")})
    assert count(database, "CertificateData") == 2, "different JSON values: two certificates, same stored values"


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


def test_certificate_from_der_matches_the_raw_text(pki, caplog):
    text = raw(pki.intermediate)
    from_text, from_der = Certificate(text), Certificate.from_der(base64.b64decode(text), text)
    assert from_der.raw == text and from_der.cert == from_text.cert
    assert from_der.extension_criticality(ExtensionOID.KEY_USAGE) == from_text.extension_criticality(ExtensionOID.KEY_USAGE)
    caplog.clear()
    assert Certificate.from_der(b"garbage").cert is None
    assert "Invalid certificate, parsing error" in caplog.text
