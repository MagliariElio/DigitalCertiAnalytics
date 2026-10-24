"""The SQLite storage of the ZLint results (db.zlint_store) and reading_zlint_results.py."""
import random
import sqlite3
import subprocess
import sys
from collections import Counter
from itertools import repeat
from pathlib import Path

import pytest
from helpers import Pki

from analysis.zlint_analysis import reading_zlint_results as reading
from db import zlint_store
from db.database import DatabaseType
from db.raw_codec import register_sql_functions
from db.zlint_store import LintResult, ZlintReader, ZlintStore, body_digest, decode_body, encode_body

READER = Path(reading.__file__)


def _database(open_database, count=3, db_type=DatabaseType.LEAF, repeat_rows=1):
    database, dao = open_database(db_type)
    for row in Pki().rows(count):
        if row["data"]["tls"]["status"] == "success":
            server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            for _ in range(repeat_rows):
                with database.transaction():
                    dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    return database, dao


def _all(conn, sql):
    return [tuple(row) for row in conn.execute(sql)]


def _units(conn):
    return [row[0] for row in conn.execute("SELECT DISTINCT COALESCE(raw_id, 0) FROM CertificateData ORDER BY 1")]


def _ok(raw_id, zlint_result):
    body = encode_body(zlint_result)
    return LintResult(raw_id, body_digest(body), body, None, None)


def _error(raw_id, message="Error running ZLint: unable to parse PEM\n"):
    return LintResult(raw_id, None, None, message, "2024-10-06 12:30:00,123")


def _output(*warnings):
    """A zlint-like output of a few hundred lints, with the given lints as warnings."""
    return {f"e_lint_{index:03d}": {"result": "warn" if f"e_lint_{index:03d}" in warnings else "pass"}
            for index in range(300)}


def _started_store(conn):
    store = ZlintStore(conn)
    store.start("ZLint version test")
    return store


def _types(value):
    """The value with the type of every element, to compare results that are equal but of other types."""
    if isinstance(value, dict):
        return [(key, _types(item)) for key, item in value.items()]
    if isinstance(value, list):
        return [_types(item) for item in value]
    return type(value), value


def test_body_keeps_key_order_and_value_types():
    lint = {"result": "NA", "n": 1.0, "t": True, "z": None, "s": "1", "list": [1, "x", {"k": False}]}
    output = {"w_b": {"result": "warn", "n": 1}, "e_a": lint, "text": "\ud800 lone surrogate", "é": "ü", "big": 2 ** 70}
    body = encode_body(output)
    assert decode_body(body) == output
    assert _types(decode_body(body)) == _types(output)
    assert len({body_digest(encode_body({"n": value})) for value in (1, 1.0, True, "1", None)}) == 5


def test_equal_outputs_are_stored_once_with_the_first_as_dictionary(open_database):
    _, dao = _database(open_database)
    conn = dao.connection
    first, second, third = _units(conn)
    store = _started_store(conn)

    store.save([_ok(first, _output()), _ok(second, _output("e_lint_007")), _ok(third, _output())])

    body = encode_body(_output())
    assert _all(conn, "SELECT zstd_dictionary FROM ZlintDictionaries") == [(body,)]
    stored = _all(conn, "SELECT body_id, sha256, LENGTH(body_zstd) FROM ZlintBodies ORDER BY body_id")
    assert [(body_id, sha256) for body_id, sha256, _ in stored] == [
        (1, body_digest(body)), (2, body_digest(encode_body(_output("e_lint_007"))))]
    # Outputs differ in a few lints: with the first one as dictionary each takes a few dozen bytes
    assert all(size < len(body) // 50 for _, _, size in stored)
    assert _all(conn, "SELECT raw_id, body_id FROM ZlintResults ORDER BY raw_id") == [
        (first, 1), (second, 2), (third, 1)]
    reader = ZlintReader(conn)
    assert reader.body(1) == _output() and reader.body(2) == _output("e_lint_007")
    assert list(reader.body(2)) == list(_output())


def test_failed_save_stores_nothing_and_the_next_one_works(open_database):
    _, dao = _database(open_database)
    conn = dao.connection
    first, second, _ = _units(conn)
    store = _started_store(conn)

    with pytest.raises(sqlite3.IntegrityError):
        # The same certificate twice: the whole save is rolled back, its dictionary too
        store.save([_ok(first, _output()), _ok(first, _output())])
    assert conn.execute("SELECT (SELECT COUNT(*) FROM ZlintResults) + (SELECT COUNT(*) FROM ZlintBodies) + "
                        "(SELECT COUNT(*) FROM ZlintDictionaries)").fetchone()[0] == 0

    store.save([_ok(first, _output("e_lint_001")), _error(second)])
    assert conn.execute("SELECT zstd_dictionary FROM ZlintDictionaries").fetchone()[0] == encode_body(
        _output("e_lint_001"))
    assert ZlintReader(conn).body(1) == _output("e_lint_001")
    assert _all(conn, "SELECT raw_id, body_id, error_message FROM ZlintResults ORDER BY raw_id") == [
        (first, 1, None), (second, None, "Error running ZLint: unable to parse PEM\n")]


def test_body_cache_is_bounded(open_database, monkeypatch):
    monkeypatch.setattr(zlint_store, "BODY_CACHE_SIZE", 1)
    _, dao = _database(open_database)
    conn = dao.connection
    first, second, third = _units(conn)
    store = _started_store(conn)

    for raw_id, output in ((first, _output()), (second, _output("e_lint_002")), (third, _output())):
        store.save([_ok(raw_id, output)])

    assert len(store._body_ids) <= 1
    assert _all(conn, "SELECT raw_id, body_id FROM ZlintResults ORDER BY raw_id") == [
        (first, 1), (second, 2), (third, 1)]


def test_start_replaces_the_results_and_keeps_the_issuers_as_they_were(open_database):
    database, dao = _database(open_database)
    conn = dao.connection
    store = _started_store(conn)
    store.save([_ok(raw_id, _output()) for raw_id in _units(conn)])
    assert zlint_store.has_tables(conn)

    store = _started_store(conn)
    assert conn.execute("SELECT COUNT(*) FROM ZlintResults").fetchone()[0] == 0
    assert _all(conn, "SELECT * FROM ZlintIssuers") == _all(
        conn, "SELECT issuer_id, common_name, organization, issuer_dn FROM IssuerData")
    store.save([_ok(raw_id, _output()) for raw_id in _units(conn)])
    reader = ZlintReader(conn)
    organizations = [row[0] for row in reader.documents("issuer_organization")]
    assert len(organizations) == 3 and "Changed" not in organizations
    # e.g. the chart correction of the issuer organizations, after ZLint ran
    conn.execute("UPDATE IssuerData SET organization = 'Changed'")
    conn.commit()

    assert [row[0] for row in reader.documents("issuer_organization")] == organizations
    assert reader.run_values()["zlint_version"] == "ZLint version test"
    store.finish("finished")
    assert reader.run_values()["state"] == "finished"


def test_units_are_the_distinct_raws_of_the_certificates(open_database):
    database, dao = _database(open_database, count=3, repeat_rows=2)
    conn = dao.connection
    # The certificate of the first two occurrences has no raw
    conn.execute("UPDATE CertificateData SET raw_id = NULL WHERE certificate_id = 1")
    conn.commit()
    store = _started_store(conn)

    assert store.prepare_units() == 3
    batches = list(store.iter_units(2))
    assert [len(batch) for batch in batches] == [2, 1]
    units = [row for batch in batches for row in batch]
    # raw_id 0 stands for the certificates without a raw; raws of the issuers only are not linted
    assert units[0] == (0, None, None)
    assert [raw_id for raw_id, _, _ in units] == _units(conn)
    issuer_raws = {row[0] for row in conn.execute("SELECT raw_id FROM IssuerData")}
    assert issuer_raws and not issuer_raws & {raw_id for raw_id, _, _ in units}
    codec = database.raw_codec()
    register_sql_functions(conn)
    certificate_raws = {row[0] for row in conn.execute(
        "SELECT dca_raw(r.der_zstd, r.raw) FROM CertificateData AS c JOIN RawCertificates AS r ON r.raw_id = c.raw_id")}
    assert {codec.decode(der_zstd, raw) for _, der_zstd, raw in units[1:]} == certificate_raws
    store.drop_units()
    assert conn.execute("SELECT name FROM sqlite_temp_master WHERE name = 'zlint_units'").fetchone() is None


def test_errors_are_listed_once_per_occurrence_in_id_order(open_database):
    _, dao = _database(open_database, count=2, repeat_rows=2)
    conn = dao.connection
    first, second = _units(conn)
    store = _started_store(conn)
    store.save([_ok(first, _output())])
    assert list(store.error_occurrences()) == []

    store.save([_error(second, "failed")])
    assert list(store.error_occurrences()) == [(3, "failed"), (4, "failed")]


# --- reading_zlint_results.py ----------------------------------------------------------------------------------------

def _v1_collect_statistics(documents):
    """The per-document counting of the MongoDB version, the reference of the weighted counting."""
    occurrences, certificates = Counter(), Counter()
    for doc in documents:
        zlint_results = doc.get("zlint_results", {})
        results = [detail.get("result") for detail in zlint_results.values()]
        occurrences.update(zip(results, zlint_results, repeat(doc.get("issuer_dn"))))
        for result in dict.fromkeys(results):
            certificates[result] += 1
    return occurrences, certificates


def _weighted(documents):
    """The groups of reading.weighted_groups() for in-memory (body_id, issuer_dn, zlint_results) documents."""
    bodies = {body_id: zlint_results for body_id, _, zlint_results in documents}
    groups = Counter((body_id, issuer_dn) for body_id, issuer_dn, _ in documents)
    return [(*reading.lints(bodies[body_id]), issuer_dn, weight) for (body_id, issuer_dn), weight in groups.items()]


@pytest.mark.parametrize("seed", range(5))
def test_weighted_counting_equals_counting_each_certificate(seed):
    generator = random.Random(seed)
    lint_names = [f"lint_{index}" for index in range(12)]
    results = ["pass", "NA", "NE", "warn", "error", "info"]
    bodies = []
    for _ in range(6):
        names = generator.sample(lint_names, generator.randint(1, len(lint_names)))
        bodies.append({name: {"result": generator.choice(results)} for name in names})
    issuers = ["CN=A", "CN=B", None, "CN=C"]
    documents = [(body_id, generator.choice(issuers), bodies[body_id])
                 for body_id in (generator.randrange(len(bodies)) for _ in range(200))]

    expected = _v1_collect_statistics({"issuer_dn": issuer_dn, "zlint_results": zlint_results}
                                      for _, issuer_dn, zlint_results in documents)
    occurrences, certificates = reading.collect_statistics(_weighted(documents))

    assert list(occurrences.items()) == list(expected[0].items())
    assert list(certificates.items()) == list(expected[1].items())


def _linted_database(open_database):
    """A leaf database with results: occurrences 1-2 share an output, 3-4 have another one, 5-6 have an error."""
    database, dao = _database(open_database, count=3, repeat_rows=2)
    conn = dao.connection
    first, second, third = _units(conn)
    store = _started_store(conn)
    store.save([_ok(first, _output("e_lint_003")), _ok(second, _output("e_lint_004", "e_lint_005")), _error(third)])
    return database, dao


def _v1_csvs(documents, directory):
    occurrences, certificates = _v1_collect_statistics(documents)
    directory.mkdir()
    reading.write_field_ranking(occurrences, str(directory / "zlint_results.csv"))
    reading.write_issuer_ranking(occurrences, str(directory / "issuer_ranking_by_result.csv"))
    reading.write_certificates_summary(certificates, str(directory / "certificates_result_summary.csv"))
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def test_reader_writes_the_csvs_of_the_stored_results(open_database, tmp_path, monkeypatch, capsys):
    database, dao = _linted_database(open_database)
    reader = ZlintReader(dao.connection)
    documents = [{"issuer_dn": issuer_dn, "zlint_results": reader.body(body_id)}
                 for issuer_dn, body_id in reader.documents("issuer_dn, body_id", "body_id IS NOT NULL")]
    assert len(documents) == 4
    expected = _v1_csvs(documents, tmp_path / "expected")
    (tmp_path / "out").mkdir()
    monkeypatch.chdir(tmp_path / "out")

    assert reading.main(["leaf", "--db", database.db_path]) == 0

    assert {path.name: path.read_bytes() for path in (tmp_path / "out").iterdir()} == expected
    assert capsys.readouterr().out.splitlines() == [
        "The results by field have been written to 'zlint_results.csv'.",
        "The issuer ranking by result has been written to 'issuer_ranking_by_result.csv'.",
        "The certificate summary has been written to 'certificates_result_summary.csv'."]


def test_reader_runs_as_a_script_with_the_former_database_names(open_database, tmp_path):
    database, _ = _linted_database(open_database)
    database.close()
    result = subprocess.run([sys.executable, str(READER), "Leaf_Zlint_Checks_Google_3", "--db", database.db_path],
                            cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in tmp_path.iterdir() if path.suffix == ".csv") == [
        "certificates_result_summary.csv", "issuer_ranking_by_result.csv", "zlint_results.csv"]


def test_reader_without_results(open_database, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "missing.db"
    assert reading.main(["leaf", "--db", str(missing)]) == 1
    assert capsys.readouterr().out == (f"No ZLint results found in the leaf database '{missing}' "
                                       "(run --leaf_zlint_check first).\n")
    assert not missing.exists()

    # A database never checked with ZLint, then one whose certificates all failed
    database, dao = _database(open_database, 2, DatabaseType.INTERMEDIATE)
    assert reading.main(["intermediate", "--db", database.db_path]) == 1
    assert "No ZLint results found in the intermediate database" in capsys.readouterr().out
    _started_store(dao.connection).save([_error(raw_id) for raw_id in _units(dao.connection)])
    assert reading.main(["intermediate", "--db", database.db_path]) == 1
    assert "(run --intermediate_zlint_check first)" in capsys.readouterr().out
    assert list(tmp_path.glob("*.csv")) == []

    assert reading.main(["root", "--db", str(missing)]) == 1
    assert capsys.readouterr().out.endswith("(ZLint checks only the leaf and intermediate certificates).\n")


def test_reader_with_a_database_of_an_older_version(tmp_path, capsys):
    old = tmp_path / "leaf_certificates.db"
    conn = sqlite3.connect(old)
    conn.execute("CREATE TABLE Certificates (certificate_id INTEGER PRIMARY KEY, raw TEXT)")
    conn.commit()
    conn.close()
    before = old.read_bytes()

    assert reading.main(["--db", str(old)]) == 1

    assert capsys.readouterr().err == (f"The leaf database '{old}' was created by an older version of "
                                       "DigitalCertiAnalytics: run the analysis again with --leaf_analysis to "
                                       "recreate it.\n")
    assert old.read_bytes() == before


def test_reader_arguments(capsys):
    assert reading._database_type("Intermediate_Zlint_Checks_Google_3") == "intermediate"
    assert reading._database_type("Root_Zlint_Checks") == "root"
    assert reading._database_type("LEAF") == "leaf"
    with pytest.raises(SystemExit) as stop:
        reading.main(["unknown"])
    assert stop.value.code == 2
    assert "unknown certificate type 'unknown'" in capsys.readouterr().err
    assert reading.default_db_path("leaf") == READER.resolve().parents[1] / "leaf" / "leaf_certificates.db"


def test_reader_without_zstandard_says_to_run_the_installer(open_database, monkeypatch, capsys):
    database, _ = _linted_database(open_database)
    monkeypatch.setattr(reading, "zstandard", None)
    assert reading.main(["--db", database.db_path]) == 1
    assert capsys.readouterr().err == ("The Python package 'zstandard' is not installed. Run the installer again "
                                       "(install.sh on macOS and Linux, install.bat on Windows) to repair the "
                                       "installation.\n")
