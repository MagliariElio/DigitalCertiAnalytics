"""ZLint analysis tests with a fake zlint executable and a fake MongoDB."""
import stat

import pytest
from helpers import Pki

from db.database import DatabaseType
from utils import zlint_utils

FAKE_ZLINT = """#!/bin/sh
input=$(cat)
case "$input" in
  *"BEGIN CERTIFICATE"*)
    echo '{"e_lint_a": {"result": "pass"}, "w_lint_b": {"result": "warn"}, "n_lint_c": {"result": "pass"}}';;
  *) echo "bad input" >&2; exit 1;;
esac
"""


class FakeCollection:
    def __init__(self):
        self.documents = []

    def insert_one(self, document):
        self.documents.append(document)

    def insert_many(self, documents):
        self.documents.extend(documents)


class FakeMongo:
    instances = []

    def __init__(self, db_type):
        self.db_type = db_type
        self.collections = {}
        self.closed = False
        FakeMongo.instances.append(self)

    def connect(self):
        pass

    def get_collection(self, name):
        return self.collections.setdefault(name, FakeCollection())

    def close(self):
        self.closed = True


@pytest.fixture
def fake_environment(tmp_path, monkeypatch):
    executable = tmp_path / "zlint"
    executable.write_text(FAKE_ZLINT)
    executable.chmod(executable.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(zlint_utils, "ZLINT_PATH", executable)
    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", FakeMongo)
    FakeMongo.instances.clear()
    return executable


def test_results_are_stored(fake_environment, open_database):
    database, dao = open_database(DatabaseType.LEAF)
    for row in Pki().rows(5):
        if row["data"]["tls"]["status"] == "success":
            server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            with database.transaction():
                dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    database.conn.execute("UPDATE Certificates SET raw = NULL WHERE certificate_id = 1")
    database.conn.commit()

    zlint_utils.run_zlint_check(dao)

    mongo = FakeMongo.instances[-1]
    results = mongo.collections["zlint_results"].documents
    errors = mongo.collections["zlint_errors"].documents
    assert sorted(document["certificate_id"] for document in results) == [2, 3, 4, 5]
    assert results[0]["count_results"] == {"pass": 2, "warn": 1}
    assert results[0]["issuer_common_name"] == "Test Intermediate CA"
    assert [document["certificate_id"] for document in errors] == [1]
    assert mongo.closed


def test_missing_executable(tmp_path, monkeypatch, open_database):
    monkeypatch.setattr(zlint_utils, "ZLINT_PATH", tmp_path / "missing")
    monkeypatch.setattr(zlint_utils, "MongoDbDatabase", FakeMongo)
    FakeMongo.instances.clear()
    _, dao = open_database(DatabaseType.LEAF)
    zlint_utils.run_zlint_check(dao)
    assert FakeMongo.instances == []
