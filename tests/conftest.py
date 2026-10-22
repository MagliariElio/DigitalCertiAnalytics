from pathlib import Path

import pytest
from helpers import Pki

from dao.certificate_dao import CertificateDAO
from db.database import Database, DatabaseType

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
SCHEMA_PATH = SRC_DIR / "db" / "schema_db.sql"


@pytest.fixture(scope="session")
def pki():
    return Pki()


@pytest.fixture
def open_database(tmp_path):
    """Factory returning an empty database of the given type and its DAO; all are closed on teardown."""
    databases = []

    def _open(db_type=DatabaseType.LEAF, name=None):
        database = Database(tmp_path / (name or f"{db_type.value}.db"), SCHEMA_PATH, db_type)
        database.connect(delete_database=True)
        databases.append(database)
        return database, CertificateDAO(database.conn, db_type)

    yield _open
    for database in databases:
        database.close()
