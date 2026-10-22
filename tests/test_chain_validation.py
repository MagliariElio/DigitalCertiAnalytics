"""Chain validation with a fake sslyze executable on PATH."""
import stat
import sys

from helpers import Pki

from db.database import DatabaseType
from utils.chain_utils import validate_leaf_certificate_chains

# Accepts one or more hosts like sslyze: site1 has an invalid chain, unknown hosts cannot be resolved
FAKE_SSLYZE = f"""#!{sys.executable}
import json, sys
invalid, results = [], []
for host in [argument for argument in sys.argv[1:] if not argument.startswith("-")]:
    if host.startswith("unknown"):
        invalid.append({{"server_string": host + ":443", "error_message": "Could not resolve hostname"}})
        continue
    validation = {{"was_validation_successful": not host.startswith("site1.")}}
    deployment = {{"path_validation_results": [validation]}}
    results.append({{"server_location": {{"hostname": host, "port": 443}}, "scan_status": "COMPLETED",
                    "scan_result": {{"certificate_info": {{"result": {{"certificate_deployments": [deployment]}}}}}}}})
print(json.dumps({{"invalid_server_strings": invalid, "server_scan_results": results}}))
"""


def test_chain_validation(tmp_path, monkeypatch, open_database):
    executable = tmp_path / "sslyze"
    executable.write_text(FAKE_SSLYZE)
    executable.chmod(executable.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    database, dao = open_database(DatabaseType.LEAF)
    rows = [row for row in Pki().rows(6) if row["data"]["tls"]["status"] == "success"]
    rows[5]["domain"] = "unknown.example.test"
    for row in rows:
        server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
        with database.transaction():
            dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)

    validate_leaf_certificate_chains(dao, database)

    validity = dict(database.conn.execute("SELECT leaf_domain, signature_valid FROM Certificates").fetchall())
    assert validity == {"site0.example.test": "Valid", "site1.example.test": "Not Valid", "site2.example.test": "Valid",
                        "site3.example.test": "Valid", "site4.example.test": "Valid", "unknown.example.test": "Error"}


def test_missing_sslyze_keeps_existing_values(tmp_path, monkeypatch, open_database):
    monkeypatch.setenv("PATH", str(tmp_path))
    database, dao = open_database(DatabaseType.LEAF)
    row = Pki().rows(1)[0]
    server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
    with database.transaction():
        dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    validate_leaf_certificate_chains(dao, database)
    assert database.conn.execute("SELECT signature_valid FROM Certificates").fetchone()[0] == "Valid"
