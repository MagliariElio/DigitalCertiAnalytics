"""Chain validation with a fake sslyze executable on PATH."""
import json
import signal
import stat
import subprocess
import sys
import threading
import time

import pytest
from helpers import Pki

from db.database import DatabaseType
from utils import chain_utils
from utils.chain_utils import validate_leaf_certificate_chains

# Accepts one or more hosts like sslyze 6 and logs the hosts of each invocation. site1 has an invalid chain, unknown
# hosts cannot be resolved, down hosts have no connectivity. A batch (several hosts) fails with 'flaky', hangs with
# 'slow', crashes with 'killed', is interrupted (Ctrl+C) with 'interrupted' and has no server_location with 'legacy'.
FAKE_SSLYZE = """#!{python}
import json, os, signal, sys, time
hosts = sys.argv[4:]
with open({log!r}, "a") as log:
    log.write(json.dumps(hosts) + "\\n")
batch = len(hosts) > 1
if batch and any("flaky" in host for host in hosts):
    sys.stderr.write("boom")
    sys.exit(1)
if any("slow" in host for host in hosts) and batch or any("hang" in host for host in hosts):
    time.sleep(30)
if batch and any("killed" in host for host in hosts):
    os.kill(os.getpid(), signal.SIGKILL)
if batch and any("interrupted" in host for host in hosts):
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGINT)
invalid, results = [], []
for host in hosts:
    if host.startswith("unknown"):
        invalid.append({{"server_string": host + ":443", "error_message": "Could not resolve hostname"}})
        continue
    location = {{"hostname": host, "port": 443}}
    if host.startswith("down"):
        results.append({{"server_location": location, "scan_status": "ERROR_NO_CONNECTIVITY", "scan_result": None}})
        continue
    validation = {{"was_validation_successful": not host.lower().startswith("site1.")}}
    deployment = {{"path_validation_results": [validation]}}
    result = {{"server_location": location, "scan_status": "COMPLETED",
              "scan_result": {{"certificate_info": {{"result": {{"certificate_deployments": [deployment]}}}}}}}}
    if any("legacy" in host for host in hosts):
        del result["server_location"]
    results.append(result)
print(json.dumps({{"invalid_server_strings": invalid, "server_scan_results": results}}))
"""


class FakeSslyze:
    def __init__(self, directory):
        self.log = directory / "sslyze.log"
        path = directory / "sslyze"
        path.write_text(FAKE_SSLYZE.format(python=sys.executable, log=str(self.log)))
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def invocations(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


@pytest.fixture
def sslyze(tmp_path, monkeypatch):
    fake = FakeSslyze(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    return fake


def _database_with(open_database, domains):
    database, dao = open_database(DatabaseType.LEAF)
    rows = [row for row in Pki().rows(len(domains)) if row["data"]["tls"]["status"] == "success"]
    for row, domain in zip(rows, domains):
        row["domain"] = domain
        server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
        with database.transaction():
            dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    return database, dao


def _validity(database):
    rows = database.conn.execute("SELECT leaf_domain, signature_valid FROM Certificates ORDER BY certificate_id")
    return [tuple(row) for row in rows]


def test_chain_validation(sslyze, open_database):
    domains = [f"site{i}.example.test" for i in range(5)] + ["unknown.example.test", "down.example.test"]
    database, dao = _database_with(open_database, domains)

    validate_leaf_certificate_chains(dao, database)

    assert _validity(database) == [
        ("site0.example.test", "Valid"), ("site1.example.test", "Not Valid"), ("site2.example.test", "Valid"),
        ("site3.example.test", "Valid"), ("site4.example.test", "Valid"), ("unknown.example.test", "Error"),
        ("down.example.test", "Error")]
    assert sslyze.invocations() == [domains]


def test_batches_and_duplicate_hosts_in_any_case(sslyze, open_database, monkeypatch):
    monkeypatch.setattr(chain_utils, "SSLYZE_BATCH_SIZE", 3)
    domains = ["site0.example.test", "Site1.Example.Test", "site1.example.test", "site2.example.test",
               "site3.example.test", "-option.example.test", "host.example.test:8443"]
    database, dao = _database_with(open_database, domains)

    validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == [
        "Valid", "Not Valid", "Not Valid", "Valid", "Valid", "Valid", "Valid"]
    # Each host once per batch; names sslyze would not report unchanged are checked alone as before
    assert sorted(sslyze.invocations()) == sorted([
        ["site0.example.test", "Site1.Example.Test"], ["site2.example.test", "site3.example.test"],
        ["-option.example.test"], ["host.example.test:8443"]])


def test_failed_batch_falls_back_to_single_hosts(sslyze, open_database, caplog):
    domains = ["site0.example.test", "flaky.example.test", "site1.example.test", "down.example.test"]
    database, dao = _database_with(open_database, domains)

    validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == ["Valid", "Valid", "Not Valid", "Error"]
    assert sslyze.invocations()[0] == domains
    assert sorted(sslyze.invocations()[1:]) == sorted([domain] for domain in domains)
    assert "sslyze scan of 4 hosts failed (exit code 1)" in caplog.text
    # The no-connectivity host is logged as when it was scanned alone
    assert "for hostname down.example.test: 'NoneType' object has no attribute 'get'" in caplog.text


def test_batch_timeout_falls_back_to_single_hosts(sslyze, open_database, monkeypatch, caplog):
    # The batch timeout is capped, whatever the per-host one
    monkeypatch.setattr(chain_utils, "SSLYZE_BATCH_TIMEOUT", 0.5)
    monkeypatch.setattr(chain_utils, "SSLYZE_TIMEOUT", 60)
    database, dao = _database_with(open_database, ["slow.example.test", "site1.example.test"])

    started = time.monotonic()
    validate_leaf_certificate_chains(dao, database)

    assert time.monotonic() - started < 10
    assert [validity for _, validity in _validity(database)] == ["Valid", "Not Valid"]
    assert "sslyze scan of 2 hosts failed (timeout): checking them one at a time." in caplog.text


@pytest.mark.parametrize("hosts, timeout", [(2, 300), (10, 300), (11, 600), (20, 600), (21, 900), (100, 900)])
def test_batch_timeout_per_group_of_concurrent_hosts(hosts, timeout):
    # sslyze scans 10 hosts at a time, each bounded by the per-host timeout
    assert chain_utils._batch_timeout(hosts) == timeout


def test_batch_timeout_counts_each_host_once(sslyze, monkeypatch):
    timeouts = []
    run = chain_utils._SslyzeProcesses.run

    def record_timeout(self, command, timeout):
        timeouts.append(timeout)
        return run(self, command, timeout)

    monkeypatch.setattr(chain_utils._SslyzeProcesses, "run", record_timeout)
    hosts = [f"site{i}.example.test" for i in range(10)]
    items = list(enumerate(hosts + [host.upper() for host in hosts]))
    processes = chain_utils._SslyzeProcesses()

    assert len(chain_utils._scan_batch(items, processes)[0]) == 20
    assert len(chain_utils._scan_batch(items + [(20, "site10.example.test")], processes)[0]) == 21
    assert timeouts == [300, 600]
    assert [len(invocation) for invocation in sslyze.invocations()] == [10, 11]


def test_hosts_missing_from_the_output_are_checked_alone(sslyze, open_database):
    domains = ["legacy.example.test", "site1.example.test", "site2.example.test"]
    database, dao = _database_with(open_database, domains)

    validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == ["Valid", "Not Valid", "Valid"]
    assert len(sslyze.invocations()) == 4


def test_crashed_batch_falls_back_to_single_hosts(sslyze, open_database, caplog):
    database, dao = _database_with(open_database, ["killed.example.test", "site1.example.test"])

    validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == ["Valid", "Not Valid"]
    assert len(sslyze.invocations()) == 3
    assert f"(exit code {-signal.SIGKILL})" in caplog.text


def test_interrupted_batch_stores_nothing(sslyze, open_database):
    database, dao = _database_with(open_database, ["interrupted.example.test", "site1.example.test"])
    database.conn.execute("UPDATE Certificates SET signature_valid = 'Unsupported Key Type'")
    database.conn.commit()

    validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == ["Unsupported Key Type", "Unsupported Key Type"]
    assert len(sslyze.invocations()) == 1


def test_interrupt_saves_results_and_kills_running_scans(sslyze, open_database, monkeypatch):
    monkeypatch.setattr(chain_utils, "SSLYZE_BATCH_SIZE", 2)
    monkeypatch.setattr(chain_utils, "CHAIN_VALIDATION_WORKERS", 2)
    domains = ["site0.example.test", "site1.example.test", "hang0.example.test", "hang1.example.test"]
    database, dao = _database_with(open_database, domains)
    database.conn.execute("UPDATE Certificates SET signature_valid = 'Unsupported Key Type'")
    database.conn.commit()

    real_wait = chain_utils.wait
    calls = []

    def wait_then_interrupt(futures, return_when):
        calls.append(1)
        if len(calls) > 1:
            raise KeyboardInterrupt
        # Return as soon as the first batch is done, while the other one hangs
        while not any(future.done() for future in futures):
            time.sleep(0.01)
        return real_wait(futures, return_when=return_when)

    monkeypatch.setattr(chain_utils, "wait", wait_then_interrupt)
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        validate_leaf_certificate_chains(dao, database)

    assert [validity for _, validity in _validity(database)] == [
        "Valid", "Not Valid", "Unsupported Key Type", "Unsupported Key Type"]
    # The hanging scan is killed instead of being waited for
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and thread.name.startswith("ThreadPoolExecutor"):
            thread.join(timeout=10)
    assert time.monotonic() - started < 10


def test_stopped_processes_are_killed():
    processes = chain_utils._SslyzeProcesses()
    errors = []

    def run():
        try:
            processes.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=60)
        except subprocess.CalledProcessError as e:
            errors.append(e.returncode)

    thread = threading.Thread(target=run)
    thread.start()
    time.sleep(0.5)
    processes.stop()
    thread.join(timeout=10)
    assert errors and errors[0] < 0
    with pytest.raises(subprocess.CalledProcessError):
        processes.run([sys.executable, "-c", "pass"], timeout=60)


def test_missing_sslyze_keeps_existing_values(tmp_path, monkeypatch, open_database):
    monkeypatch.setenv("PATH", str(tmp_path))
    database, dao = open_database(DatabaseType.LEAF)
    row = Pki().rows(1)[0]
    server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
    with database.transaction():
        dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    validate_leaf_certificate_chains(dao, database)
    assert database.conn.execute("SELECT signature_valid FROM Certificates").fetchone()[0] == "Valid"
