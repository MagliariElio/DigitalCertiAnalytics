"""OCSP analysis tests against a local OCSP responder."""
import asyncio
import base64
import copy
import csv
import datetime
import json
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

import aiohttp
import aiosqlite
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp

import utils.ocsp_utils as ocsp_utils
from db.database import DatabaseType
from utils.ocsp_utils import run_ocsp_analysis

ALGORITHM_NAMES = {hashes.SHA256: "sha256", hashes.SHA1: "sha1", hashes.SHA384: "sha384", hashes.SHA512: "sha512",
                   hashes.SHA224: "sha224"}

# Each scenario takes well under a second: a dispatcher deadlock fails the test instead of hanging the suite
SCENARIO_TIMEOUT = 10


def run(coroutine, timeout=SCENARIO_TIMEOUT):
    return asyncio.run(asyncio.wait_for(coroutine, timeout))


def with_ocsp_url(pki, ocsp_url):
    """Copy of the session PKI whose rows point to ocsp_url: generating new keys took most of the test time."""
    pki = copy.copy(pki)
    pki.ocsp_url = ocsp_url
    return pki


def ocsp_response(pki, request_der, revoked_serials):
    """OCSP response signed by the intermediate; SHA256 CertIDs with odd serials get a non-OCSP body."""
    request = ocsp.load_der_ocsp_request(request_der)
    if isinstance(request.hash_algorithm, hashes.SHA256) and request.serial_number % 2 == 1:
        return web.Response(body=b"<html>not ocsp</html>")
    now = datetime.datetime.now(datetime.timezone.utc)
    dummy = (x509.CertificateBuilder().subject_name(pki.intermediate.subject).issuer_name(pki.intermediate.subject)
             .public_key(pki.intermediate_key.public_key()).serial_number(request.serial_number)
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
             .sign(pki.intermediate_key, hashes.SHA256()))
    revoked = request.serial_number in revoked_serials
    response = ocsp.OCSPResponseBuilder().add_response(
        cert=dummy, issuer=pki.intermediate, algorithm=request.hash_algorithm,
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=now, next_update=now + datetime.timedelta(days=1),
        revocation_time=now if revoked else None, revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, pki.intermediate).sign(pki.intermediate_key, hashes.SHA256())
    return web.Response(body=response.public_bytes(serialization.Encoding.DER))


async def start_responder(handler, routes=()):
    app = web.Application()
    app.router.add_get("/ocsp/{tail:.*}", handler)
    for path, route_handler in routes:
        app.router.add_get(path, route_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


@asynccontextmanager
async def responder(pki, issuer_handler=None, revoked=frozenset({5003})):
    """Local responder signing with the PKI (/ocsp and /bad, plus /issuer); yields its base URL and the request statistics."""
    state = {"pki": pki, "connections": set(), "attempts": [], "issuer_downloads": 0}

    def decode(request):
        tail = request.raw_path.split("/", 2)[2]
        state["connections"].add(request.transport.get_extra_info("peername"))
        der = base64.b64decode(unquote(tail))
        parsed = ocsp.load_der_ocsp_request(der)
        algorithm = ALGORITHM_NAMES[type(parsed.hash_algorithm)]
        state["attempts"].append((parsed.serial_number, request.path.split("/")[1], algorithm))
        return der

    async def handler(request):
        return ocsp_response(state["pki"], decode(request), revoked)

    async def bad_handler(request):
        decode(request)
        return web.Response(body=b"<html>not ocsp</html>")

    async def issuer(request):
        state["issuer_downloads"] += 1
        return await issuer_handler(request, state)

    routes = [("/bad/{tail:.*}", bad_handler)]
    if issuer_handler:
        routes.append(("/issuer", issuer))
    runner, port = await start_responder(handler, routes)
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        await runner.cleanup()


def ingest(database, dao, rows):
    # One transaction: a commit per row made the tests slow on a busy disk
    with database.transaction():
        for row in rows:
            if row["data"]["tls"]["status"] != "success":
                continue
            server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
            dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    database.finalize_analysis()


def set_urls(database, ocsp_urls, issuer_url=None, drop_issuers=False):
    """Rewrite the AIA of every certificate; drop_issuers forces the issuer download."""
    aia = {"ocsp_urls": ocsp_urls}
    if issuer_url:
        aia["issuer_urls"] = [issuer_url]
    database.conn.execute("UPDATE Certificates SET authority_info_access = ?", (json.dumps(aia),))
    if drop_issuers:
        database.conn.execute("UPDATE Issuers SET raw = NULL")
    database.conn.commit()


def statuses(database):
    return dict(database.conn.execute("SELECT leaf_domain, ocsp_check FROM Certificates").fetchall())


def expected_statuses(count, revoked=(5003,)):
    return {f"site{i}.example.test": "Revoked" if 5000 + i in revoked else "Good" for i in range(count)}


def test_ocsp_analysis_with_fallback_backup_and_resume(tmp_path, open_database, pki):
    async def handler(request):
        tail = request.raw_path.split("/ocsp/", 1)[1]
        return ocsp_response(pki, base64.b64decode(unquote(tail)), {5003})

    async def scenario():
        runner, port = await start_responder(handler)
        try:
            database, dao = open_database(DatabaseType.LEAF)
            # The OCSP URL comes from the ingested AIA
            ingest(database, dao, with_ocsp_url(pki, f"http://127.0.0.1:{port}/ocsp").rows(6))
            await run_ocsp_analysis(database, tmp_path)
            return database
        finally:
            await runner.cleanup()

    database = run(scenario())
    # Odd serials fail with SHA256 and are recovered via the SHA1 fallback; 5003 is revoked
    assert statuses(database) == expected_statuses(6)

    backup = tmp_path / "ocsp_certificates_backup.csv"
    assert not (tmp_path / "ocsp_check_results_temp.csv").exists()
    with open(backup, newline="") as backup_file:
        rows = list(csv.reader(backup_file))
    assert rows[0] == ["OCSP Check", "Certificate Id", "Leaf Domain"] and len(rows) == 7

    # A rebuilt database resumes from the backup and from a temp file whose last row is truncated
    database.conn.execute("UPDATE Certificates SET ocsp_check = 'No Request Done'")
    database.conn.commit()
    with open(tmp_path / "ocsp_check_results_temp.csv", "w", newline="") as temp_file:
        temp_file.write("Unknown,1,site0.example.test\nGood,2")
    run(run_ocsp_analysis(database, tmp_path))
    statuses_by_id = dict(database.conn.execute("SELECT certificate_id, ocsp_check FROM Certificates").fetchall())
    assert statuses_by_id[1] == "Unknown" and statuses_by_id[4] == "Revoked"
    assert backup.exists()


def read_csv(path):
    with open(path, newline="") as csv_file:
        return list(csv.reader(csv_file))


def test_cancelled_analysis_keeps_checked_rows_for_the_resume(tmp_path, open_database, monkeypatch, pki, caplog):
    """Ctrl+C cancels the analysis task: completed checks stay in the temp file and the resume checks only the others."""
    monkeypatch.setattr(ocsp_utils, "OCSP_MAX_CONCURRENT_REQUESTS", 1)    # rows checked one at a time, in id order
    requested = []

    async def scenario():
        held, release = asyncio.Event(), asyncio.Event()

        async def handler(request):
            der = base64.b64decode(unquote(request.raw_path.split("/ocsp/", 1)[1]))
            serial = ocsp.load_der_ocsp_request(der).serial_number
            requested.append(serial)
            if serial == 5003 and not release.is_set():
                held.set()
                await release.wait()
            return ocsp_response(pki, der, {5003})

        runner, port = await start_responder(handler)
        try:
            database, dao = open_database(DatabaseType.LEAF)
            ingest(database, dao, with_ocsp_url(pki, f"http://127.0.0.1:{port}/ocsp").rows(6))
            analysis = asyncio.create_task(run_ocsp_analysis(database, tmp_path))
            await held.wait()       # the first three rows are checked and written
            analysis.cancel()
            with pytest.raises(asyncio.CancelledError):
                await analysis
            interrupted = (read_csv(tmp_path / ocsp_utils.OCSP_TEMP_FILE), set(statuses(database).values()),
                           (tmp_path / ocsp_utils.OCSP_BACKUP_FILE).exists())
            release.set()
            requested.clear()
            await run_ocsp_analysis(database, tmp_path)
            return database, interrupted
        finally:
            release.set()
            await runner.cleanup()

    with caplog.at_level(logging.INFO):
        database, (temp_rows, interrupted_statuses, backup_written) = run(scenario())
    assert "OCSP check cancelled." in caplog.messages
    assert [(row[0], row[2]) for row in temp_rows] == [("Good", f"site{i}.example.test") for i in range(3)]
    assert interrupted_statuses == {"No Request Done"} and not backup_written
    # Odd serials are requested twice (SHA256, then SHA1)
    assert sorted(requested) == [5003, 5003, 5004, 5005, 5005]
    assert statuses(database) == expected_statuses(6)
    assert not (tmp_path / ocsp_utils.OCSP_TEMP_FILE).exists()
    assert len(read_csv(tmp_path / ocsp_utils.OCSP_BACKUP_FILE)) == 7


# Cancels the analysis while it opens its database connection, as a Ctrl+C at the start of the stage does
CANCELLED_WHILE_CONNECTING = """
import asyncio, sys
from db.database import Database, DatabaseType
from utils.ocsp_utils import run_ocsp_analysis

async def main():
    database = Database(sys.argv[1], "db/schema_db.sql", DatabaseType.LEAF)
    database.connect(delete_database=True)
    task = asyncio.create_task(run_ocsp_analysis(database, sys.argv[2]))
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print("cancelled")
    database.close()

asyncio.run(main())
"""


def test_analysis_cancelled_while_connecting_lets_the_interpreter_exit(tmp_path):
    """aiosqlite 0.20 leaves its worker thread waiting when the connect is cancelled: the interpreter would never exit."""
    src_dir = Path(ocsp_utils.__file__).resolve().parents[1]
    command = [sys.executable, "-c", CANCELLED_WHILE_CONNECTING, str(tmp_path / "leaf.db"), str(tmp_path)]
    result = subprocess.run(command, cwd=src_dir, capture_output=True, text=True, timeout=SCENARIO_TIMEOUT)
    assert (result.returncode, result.stdout) == (0, "cancelled\n"), result.stderr


def test_certificates_without_urls(tmp_path, open_database, pki):
    database, dao = open_database(DatabaseType.LEAF)
    ingest(database, dao, pki.rows(2))       # the session PKI has no OCSP URL
    run(run_ocsp_analysis(database, tmp_path))
    assert database.conn.execute("SELECT DISTINCT ocsp_check FROM Certificates").fetchall()[0][0] == "No OCSP Url Found"


def test_attempt_order_over_urls_and_algorithms(tmp_path, open_database, pki):
    """Unreachable URL -> next URL; invalid responses -> next algorithm, then next URL."""
    async def scenario():
        async with responder(pki) as (base_url, state):
            database, dao = open_database(DatabaseType.LEAF)
            ingest(database, dao, pki.rows(2))
            set_urls(database, ["http://127.0.0.1:1/ocsp", f"{base_url}/bad", f"{base_url}/ocsp"])
            await run_ocsp_analysis(database, tmp_path)
            return database, state

    database, state = run(scenario())
    assert statuses(database) == expected_statuses(2)
    every_algorithm = [("bad", name) for name in ("sha256", "sha1", "sha384", "sha512", "sha224")]
    for serial, tail in ((5000, [("ocsp", "sha256")]), (5001, [("ocsp", "sha256"), ("ocsp", "sha1")])):
        assert [attempt[1:] for attempt in state["attempts"] if attempt[0] == serial] == every_algorithm + tail


def test_keep_alive_and_pages_pipeline(tmp_path, open_database, monkeypatch, pki):
    """Several keyset pages, each certificate checked once, over one reused connection."""
    monkeypatch.setattr(ocsp_utils, "OCSP_BATCH_SIZE", 2)
    monkeypatch.setattr(ocsp_utils, "OCSP_MAX_CONCURRENT_REQUESTS", 1)

    async def scenario():
        async with responder(pki) as (base_url, state):
            database, dao = open_database(DatabaseType.LEAF)
            ingest(database, dao, with_ocsp_url(pki, f"{base_url}/ocsp").rows(7))
            await run_ocsp_analysis(database, tmp_path)
            return database, state

    database, state = run(scenario())
    assert statuses(database) == expected_statuses(7)
    # Even serials need one request, odd ones two (SHA256 then SHA1)
    assert sorted(attempt[0] for attempt in state["attempts"]) == sorted([5000 + i for i in range(7)] + [5001, 5003, 5005])
    assert len(state["connections"]) == 1


def test_pending_rows_prefetch_and_early_close(open_database, pki, monkeypatch):
    """Pages come in id order; closing the iterator early cancels the prefetched page and leaves the connection usable."""
    monkeypatch.setattr(ocsp_utils, "OCSP_BATCH_SIZE", 2)
    database, dao = open_database(DatabaseType.LEAF)
    ingest(database, dao, pki.rows(5))
    ids = [row[0] for row in database.conn.execute("SELECT certificate_id FROM Certificates ORDER BY 1")]

    async def scenario():
        async with aiosqlite.connect(database.db_path) as db:
            every = [row[0] async for row in ocsp_utils._pending_rows(db)]
            rows = ocsp_utils._pending_rows(db)
            first = [(await rows.__anext__())[0] for _ in range(3)]
            await rows.aclose()
            async with db.execute("SELECT COUNT(*) FROM Certificates") as cursor:
                return every, first, (await cursor.fetchone())[0]

    assert run(scenario()) == (ids, ids[:3], 5)


async def issuer_der(request, state):
    await asyncio.sleep(0.05)       # the concurrent rows overlap the download
    return web.Response(body=state["pki"].intermediate.public_bytes(serialization.Encoding.DER),
                        content_type="application/pkix-cert")


def run_with_issuer_download(tmp_path, open_database, pki, issuer_handler, count=6):
    async def scenario():
        async with responder(pki, issuer_handler) as (base_url, state):
            database, dao = open_database(DatabaseType.LEAF)
            ingest(database, dao, pki.rows(count))
            set_urls(database, [f"{base_url}/ocsp"], f"{base_url}/issuer", drop_issuers=True)
            await run_ocsp_analysis(database, tmp_path)
            return database, state, f"{base_url}/issuer"

    return run(scenario())


def test_issuer_downloaded_once_for_concurrent_rows(tmp_path, open_database, pki):
    database, state, _ = run_with_issuer_download(tmp_path, open_database, pki, issuer_der)
    assert statuses(database) == expected_statuses(6)
    assert state["issuer_downloads"] == 1


@pytest.mark.parametrize("content_type, encode", [
    ("text/plain", lambda pki: pki.intermediate.public_bytes(serialization.Encoding.PEM)),
    ("application/pkcs7-mime",
     lambda pki: pkcs7.serialize_certificates([pki.root, pki.intermediate], serialization.Encoding.DER)),
])
def test_issuer_formats_from_cached_download(tmp_path, open_database, pki, content_type, encode):
    async def issuer(request, state):
        return web.Response(body=encode(state["pki"]), content_type=content_type)

    database, state, _ = run_with_issuer_download(tmp_path, open_database, pki, issuer)
    assert statuses(database) == expected_statuses(6)
    assert state["issuer_downloads"] == 1


def test_unknown_issuer_format_logged_for_each_row(tmp_path, open_database, pki, caplog):
    async def issuer(request, state):
        return web.json_response({})

    with caplog.at_level(logging.ERROR):
        database, state, issuer_url = run_with_issuer_download(tmp_path, open_database, pki, issuer, count=4)
    assert set(statuses(database).values()) == {"Impossible Retrieve OCSP Information"}
    assert state["issuer_downloads"] == 1
    message = f"Unknown certificate format ({issuer_url}): application/json; charset=utf-8"
    assert [record.getMessage() for record in caplog.records].count(message) == 4


def test_failed_issuer_download_is_retried(tmp_path, open_database, pki, monkeypatch, caplog):
    """A failed download is not cached: the next row downloads again, then the success is reused."""
    monkeypatch.setattr(ocsp_utils, "OCSP_MAX_CONCURRENT_REQUESTS", 1)

    async def issuer(request, state):
        if state["issuer_downloads"] == 1:
            return web.Response(status=503)
        return await issuer_der(request, state)

    with caplog.at_level(logging.ERROR):
        database, state, issuer_url = run_with_issuer_download(tmp_path, open_database, pki, issuer)
    expected = expected_statuses(6)
    expected["site0.example.test"] = "Impossible Retrieve OCSP Information"
    assert statuses(database) == expected
    assert state["issuer_downloads"] == 2
    message = f"Error retrieving the certificate ({issuer_url}): HTTP status 503"
    assert [record.getMessage() for record in caplog.records].count(message) == 1


def test_shared_failed_download_logged_for_each_row(tmp_path, open_database, pki, caplog):
    async def issuer(request, state):
        await asyncio.sleep(0.05)
        return web.Response(status=404)

    with caplog.at_level(logging.ERROR):
        database, state, issuer_url = run_with_issuer_download(tmp_path, open_database, pki, issuer, count=4)
    assert set(statuses(database).values()) == {"Impossible Retrieve OCSP Information"}
    assert state["issuer_downloads"] == 1
    message = f"Error retrieving the certificate ({issuer_url}): HTTP status 404"
    assert [record.getMessage() for record in caplog.records].count(message) == 4


def test_cancelled_row_does_not_cancel_shared_download(pki):
    async def scenario():
        async with responder(pki, issuer_der) as (base_url, state):
            async with aiohttp.ClientSession() as session:
                downloads = ocsp_utils._IssuerDownloads(session)
                first = asyncio.create_task(downloads.get(f"{base_url}/issuer", "Test Intermediate CA"))
                second = asyncio.create_task(downloads.get(f"{base_url}/issuer", "Test Intermediate CA"))
                await asyncio.sleep(0.01)
                first.cancel()
                issuer = await second
                assert first.cancelled() and issuer == pki.intermediate

                # Shutdown cancels the downloads still running
                pending = asyncio.create_task(downloads.get(f"{base_url}/issuer?other", "Test Intermediate CA"))
                while state["issuer_downloads"] < 2:
                    await asyncio.sleep(0.005)
                await downloads.aclose()
                with pytest.raises(asyncio.CancelledError):
                    await pending
            return state["issuer_downloads"]

    assert run(scenario()) == 2


@pytest.mark.parametrize("max_idle, idle_after_bursts", [(2, [2, 2, 2]), (100, [8, 8, 16])])
def test_idle_connections_are_bounded(max_idle, idle_after_bursts):
    """The bound covers every host pool; a reused connection goes back to the pool; pools are walked only at the bound."""
    peers = set()

    async def slow(request):
        peers.add(request.transport.get_extra_info("peername"))
        await asyncio.sleep(0.02)       # the requests of a burst overlap: one connection each
        return web.Response(text="ok")

    async def scenario():
        runner, port = await start_responder(slow)
        second_site = web.TCPSite(runner, "127.0.0.1", 0)
        await second_site.start()
        second_port = second_site._server.sockets[0].getsockname()[1]
        try:
            async with ocsp_utils._create_session(concurrency=8, max_idle=max_idle) as session:
                connector = session.connector
                walks = []
                count_idle = connector.idle_connections
                connector.idle_connections = lambda: walks.append(1) or count_idle()

                async def get(port, count=1):
                    async def one():
                        async with session.get(f"http://127.0.0.1:{port}/ocsp/x") as response:
                            return await response.text()
                    assert await asyncio.gather(*(one() for _ in range(count))) == ["ok"] * count

                await get(port, 8)
                idle = [count_idle()]
                for _ in range(3):
                    await get(port)
                idle.append(count_idle())
                connections_after_reuse = len(peers)
                await get(second_port, 8)
                idle.append(count_idle())
                return idle, connections_after_reuse, len(walks)
        finally:
            await runner.cleanup()

    idle, connections_after_reuse, walks = run(scenario())
    assert idle == idle_after_bursts
    assert connections_after_reuse == 8     # the three sequential requests reused pooled connections
    # Below the bound the pools are never walked; at the bound, once per release
    assert walks == (0 if max_idle == 100 else 6 + 3 + 8)


def test_connection_limits_from_open_files():
    assert ocsp_utils._connection_limits(None) == (200, 1000)
    assert ocsp_utils._connection_limits(4096) == (200, 1000)
    assert ocsp_utils._connection_limits(1024) == (200, 760)
    assert ocsp_utils._connection_limits(256) == (96, 96)
    assert ocsp_utils._connection_limits(10) == (1, 1)


class FakeResource:
    RLIMIT_NOFILE = 7
    RLIM_INFINITY = -1

    def __init__(self, soft, hard, fail=False):
        self.limits, self.fail, self.calls = (soft, hard), fail, []

    def getrlimit(self, resource):
        return self.limits

    def setrlimit(self, resource, limits):
        self.calls.append(limits)
        if self.fail:
            raise ValueError("not allowed")
        self.limits = limits


@pytest.mark.parametrize("soft, hard, fail, expected, calls", [
    (256, -1, False, 4096, [(4096, -1), (256, -1)]),        # raised, then restored
    (256, 1024, False, 1024, [(1024, 1024), (256, 1024)]),   # capped by the hard limit
    (256, -1, True, 256, [(4096, -1)]),                      # not allowed: current limit
    (65536, -1, False, 65536, []),                           # already enough
    (-1, -1, False, None, []),                               # unlimited
])
def test_open_files_limit(monkeypatch, soft, hard, fail, expected, calls):
    fake = FakeResource(soft, hard, fail)
    monkeypatch.setattr(ocsp_utils, "resource", fake)
    with ocsp_utils._open_files_limit() as limit:
        assert limit == expected
    assert fake.calls == calls


def test_open_files_limit_without_resource_module(monkeypatch):
    monkeypatch.setattr(ocsp_utils, "resource", None)
    with ocsp_utils._open_files_limit() as limit:
        assert limit is None


def test_first_failure_stops_the_checks():
    """An error writing a result is raised at once and cancels the checks in flight."""
    started, cancelled = [], []

    class Checker:
        async def check(self, row):
            started.append(row[0])
            try:
                await asyncio.sleep(0 if row[0] == 3 else 30)
            except asyncio.CancelledError:
                cancelled.append(row[0])
                raise
            return "Good", row[0], row[-1]

    class Writer:
        def writerow(self, row):
            if row[1] == 3:
                raise OSError("disk full")

    closed = []

    async def rows():
        try:
            for certificate_id in range(1, 100):
                yield certificate_id, f"d{certificate_id}"
        finally:
            closed.append(True)

    async def scenario():
        pbar = SimpleNamespace(update=lambda n: None)
        with pytest.raises(OSError, match="disk full"):
            await ocsp_utils._run_checks(rows(), Checker(), 5, Writer(), pbar)
        # Checked before asyncio.run closes the async generators left open
        assert closed == [True]

    run(scenario())
    assert started == [1, 2, 3, 4, 5] and sorted(cancelled) == [1, 2, 4, 5]


def test_failure_after_the_last_row_is_raised():
    """A check failing after the last row was dispatched, before the iterator ends, is raised by the final wait."""
    events = []

    class Checker:
        async def check(self, row):
            await asyncio.sleep(0)
            return "Good", row[0], row[-1]

    class Writer:
        def writerow(self, row):
            events.append(row[1])
            if row[1] == 3:
                raise OSError("disk full")

    async def rows():
        for certificate_id in range(1, 4):
            yield certificate_id, f"d{certificate_id}"
        # Ends once the failed check is over: no further row start sees the failure
        await asyncio.sleep(0.05)
        events.append("end")

    async def scenario():
        pbar = SimpleNamespace(update=lambda n: None)
        with pytest.raises(OSError, match="disk full"):
            await ocsp_utils._run_checks(rows(), Checker(), 5, Writer(), pbar)

    run(scenario())
    assert events == [1, 2, 3, "end"]


def test_checks_are_bounded_and_every_result_is_written():
    """At most `concurrency` checks in flight, completing out of order; each result written and counted once."""
    stats = {"in_flight": 0, "peak": 0}
    written, progress = [], []

    class Checker:
        async def check(self, row):
            stats["in_flight"] += 1
            stats["peak"] = max(stats["peak"], stats["in_flight"])
            await asyncio.sleep(0.001 * (row[0] % 3))
            stats["in_flight"] -= 1
            return "Good", row[0], row[-1]

    async def rows():
        for certificate_id in range(1, 51):
            yield certificate_id, f"d{certificate_id}"

    async def scenario():
        writer, pbar = SimpleNamespace(writerow=written.append), SimpleNamespace(update=progress.append)
        await ocsp_utils._run_checks(rows(), Checker(), 4, writer, pbar)

    run(scenario())
    assert sorted(written) == [("Good", i, f"d{i}") for i in range(1, 51)] and written != sorted(written)
    assert progress == [1] * 50 and stats == {"in_flight": 0, "peak": 4}
