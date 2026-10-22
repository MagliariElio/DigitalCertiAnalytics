"""End-to-end OCSP analysis tests against a local OCSP responder."""
import asyncio
import base64
import csv
import datetime
from urllib.parse import unquote

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from helpers import Pki

from db.database import DatabaseType
from utils.ocsp_utils import run_ocsp_analysis


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


async def start_responder(handler):
    app = web.Application()
    app.router.add_get("/ocsp/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


def ingest(database, dao, rows):
    for row in rows:
        if row["data"]["tls"]["status"] != "success":
            continue
        server = row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]
        with database.transaction():
            dao.process_insert_certificate(row, server["certificate"], server["chain"], 0)
    database.finalize_analysis()


def test_ocsp_analysis_with_fallback_backup_and_resume(tmp_path, open_database):
    state = {}

    async def handler(request):
        tail = request.raw_path.split("/ocsp/", 1)[1]
        return ocsp_response(state["pki"], base64.b64decode(unquote(tail)), {5003})

    async def scenario():
        runner, port = await start_responder(handler)
        try:
            pki = state["pki"] = Pki(ocsp_url=f"http://127.0.0.1:{port}/ocsp")
            database, dao = open_database(DatabaseType.LEAF)
            ingest(database, dao, pki.rows(6))
            await run_ocsp_analysis(database, tmp_path)
            return database
        finally:
            await runner.cleanup()

    database = asyncio.run(scenario())
    statuses = dict(database.conn.execute("SELECT leaf_domain, ocsp_check FROM Certificates").fetchall())
    # Odd serials fail with SHA256 and are recovered via the SHA1 fallback; 5003 is revoked
    assert statuses["site3.example.test"] == "Revoked"
    assert {status for domain, status in statuses.items() if domain != "site3.example.test"} == {"Good"}

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
    asyncio.run(run_ocsp_analysis(database, tmp_path))
    statuses = dict(database.conn.execute("SELECT certificate_id, ocsp_check FROM Certificates").fetchall())
    assert statuses[1] == "Unknown" and statuses[4] == "Revoked"
    assert backup.exists()


def test_certificates_without_urls(tmp_path, open_database, pki):
    database, dao = open_database(DatabaseType.LEAF)
    ingest(database, dao, pki.rows(2))       # the session PKI has no OCSP URL
    asyncio.run(run_ocsp_analysis(database, tmp_path))
    assert database.conn.execute("SELECT DISTINCT ocsp_check FROM Certificates").fetchall()[0][0] == "No OCSP Url Found"
