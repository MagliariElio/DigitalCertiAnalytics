from __future__ import annotations

import asyncio
import base64
import csv
import json
import logging
import os
from contextlib import asynccontextmanager
from itertools import islice
from typing import Iterable, Iterator
from urllib.parse import quote, urljoin

import aiohttp
import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from bean.certificate import Certificate
from db.database import CERTIFICATE_ID_INDEX_SQL, Database, DatabaseType
from utils.utils import progress_bar

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Without this cap, tens of thousands of connections would open at once, exhausting file descriptors
# and producing false "Impossible Retrieve OCSP Information" results
OCSP_MAX_CONCURRENT_REQUESTS = 200

HTTP_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=20)

# Rows per DB page, per CSV executemany and per backup fetchmany
OCSP_BATCH_SIZE = 50000
CSV_IMPORT_BATCH_SIZE = 50000
BACKUP_FETCH_SIZE = 10000

OCSP_TEMP_FILE = "ocsp_check_results_temp.csv"
OCSP_BACKUP_FILE = "ocsp_certificates_backup.csv"
OCSP_BACKUP_HEADER = ("OCSP Check", "Certificate Id", "Leaf Domain")

IMPOSSIBLE_RETRIEVE = "Impossible Retrieve OCSP Information"

# Hash algorithms tried, in order, to build the request CertID
HASH_ALGORITHMS = (SHA256(), SHA1(), SHA384(), SHA512(), SHA224())

CERT_STATUS = {
    ocsp.OCSPCertStatus.GOOD: "Good",
    ocsp.OCSPCertStatus.REVOKED: "Revoked",
    ocsp.OCSPCertStatus.UNKNOWN: "Unknown",
}

ISSUER_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/86.0.4240.183 Safari/537.36"
}
DER_CONTENT_TYPES = ("application/x-x509-ca-cert", "application/octet-stream", "binary/octet-stream", "application/pkix-cert")
PEM_CONTENT_TYPES = ("application/x-pem-file", "text/plain")
PKCS7_CONTENT_TYPES = ("application/pkcs7-mime", "application/x-pkcs7-certificates")
PEM_HEADER = b"-----BEGIN CERTIFICATE-----"

MARK_NO_OCSP_URL = """
    UPDATE Certificates
    SET ocsp_check = 'No OCSP Url Found'
    WHERE ocsp_check = 'No Request Done' AND
        (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')
"""

# Non-root certificates only: a root is its own issuer
MARK_NO_ISSUER_URL = """
    UPDATE Certificates
    SET ocsp_check = 'No Issuer Url Found'
    WHERE ocsp_check = 'No Request Done'
    AND NOT authority_info_access LIKE '{}'
    AND NOT authority_info_access LIKE '%issuer_urls%'
    AND issuer_id IN (SELECT issuer_id FROM Issuers WHERE raw IS NULL)
"""

COUNT_PENDING = """
    SELECT COUNT(c.certificate_id)
    FROM Certificates AS c
    INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
    WHERE c.ocsp_check = 'No Request Done'
"""

# Keyset pagination: results go to the temp file, so rows stay 'No Request Done' until the import
SELECT_PENDING = """
    SELECT c.certificate_id, c.authority_info_access, i.common_name, i.raw, c.raw, c.leaf_domain
    FROM Certificates AS c
    INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
    WHERE c.ocsp_check = 'No Request Done' AND c.certificate_id > ?
    ORDER BY c.certificate_id
    LIMIT ?
"""

SELECT_CHECKED = """
    SELECT ocsp_check, certificate_id, leaf_domain
    FROM Certificates
    WHERE ocsp_check <> 'No Request Done'
"""

CREATE_TEMP_TABLE = ("CREATE TEMPORARY TABLE IF NOT EXISTS TempOCSP "
                     "(certificate_id INT, ocsp_check VARCHAR(36), leaf_domain VARCHAR)")
CREATE_TEMP_INDEX = "CREATE INDEX IF NOT EXISTS idx_temp_ocsp ON TempOCSP(certificate_id, leaf_domain)"
INSERT_TEMP = "INSERT INTO TempOCSP (certificate_id, ocsp_check, leaf_domain) VALUES (?, ?, ?)"

UPDATE_FROM_TEMP = """
    UPDATE Certificates
    SET ocsp_check = (
        SELECT ocsp_check FROM TempOCSP
        WHERE Certificates.certificate_id = TempOCSP.certificate_id AND Certificates.leaf_domain = TempOCSP.leaf_domain
    )
    WHERE EXISTS (
        SELECT 1 FROM TempOCSP
        WHERE Certificates.certificate_id = TempOCSP.certificate_id AND Certificates.leaf_domain = TempOCSP.leaf_domain
    )
"""


# ---------------------------------------------------------------- OCSP requests

def _load_der_or_pem(content: bytes) -> x509.Certificate:
    if content.startswith(PEM_HEADER):
        return x509.load_pem_x509_certificate(content)
    return x509.load_der_x509_certificate(content)


def _select_from_pkcs7(content: bytes, issuer_common_name: str, issuer_url: str) -> x509.Certificate | None:
    """Pick the last certificate in the PKCS #7 bundle whose Common Name matches the issuer's."""
    issuer_cert = None
    for cert in pkcs7.load_der_pkcs7_certificates(content):
        # Some bundle certificates have no Common Name
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names and common_names[0].value == issuer_common_name:
            issuer_cert = cert

    if issuer_cert is None:
        logging.error(f"Errore certificato non trovato durante il parsing del PKCS #7 ({issuer_url})")
    return issuer_cert


async def _parse_issuer_response(response: aiohttp.ClientResponse, issuer_url: str,
                                 issuer_common_name: str) -> x509.Certificate | None:
    """Parse the issuer certificate according to its Content-Type (DER/PEM/PKCS #7)."""
    content_type = response.headers.get("Content-Type", "")
    if content_type == "" or any(t in content_type for t in DER_CONTENT_TYPES):
        return _load_der_or_pem(await response.read())
    if any(t in content_type for t in PEM_CONTENT_TYPES):
        return x509.load_pem_x509_certificate((await response.text()).encode("utf-8"))
    if any(t in content_type for t in PKCS7_CONTENT_TYPES):
        return _select_from_pkcs7(await response.read(), issuer_common_name, issuer_url)

    logging.error(f"Formato del certificato sconosciuto ({issuer_url}): {content_type}")
    return None


async def _download_issuer_certificate(issuer_url: str, issuer_common_name: str,
                                       session: aiohttp.ClientSession) -> x509.Certificate | None:
    """Download the issuer certificate from the AIA URL, None on error."""
    try:
        async with session.get(issuer_url, headers=ISSUER_REQUEST_HEADERS) as response:
            if response.status != 200:
                logging.error(f"Errore nel recupero del certificato ({issuer_url}). Stato: {response.status}")
                return None
            return await _parse_issuer_response(response, issuer_url, issuer_common_name)
    except asyncio.TimeoutError:
        return None
    except aiohttp.ClientError as e:
        logging.error(f"Errore HTTP nel recupero del certificato ({issuer_url}): {e}")
    except Exception as e:
        logging.error(f"Errore nel recupero o nel parsing del certificato ({issuer_url}): {e}")
    return None


def _ocsp_response_status(content: bytes) -> str:
    """Map a DER OCSP response to the certificate status."""
    response = ocsp.load_der_ocsp_response(content)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return IMPOSSIBLE_RETRIEVE
    return CERT_STATUS.get(response.certificate_status, IMPOSSIBLE_RETRIEVE)


async def _ocsp_query(certificate: x509.Certificate, issuer: x509.Certificate, algorithm, ocsp_url: str,
                      session: aiohttp.ClientSession) -> str | None:
    """Send an OCSP GET request and return the status, None on network error or timeout."""
    url = ocsp_url
    try:
        request = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, algorithm).build()
        # The base64 request must also be URL-encoded ('+', '/', '='), see RFC 6960 Appendix A.1
        encoded = base64.b64encode(request.public_bytes(serialization.Encoding.DER)).decode("ascii")
        url = urljoin(ocsp_url + "/", quote(encoded, safe=""))

        async with session.get(url) as response:
            if response.status != 200:
                return "Not Ok OCSP Response"
            content = await response.read()
        return _ocsp_response_status(content)
    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
        logging.debug(f"Errore di rete durante la richiesta OCSP per {url}: {e}")
        return None
    except ValueError as e:
        # Invalid OCSP response: retry with another hash algorithm or URL
        logging.debug(f"Risposta OCSP non valida per {url}: {e}")
    except Exception as e:
        logging.error(f"Errore durante la richiesta OCSP per {url}: {e}")
    return IMPOSSIBLE_RETRIEVE


async def _query_ocsp_urls(certificate: x509.Certificate, issuer: x509.Certificate, ocsp_urls: list[str],
                           session: aiohttp.ClientSession) -> str:
    """Try each OCSP URL with each hash algorithm until a conclusive status."""
    for ocsp_url in ocsp_urls:
        for algorithm in HASH_ALGORITHMS:
            status = await _ocsp_query(certificate, issuer, algorithm, ocsp_url, session)
            if status is None:
                break   # Server unreachable: try the next URL
            if status != IMPOSSIBLE_RETRIEVE:
                return status
    return IMPOSSIBLE_RETRIEVE


async def _certificate_ocsp_status(row: tuple, certificate_type: DatabaseType, session: aiohttp.ClientSession) -> str:
    """Return the OCSP status of a certificate from its database row."""
    _, authority_info_access, issuer_common_name, issuer_raw, raw, _ = row
    aia = json.loads(authority_info_access)
    issuer_url = next(iter(aia.get("issuer_urls", [])), None)
    ocsp_urls = aia.get("ocsp_urls", [])

    # A root is its own issuer
    is_root = certificate_type == DatabaseType.ROOT
    issuer = Certificate.load(raw if is_root else issuer_raw)

    if issuer_url is None and issuer is None:
        return "No Issuer Url Found"
    if len(ocsp_urls) == 0:
        return "No OCSP Url Found"

    certificate = issuer if is_root else Certificate.load(raw)
    if certificate is None:
        logging.error("Impossibile eseguire la richiesta OCSP: il certificato non è presente")
        return IMPOSSIBLE_RETRIEVE

    # Download a missing issuer certificate once for all URLs and algorithms
    if issuer is None:
        issuer = await _download_issuer_certificate(issuer_url, issuer_common_name, session)
        if issuer is None:
            return IMPOSSIBLE_RETRIEVE

    return await _query_ocsp_urls(certificate, issuer, ocsp_urls, session)


async def _check_certificate(row: tuple, certificate_type: DatabaseType,
                             session: aiohttp.ClientSession) -> tuple[str, int, str]:
    """Return the CSV row (status, certificate_id, leaf_domain) for a certificate."""
    try:
        status = await _certificate_ocsp_status(row, certificate_type, session)
    except Exception as e:
        logging.debug(f"Errore durante il controllo OCSP del certificato ID {row[0]}: {e}")
        status = IMPOSSIBLE_RETRIEVE
    return status, row[0], row[-1]


# ---------------------------------------------------------------- database and CSV files

@asynccontextmanager
async def _bulk_update_mode(db: aiosqlite.Connection):
    """In-memory journal and no fsync during the import, restored afterwards."""
    # MEMORY rather than OFF: with journal_mode = OFF, ROLLBACK is not supported
    await db.execute("PRAGMA journal_mode = MEMORY")
    await db.execute("PRAGMA synchronous = OFF")
    await db.execute("PRAGMA temp_store = MEMORY")
    yield
    await db.execute("PRAGMA journal_mode = DELETE")
    await db.execute("PRAGMA synchronous = FULL")
    await db.execute("PRAGMA temp_store = FILE")


def _valid_rows(reader: Iterable[list[str]], path: str) -> Iterator[tuple[int, str, str]]:
    """Yield CSV rows as (certificate_id, ocsp_check, leaf_domain), skipping malformed ones."""
    for row in reader:
        # E.g. a truncated last row if the program was interrupted while writing
        if len(row) < 3 or not row[1].isdigit():
            logging.warning(f"Riga non valida ignorata nel file '{path}': {row}")
            continue
        yield int(row[1]), row[0], row[2]


def _batched(iterable: Iterable, size: int) -> Iterator[list]:
    """Split an iterable into lists of at most size items (itertools.batched needs Python 3.12)."""
    iterator = iter(iterable)
    while batch := list(islice(iterator, size)):
        yield batch


async def _import_csv(db: aiosqlite.Connection, path: str, is_backup: bool) -> None:
    """Apply the OCSP results of a CSV file to the database, then delete it unless it is the backup."""
    logging.info(f"Inizio aggiornamento dei dati dal file {'di backup' if is_backup else 'temporaneo'} al database.")

    with open(path, mode="r", newline="") as csv_file:
        reader = csv.reader(csv_file)
        if is_backup:
            next(reader, None)   # Header (the backup file may be empty)

        async with _bulk_update_mode(db):
            try:
                await db.execute(CERTIFICATE_ID_INDEX_SQL)
                await db.execute(CREATE_TEMP_TABLE)
                # One database round-trip per batch
                for batch in _batched(_valid_rows(reader, path), CSV_IMPORT_BATCH_SIZE):
                    await db.executemany(INSERT_TEMP, batch)
                # Without this index the UPDATE scans the whole temp table for each certificate
                await db.execute(CREATE_TEMP_INDEX)
                await db.execute(UPDATE_FROM_TEMP)
                await db.execute("DROP TABLE IF EXISTS TempOCSP")
                await db.commit()
            except BaseException:
                await db.rollback()
                raise

    # The backup is kept until a new one is written
    if not is_backup:
        os.remove(path)


async def _save_backup(db: aiosqlite.Connection, backup_file: str) -> None:
    """Atomically rewrite the backup CSV with the OCSP results stored in the database."""
    temp_file = f"{backup_file}.tmp"
    with open(temp_file, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(OCSP_BACKUP_HEADER)
        async with db.execute(SELECT_CHECKED) as cursor:
            while rows := await cursor.fetchmany(BACKUP_FETCH_SIZE):
                writer.writerows(rows)
    os.replace(temp_file, backup_file)


async def _fetch_pending(db: aiosqlite.Connection, last_certificate_id: int) -> list[tuple]:
    async with db.execute(SELECT_PENDING, (last_certificate_id, OCSP_BATCH_SIZE)) as cursor:
        return await cursor.fetchall()


async def _count_pending(db: aiosqlite.Connection) -> int:
    async with db.execute(COUNT_PENDING) as cursor:
        return (await cursor.fetchone())[0]


async def _mark_unverifiable(db: aiosqlite.Connection, certificate_type: DatabaseType) -> None:
    """Mark certificates without an OCSP URL and, for non-roots, without issuer URL and certificate."""
    await db.execute(MARK_NO_OCSP_URL)
    await db.commit()
    if certificate_type != DatabaseType.ROOT:
        await db.execute(MARK_NO_ISSUER_URL)
        await db.commit()


# ---------------------------------------------------------------- OCSP analysis

async def _check_pending_certificates(db: aiosqlite.Connection, certificate_type: DatabaseType, writer, pbar) -> None:
    """Check pending certificates (at most OCSP_MAX_CONCURRENT_REQUESTS at once), writing each result when ready."""
    semaphore = asyncio.Semaphore(OCSP_MAX_CONCURRENT_REQUESTS)
    tasks: set[asyncio.Task] = set()
    failures: list[BaseException] = []

    async def check_and_write(row: tuple, session: aiohttp.ClientSession) -> None:
        try:
            # Written immediately so an interruption doesn't lose completed checks
            writer.writerow(await _check_certificate(row, certificate_type, session))
            pbar.update(1)
        finally:
            semaphore.release()

    def on_done(task: asyncio.Task) -> None:
        tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            failures.append(task.exception())

    # force_close: idle keep-alive connections don't count towards the limit and could exhaust file descriptors
    connector = aiohttp.TCPConnector(limit=OCSP_MAX_CONCURRENT_REQUESTS, force_close=True)
    async with aiohttp.ClientSession(connector=connector, timeout=HTTP_REQUEST_TIMEOUT) as session:
        try:
            last_certificate_id = 0
            while rows := await _fetch_pending(db, last_certificate_id):
                for row in rows:
                    # Bounds in-flight checks without waiting for the whole page
                    await semaphore.acquire()
                    if failures:
                        raise failures[0]
                    task = asyncio.create_task(check_and_write(row, session))
                    tasks.add(task)
                    task.add_done_callback(on_done)
                last_certificate_id = rows[-1][0]
            await asyncio.gather(*tasks)
            if failures:
                raise failures[0]
        finally:
            # On error or interruption, cancel the checks still running
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def _check_certificates(db: aiosqlite.Connection, certificate_type: DatabaseType, writer) -> None:
    """Check the OCSP status of 'No Request Done' certificates, writing results to the temp file."""
    logging.info(f"Inizio del controllo OCSP per i certificati. Tipo di certificati: '{certificate_type.name}', "
                 f"Batch Size: {OCSP_BATCH_SIZE}.")
    try:
        await _mark_unverifiable(db, certificate_type)

        logging.info("Conteggio del numero di certificati da elaborare...")
        total = await _count_pending(db)
        if total == 0:
            logging.info("Nessun certificato da analizzare è presente nel database.")
            return

        with progress_bar(total, " 🕵️‍♂️  [blue bold]Elaborazione Certificati[/blue bold]", "blue") as pbar:
            await _check_pending_certificates(db, certificate_type, writer, pbar)
    except Exception as e:
        # Results already in the temp file are still imported by the caller
        logging.error(f"Errore generale durante il controllo dello stato OCSP: {e}")


async def run_ocsp_analysis(database: Database, output_dir: str | os.PathLike) -> None:
    """Run the OCSP analysis on the database, resuming from and backing up results to CSV."""
    temp_file = os.path.abspath(os.path.join(output_dir, OCSP_TEMP_FILE))
    backup_file = os.path.abspath(os.path.join(output_dir, OCSP_BACKUP_FILE))
    try:
        # Secondary indexes only slow down the updates
        database.drop_secondary_indexes()

        async with aiosqlite.connect(database.db_path) as db:
            # Backup of completed runs first, then the results of an interrupted run
            if os.path.exists(backup_file):
                await _import_csv(db, backup_file, is_backup=True)
            if os.path.exists(temp_file) and os.path.getsize(temp_file) > 0:
                await _import_csv(db, temp_file, is_backup=False)

            with open(temp_file, mode="a", newline="") as temp_csv:
                await _check_certificates(db, database.db_type, csv.writer(temp_csv))
            await _import_csv(db, temp_file, is_backup=False)

            await _save_backup(db, backup_file)
            logging.info(f"Salvataggio dei dati dello stato OCSP come backup eseguito con successo: 'file://{backup_file}'")
        logging.info("Analisi OCSP per i certificati completata.")
    except asyncio.CancelledError:
        logging.info("Elaborazione della richiesta di controllo OCSP cancellata.")
        raise
    except Exception as e:
        logging.error(f"Errore nell'elaborazione della richiesta di controllo OCSP: {e}")
