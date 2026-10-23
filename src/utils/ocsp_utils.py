from __future__ import annotations

import asyncio
import base64
import csv
import json
import logging
import os
from contextlib import aclosing, asynccontextmanager, contextmanager, suppress
from itertools import islice
from typing import AsyncIterator, Iterable, Iterator, NamedTuple
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

try:
    import resource
except ImportError:     # Windows
    resource = None

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Certificates checked at once (one connection each), lowered when the open files limit is too small:
# without a cap, tens of thousands of connections would exhaust file descriptors and produce false
# "Impossible Retrieve OCSP Information" results
OCSP_MAX_CONCURRENT_REQUESTS = 200
# Idle keep-alive connections kept for reuse: they hold file descriptors too
OCSP_MAX_IDLE_CONNECTIONS = 1000
# Soft RLIMIT_NOFILE requested for the analysis (capped by the hard limit)
OCSP_OPEN_FILES_TARGET = 4096
# File descriptors left to SQLite, the CSV and log files and the event loop
RESERVED_FILE_DESCRIPTORS = 64

HTTP_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=20)
KEEPALIVE_TIMEOUT = 15
DNS_CACHE_TTL = 300

# Rows per DB page (the next page is fetched while the current one is checked), per CSV executemany and per backup fetchmany
OCSP_BATCH_SIZE = 10000
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


# ---------------------------------------------------------------- connections

def _raise_open_files_limit() -> tuple[int | None, tuple[int, int] | None]:
    """Raise the soft RLIMIT_NOFILE towards OCSP_OPEN_FILES_TARGET.

    Return the soft limit now in force (None if unknown or unlimited) and the limits to restore (None if unchanged).
    """
    if resource is None:
        return None, None
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return None, None
    target = OCSP_OPEN_FILES_TARGET if hard == resource.RLIM_INFINITY else min(hard, OCSP_OPEN_FILES_TARGET)
    if soft >= target:
        return soft, None
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError) as e:
        logging.debug(f"Could not raise the open files limit from {soft} to {target}: {e}")
        return soft, None
    return target, (soft, hard)


@contextmanager
def _open_files_limit() -> Iterator[int | None]:
    """Raise the open files limit while the block runs; yield it (None if unknown or unlimited)."""
    limit, previous = _raise_open_files_limit()
    try:
        yield limit
    finally:
        if previous is not None:
            with suppress(ValueError, OSError):
                resource.setrlimit(resource.RLIMIT_NOFILE, previous)


def _connection_limits(open_files: int | None) -> tuple[int, int]:
    """Concurrent checks (at most half of the descriptors available) and idle connections that fit in the open files limit."""
    if open_files is None:
        return OCSP_MAX_CONCURRENT_REQUESTS, OCSP_MAX_IDLE_CONNECTIONS
    budget = max(open_files - RESERVED_FILE_DESCRIPTORS, 2)
    concurrency = max(1, min(OCSP_MAX_CONCURRENT_REQUESTS, budget // 2))
    return concurrency, max(1, min(OCSP_MAX_IDLE_CONNECTIONS, budget - concurrency))


class _BoundedIdleConnector(aiohttp.TCPConnector):
    """Keep-alive connector that closes released connections instead of pooling them once max_idle are idle.

    aiohttp bounds only the connections in use; idle ones (one pool per host) are closed after the keep-alive timeout.
    """

    def __init__(self, max_idle: int, **kwargs):
        super().__init__(**kwargs)
        self._max_idle = max_idle
        # Upper bound of the idle connections: only _release adds them, so the host pools are counted
        # again only when the bound reaches max_idle, not on every release
        self._idle_bound = 0

    def idle_connections(self) -> int:
        # aiohttp pools idle connections in _conns: {key: [(protocol, release time), ...]}
        return sum(map(len, getattr(self, "_conns", {}).values()))

    def _release(self, key, protocol, *args, should_close: bool = False, **kwargs) -> None:
        if not should_close and self._idle_bound >= self._max_idle:
            self._idle_bound = self.idle_connections()
            should_close = self._idle_bound >= self._max_idle
        if not should_close:
            self._idle_bound += 1
        super()._release(key, protocol, *args, should_close=should_close, **kwargs)


def _create_session(concurrency: int, max_idle: int) -> aiohttp.ClientSession:
    """HTTP session with keep-alive, DNS cache and at most `concurrency` connections in use."""
    connector = _BoundedIdleConnector(max_idle, limit=concurrency, keepalive_timeout=KEEPALIVE_TIMEOUT,
                                      ttl_dns_cache=DNS_CACHE_TTL)
    return aiohttp.ClientSession(connector=connector, timeout=HTTP_REQUEST_TIMEOUT)


# ---------------------------------------------------------------- issuer certificates

class _Download(NamedTuple):
    """Issuer download outcome: what to parse (DER_OR_PEM, PEM, PKCS7 or UNKNOWN with the content type) or what to log."""
    kind: str | None
    payload: bytes | str | None = None
    error: str | None = None


DER_OR_PEM, PEM, PKCS7, UNKNOWN = "der_or_pem", "pem", "pkcs7", "unknown"


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
        logging.error(f"Issuer certificate not found in the PKCS #7 bundle ({issuer_url})")
    return issuer_cert


async def _read_issuer_response(response: aiohttp.ClientResponse) -> _Download:
    """Read the body according to its Content-Type (DER/PEM/PKCS #7)."""
    content_type = response.headers.get("Content-Type", "")
    if content_type == "" or any(t in content_type for t in DER_CONTENT_TYPES):
        return _Download(DER_OR_PEM, await response.read())
    if any(t in content_type for t in PEM_CONTENT_TYPES):
        return _Download(PEM, (await response.text()).encode("utf-8"))
    if any(t in content_type for t in PKCS7_CONTENT_TYPES):
        return _Download(PKCS7, await response.read())
    return _Download(UNKNOWN, content_type)


async def _download_issuer(issuer_url: str, session: aiohttp.ClientSession) -> _Download:
    """Download the issuer certificate from the AIA URL; on failure kind is None."""
    try:
        async with session.get(issuer_url, headers=ISSUER_REQUEST_HEADERS) as response:
            if response.status != 200:
                return _Download(None, error=f"Error retrieving the certificate ({issuer_url}): HTTP status {response.status}")
            return await _read_issuer_response(response)
    except asyncio.TimeoutError:
        return _Download(None)
    except aiohttp.ClientError as e:
        return _Download(None, error=f"HTTP error retrieving the certificate ({issuer_url}): {e}")
    except Exception as e:
        return _Download(None, error=f"Error retrieving or parsing the certificate ({issuer_url}): {e}")


def _parse_issuer(download: _Download, issuer_url: str, issuer_common_name: str) -> x509.Certificate | None:
    """Parse a downloaded issuer certificate, logging errors as for each download."""
    try:
        if download.kind == DER_OR_PEM:
            return _load_der_or_pem(download.payload)
        if download.kind == PEM:
            return x509.load_pem_x509_certificate(download.payload)
        if download.kind == PKCS7:
            return _select_from_pkcs7(download.payload, issuer_common_name, issuer_url)
        logging.error(f"Unknown certificate format ({issuer_url}): {download.payload}")
    except Exception as e:
        logging.error(f"Error retrieving or parsing the certificate ({issuer_url}): {e}")
    return None


class _IssuerDownloads:
    """Issuer certificates downloaded from the AIA URLs, once per URL.

    Only successful downloads are cached; concurrent requests for the same URL share one download.
    Every row parses the payload and logs failures as if it had downloaded it.
    """

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session
        self._downloads: dict[str, asyncio.Future[_Download]] = {}

    async def get(self, issuer_url: str, issuer_common_name: str) -> x509.Certificate | None:
        """The issuer certificate at issuer_url, None (already logged) on error."""
        future = self._downloads.get(issuer_url)
        if future is None:
            future = self._downloads[issuer_url] = asyncio.ensure_future(_download_issuer(issuer_url, self._session))
        # shield: a cancelled row must not cancel the download shared with other rows
        download = await asyncio.shield(future)
        if download.kind is None:
            if self._downloads.get(issuer_url) is future:
                del self._downloads[issuer_url]
            if download.error:
                logging.error(download.error)
            return None
        return _parse_issuer(download, issuer_url, issuer_common_name)

    async def aclose(self) -> None:
        """Cancel the downloads still running."""
        pending = [future for future in self._downloads.values() if not future.done()]
        for future in pending:
            future.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


# ---------------------------------------------------------------- OCSP requests

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
        logging.debug(f"Network error during the OCSP request to {url}: {e}")
        return None
    except ValueError as e:
        # Invalid OCSP response: retry with another hash algorithm or URL
        logging.debug(f"Invalid OCSP response from {url}: {e}")
    except Exception as e:
        logging.error(f"Error during the OCSP request to {url}: {e}")
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


class _OcspChecker:
    """OCSP status of database rows through one HTTP session and shared issuer downloads."""

    def __init__(self, session: aiohttp.ClientSession, certificate_type: DatabaseType):
        self._session = session
        self._is_root = certificate_type == DatabaseType.ROOT
        self.issuer_downloads = _IssuerDownloads(session)

    async def status(self, row: tuple) -> str:
        """Return the OCSP status of a certificate from its database row."""
        _, authority_info_access, issuer_common_name, issuer_raw, raw, _ = row
        aia = json.loads(authority_info_access)
        issuer_url = next(iter(aia.get("issuer_urls", [])), None)
        ocsp_urls = aia.get("ocsp_urls", [])

        # A root is its own issuer
        issuer = Certificate.load(raw if self._is_root else issuer_raw)

        if issuer_url is None and issuer is None:
            return "No Issuer Url Found"
        if len(ocsp_urls) == 0:
            return "No OCSP Url Found"

        certificate = issuer if self._is_root else Certificate.load(raw)
        if certificate is None:
            logging.error("Cannot send the OCSP request: the certificate is missing")
            return IMPOSSIBLE_RETRIEVE

        # Missing issuer certificate: downloaded once per URL for all rows, URLs and algorithms
        if issuer is None:
            issuer = await self.issuer_downloads.get(issuer_url, issuer_common_name)
            if issuer is None:
                return IMPOSSIBLE_RETRIEVE

        return await _query_ocsp_urls(certificate, issuer, ocsp_urls, self._session)

    async def check(self, row: tuple) -> tuple[str, int, str]:
        """Return the CSV row (status, certificate_id, leaf_domain) for a certificate."""
        try:
            status = await self.status(row)
        except Exception as e:
            logging.debug(f"Error during the OCSP check of certificate ID {row[0]}: {e}")
            status = IMPOSSIBLE_RETRIEVE
        return status, row[0], row[-1]


# ---------------------------------------------------------------- database and CSV files

@asynccontextmanager
async def _connect(db_path: str | os.PathLike) -> AsyncIterator[aiosqlite.Connection]:
    """aiosqlite connection whose worker thread also stops when the connect is cancelled (Ctrl+C)."""
    db = aiosqlite.connect(db_path)
    try:
        await db
    except BaseException as e:
        # aiosqlite 0.20 (a Thread) stops its thread only on Exception, and the interpreter would wait for it at exit.
        # Private API of that version; later versions stop the thread themselves
        if not isinstance(e, Exception) and hasattr(db, "_stop_running"):
            db._stop_running()
            db.join()   # The connect takes milliseconds; it must end while the event loop is open
        raise
    try:
        yield db
    finally:
        await db.close()


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
            logging.warning(f"Skipped invalid row in file '{path}': {row}")
            continue
        yield int(row[1]), row[0], row[2]


def _batched(iterable: Iterable, size: int) -> Iterator[list]:
    """Split an iterable into lists of at most size items (itertools.batched needs Python 3.12)."""
    iterator = iter(iterable)
    while batch := list(islice(iterator, size)):
        yield batch


async def _import_csv(db: aiosqlite.Connection, path: str, is_backup: bool) -> None:
    """Apply the OCSP results of a CSV file to the database, then delete it unless it is the backup."""
    logging.info(f"Updating the database from the {'backup' if is_backup else 'temporary'} file.")

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
    try:
        with open(temp_file, mode="w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(OCSP_BACKUP_HEADER)
            async with db.execute(SELECT_CHECKED) as cursor:
                while rows := await cursor.fetchmany(BACKUP_FETCH_SIZE):
                    writer.writerows(rows)
        os.replace(temp_file, backup_file)
    except BaseException:
        # Interrupted or failed: the previous backup stays as it was
        with suppress(OSError):
            os.remove(temp_file)
        raise


async def _fetch_pending(db: aiosqlite.Connection, last_certificate_id: int) -> list[tuple]:
    async with db.execute(SELECT_PENDING, (last_certificate_id, OCSP_BATCH_SIZE)) as cursor:
        return await cursor.fetchall()


async def _pending_rows(db: aiosqlite.Connection) -> AsyncIterator[tuple]:
    """Yield the pending rows page by page, fetching the next page while the current one is checked."""
    next_page = asyncio.ensure_future(_fetch_pending(db, 0))
    try:
        while rows := await next_page:
            next_page = asyncio.ensure_future(_fetch_pending(db, rows[-1][0]))
            for row in rows:
                yield row
    finally:
        next_page.cancel()
        await asyncio.gather(next_page, return_exceptions=True)


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
    """Check pending certificates (a bounded number at once), writing each result when ready."""
    with _open_files_limit() as open_files:
        concurrency, max_idle = _connection_limits(open_files)
        logging.debug(f"Concurrent OCSP checks: {concurrency}, idle connections kept: {max_idle}.")
        async with _create_session(concurrency, max_idle) as session:
            checker = _OcspChecker(session, certificate_type)
            try:
                await _run_checks(_pending_rows(db), checker, concurrency, writer, pbar)
            finally:
                await checker.issuer_downloads.aclose()


class _CheckTasks:
    """Checks in flight, at most `concurrency`, each writing its result; the first failure is kept and re-raised."""

    def __init__(self, checker: _OcspChecker, concurrency: int, writer, pbar):
        self._checker, self._writer, self._pbar = checker, writer, pbar
        self._slots = asyncio.Semaphore(concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._failures: list[BaseException] = []

    def _raise_failure(self) -> None:
        if self._failures:
            raise self._failures[0]

    async def start(self, row: tuple) -> None:
        """Start checking the row once a slot is free; raise the first failure instead."""
        # Bounds in-flight checks without waiting for the whole page
        await self._slots.acquire()
        self._raise_failure()
        task = asyncio.create_task(self._check_and_write(row))
        self._tasks.add(task)
        task.add_done_callback(self._on_done)

    async def _check_and_write(self, row: tuple) -> None:
        try:
            # Written immediately so an interruption doesn't lose completed checks
            self._writer.writerow(await self._checker.check(row))
            self._pbar.update(1)
        except Exception as e:
            # Recorded before the slot is released, so the dispatcher stops at once
            self._failures.append(e)
            raise
        finally:
            self._slots.release()

    def _on_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if not task.cancelled():
            task.exception()    # Marks the exception as retrieved: it is already in _failures

    async def wait(self) -> None:
        """Wait for the checks in flight; raise the first failure."""
        await asyncio.gather(*self._tasks)
        self._raise_failure()

    async def cancel(self) -> None:
        """Cancel the checks still running."""
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


async def _run_checks(rows: AsyncIterator[tuple], checker: _OcspChecker, concurrency: int, writer, pbar) -> None:
    """Check the rows with at most `concurrency` checks in flight; the first failure stops everything."""
    tasks = _CheckTasks(checker, concurrency, writer, pbar)
    try:
        async with aclosing(rows):
            async for row in rows:
                await tasks.start(row)
        await tasks.wait()
    finally:
        # On error or interruption, cancel the checks still running
        await tasks.cancel()


async def _check_certificates(db: aiosqlite.Connection, certificate_type: DatabaseType, writer) -> None:
    """Check the OCSP status of 'No Request Done' certificates, writing results to the temp file."""
    logging.info(f"Starting the OCSP check of '{certificate_type.name}' certificates (batch size: {OCSP_BATCH_SIZE}).")
    try:
        await _mark_unverifiable(db, certificate_type)

        logging.info("Counting the certificates to check...")
        total = await _count_pending(db)
        if total == 0:
            logging.info("No certificates to check in the database.")
            return

        with progress_bar(total, " 🕵️‍♂️  [blue bold]Processing Certificates[/blue bold]", "blue") as pbar:
            await _check_pending_certificates(db, certificate_type, writer, pbar)
    except Exception as e:
        # Results already in the temp file are still imported by the caller
        logging.error(f"Error during the OCSP status check: {e}")


async def run_ocsp_analysis(database: Database, output_dir: str | os.PathLike) -> None:
    """Run the OCSP analysis on the database, resuming from and backing up results to CSV."""
    temp_file = os.path.abspath(os.path.join(output_dir, OCSP_TEMP_FILE))
    backup_file = os.path.abspath(os.path.join(output_dir, OCSP_BACKUP_FILE))
    try:
        # Secondary indexes only slow down the updates
        database.drop_secondary_indexes()

        async with _connect(database.db_path) as db:
            # Backup of completed runs first, then the results of an interrupted run
            if os.path.exists(backup_file):
                await _import_csv(db, backup_file, is_backup=True)
            if os.path.exists(temp_file) and os.path.getsize(temp_file) > 0:
                await _import_csv(db, temp_file, is_backup=False)

            with open(temp_file, mode="a", newline="") as temp_csv:
                await _check_certificates(db, database.db_type, csv.writer(temp_csv))
            await _import_csv(db, temp_file, is_backup=False)

            await _save_backup(db, backup_file)
            logging.info(f"OCSP status backup saved: 'file://{backup_file}'")
        logging.info("OCSP analysis of the certificates completed.")
    except asyncio.CancelledError:
        logging.info("OCSP check cancelled.")
        raise
    except Exception as e:
        logging.error(f"Error while processing the OCSP check: {e}")
