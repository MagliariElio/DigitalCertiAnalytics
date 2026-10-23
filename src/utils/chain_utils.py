from __future__ import annotations

import json
import logging
import math
import re
import shutil
import signal
import subprocess
import threading
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from itertools import islice
from typing import TYPE_CHECKING, Iterator

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from utils.utils import progress_bar

if TYPE_CHECKING:
    from dao.certificate_dao import CertificateDAO
    from db.database import Database

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Parallel sslyze invocations (network-bound)
CHAIN_VALIDATION_WORKERS = 16

# Per-host sslyze timeout in seconds, so a stuck host can't stall the whole run
SSLYZE_TIMEOUT = 300

# Hosts per sslyze invocation: its start-up (~0.35 s) and the idle tail of its last scans are paid once per batch,
# and the hosts are scanned concurrently
SSLYZE_BATCH_SIZE = 100

# Timeout of a batch invocation: SSLYZE_TIMEOUT per group of the 10 hosts sslyze scans at a time, at most
# SSLYZE_BATCH_TIMEOUT. Each host is bounded by its own network timeouts: measured 100-host batches took 0.5-56 s
# (reachable, refused, unresolvable, unrouted or mixed hosts), and about 55 s per group when every host accepts the
# connection but never answers (55 s for 1 or 10 hosts, 551 s for 100). A batch that times out is checked host by
# host, which gives the same results, so this only bounds the time a stuck host wastes before its own check
SSLYZE_CONCURRENT_HOSTS = 10
SSLYZE_BATCH_TIMEOUT = 3 * SSLYZE_TIMEOUT

# Results saved per transaction, so an interrupted run keeps almost all of its work
CHAIN_VALIDATION_SAVE_EVERY = 100

# Plain host names, reported unchanged by sslyze; anything else (ports, IPs in braces, IDNs, a leading '-')
# is checked by its own invocation as before
_PLAIN_HOSTNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}(?:\.[A-Za-z0-9_-]{1,63})*")
_PORT_SUFFIX = re.compile(r":\d+$")


def is_root_certificate(certificate: dict) -> bool:
    """True if the zgrab2 certificate is a root: self-signed with subject equal to issuer."""
    parsed = certificate.get("parsed", {})
    self_signed = parsed.get("signature", {}).get("self_signed", False)
    return bool(self_signed) and parsed.get("subject_dn", "") == parsed.get("issuer_dn", "")


def walk_chain(chain: list[dict], certificate: dict) -> Iterator[tuple[dict, list[dict]]]:
    """Walk up the chain from certificate, yielding (issuer, remaining chain without it)."""
    remaining = list(chain)
    current = certificate
    while remaining:
        issuer_dn = current.get("parsed", {}).get("issuer_dn", "")
        issuer = next((cert for cert in remaining if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
        if issuer is None:
            return

        # Remove by identity, not serial: distinct certificates may share a serial number
        remaining = [cert for cert in remaining if cert is not issuer]
        yield issuer, remaining

        if is_root_certificate(issuer):
            return
        current = issuer


def intermediate_certificates(chain: list[dict], certificate: dict) -> Iterator[tuple[dict, list[dict]]]:
    """Yield the intermediates above certificate (up to the first root, excluded) with the remaining chain."""
    if not chain or is_root_certificate(certificate):
        return

    for issuer, remaining in walk_chain(chain, certificate):
        if is_root_certificate(issuer):
            return
        yield issuer, remaining


def find_root_certificate(chain: list[dict], certificate: dict) -> tuple[dict | None, int]:
    """Return the root reached up the chain and the number of intermediates walked, else (None, 0)."""
    for walked, (issuer, _) in enumerate(walk_chain(chain, certificate)):
        if is_root_certificate(issuer):
            return issuer, walked
    return None, 0


def count_intermediates_up_to_root(chain: list[dict], certificate: dict) -> tuple[int, bool]:
    """Count intermediates up to the root and whether the root is in the chain."""
    count = 0
    for issuer, _ in walk_chain(chain, certificate):
        if is_root_certificate(issuer):
            return count, True
        count += 1
    return count, False


def find_raw_cert_issuer(chain: list[dict], issuer_dn: str) -> str | None:
    """Return the raw of the first chain certificate whose subject equals issuer_dn."""
    if not isinstance(chain, list) or not isinstance(issuer_dn, str):
        logging.error("Invalid issuer lookup: the chain must be a list and the issuer_dn a string.")
        return None

    issuer = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
    return None if issuer is None else issuer.get("raw", "")


def verify_signature(cert: x509.Certificate | None, ca_cert: x509.Certificate | None) -> str:
    """Verify cert's signature with the issuer's public key."""
    if cert is None:
        logging.error("Cannot verify the signature: the certificate is missing")
        return "Error"
    if ca_cert is None:
        logging.error("Cannot verify the signature: the issuer certificate is missing")
        return "Error"

    try:
        public_key = ca_cert.public_key()
        signature, tbs_certificate = cert.signature, cert.tbs_certificate_bytes

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, tbs_certificate, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            # Padding depends on the signature algorithm (PKCS1v15 or RSASSA-PSS); for some algorithms
            # (e.g. md5WithRSAEncryption) cryptography returns no parameters, so fall back to PKCS1v15
            rsa_padding = cert.signature_algorithm_parameters
            if not isinstance(rsa_padding, (padding.PKCS1v15, padding.PSS)):
                rsa_padding = padding.PKCS1v15()
            public_key.verify(signature, tbs_certificate, rsa_padding, cert.signature_hash_algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # EdDSA has no separate hash algorithm
            public_key.verify(signature, tbs_certificate)
        else:
            return "Unsupported Key Type"
        return "Valid"
    except InvalidSignature:
        return "Not Valid"
    except Exception as e:
        logging.error(f"Error verifying the certificate: {e}")
        return "Error"


def reorder_signature_algorithm(name: str) -> str:
    """Reorder an RSA algorithm name to 'signature-hash' (e.g. 'SHA256-RSA' -> 'RSA-SHA256')."""
    if "RSA" in name and "-" in name:
        hash_algorithm, signing_algorithm = name.split("-", 1)
        return f"{signing_algorithm}-{hash_algorithm}"
    return name


def _sslyze_validation_result(scan_results: dict) -> str:
    server_scan_results = scan_results.get("server_scan_results", [])
    if len(server_scan_results) == 0:
        return "Error"

    certificate_deployments = (server_scan_results[0].get("scan_result", {}).get("certificate_info", {})
                               .get("result", {}).get("certificate_deployments", []))
    if len(certificate_deployments) == 0:
        return "Error"

    path_validation_results = certificate_deployments[0].get("path_validation_results", [])
    if any(result.get("was_validation_successful") is True for result in path_validation_results):
        return "Valid"
    return "Not Valid"


class _SslyzeProcesses:
    """Runs sslyze and kills the running invocations on interruption, so a long batch can't delay the shutdown."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running: set[subprocess.Popen] = set()
        self._stopped = False

    def run(self, command: list[str], timeout: float) -> str:
        """Return sslyze's stdout, raising like subprocess.run(command, check=True, timeout=timeout)."""
        with self._lock:
            if self._stopped:
                # As if killed straight away: no result to store
                raise subprocess.CalledProcessError(-signal.SIGKILL, command)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self._running.add(process)
        try:
            with process:
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise
        finally:
            with self._lock:
                self._running.discard(process)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        return stdout

    @property
    def stopped(self) -> bool:
        return self._stopped

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            for process in self._running:
                process.kill()


def check_certificate_chain(hostname: str, processes: _SslyzeProcesses | None = None) -> str | None:
    """Validate the host's chain with sslyze: 'Valid', 'Not Valid', 'Error', or None if sslyze was killed."""
    command = ["sslyze", "--certinfo", "--json_out", "-", hostname]
    try:
        stdout = (processes or _SslyzeProcesses()).run(command, SSLYZE_TIMEOUT)
        return _sslyze_validation_result(json.loads(stdout))
    except subprocess.CalledProcessError as e:
        if e.returncode < 0:
            # Killed by a signal (e.g. Ctrl+C on the process group): no result to store
            return None
        logging.error(f"Error running sslyze: {e.stderr}")
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout running sslyze for hostname {hostname}")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding the sslyze JSON output: {e}")
    except Exception as e:
        logging.error(f"Error checking the certificate chain for hostname {hostname}: {e}")
    return "Error"


def _host_validation_result(server_scan_result: dict, hostname: str) -> str:
    """Result of one host in a multi-host output, logged as check_certificate_chain does for that host alone."""
    try:
        return _sslyze_validation_result({"server_scan_results": [server_scan_result]})
    except Exception as e:
        # e.g. no connectivity: scan_result is null
        logging.error(f"Error checking the certificate chain for hostname {hostname}: {e}")
        return "Error"


def _index_sslyze_output(output: dict) -> tuple[dict[str, dict], set[str]]:
    """Index a multi-host sslyze output by lower-case host name: scan results and invalid (e.g. unresolvable) hosts."""
    scanned: dict[str, dict] = {}
    for server_scan_result in output["server_scan_results"]:
        location = server_scan_result.get("server_location") if isinstance(server_scan_result, dict) else None
        hostname = location.get("hostname") if isinstance(location, dict) else None
        if isinstance(hostname, str):
            scanned.setdefault(hostname.lower(), server_scan_result)

    invalid: set[str] = set()
    for invalid_server in output.get("invalid_server_strings") or []:
        server_string = invalid_server.get("server_string") if isinstance(invalid_server, dict) else None
        if isinstance(server_string, str):
            invalid.add(_PORT_SUFFIX.sub("", server_string).lower())
    return scanned, invalid


def _map_batch_results(items: list[tuple[int, str]], scanned: dict[str, dict],
                       invalid: set[str]) -> tuple[list[tuple[str, int]], list[tuple[int, str]]]:
    results, missing = [], []
    for certificate_id, hostname in items:
        key = hostname.lower()
        if key in scanned:
            results.append((_host_validation_result(scanned[key], hostname), certificate_id))
        elif key in invalid:
            # Like a single-host output with no scan result
            results.append(("Error", certificate_id))
        else:
            missing.append((certificate_id, hostname))
    if missing:
        logging.info(f"Hosts missing from the sslyze output ({len(missing)}): checking them one at a time.")
    return results, missing


def _batch_timeout(hosts: int) -> float:
    return min(SSLYZE_BATCH_TIMEOUT, SSLYZE_TIMEOUT * math.ceil(hosts / SSLYZE_CONCURRENT_HOSTS))


def _scan_batch(items: list[tuple[int, str]],
                processes: _SslyzeProcesses) -> tuple[list[tuple[str, int]], list[tuple[int, str]]]:
    """Scan plain host names with one sslyze invocation.

    Returns the (result, certificate_id) pairs and the items to check one by one: the hosts missing from the output
    and, if the invocation fails, the whole batch.
    """
    hosts: dict[str, str] = {}
    for _, hostname in items:
        hosts.setdefault(hostname.lower(), hostname)
    command = ["sslyze", "--certinfo", "--json_out", "-", *hosts.values()]
    try:
        scanned, invalid = _index_sslyze_output(json.loads(processes.run(command, _batch_timeout(len(hosts)))))
    except subprocess.CalledProcessError as e:
        if e.returncode == -signal.SIGINT or processes.stopped:
            # Interrupted (Ctrl+C): no results to store, as for a single host
            return [], []
        # Any other failure, also a crash: the hosts checked one by one get today's results
        reason = f"exit code {e.returncode}"
    except subprocess.TimeoutExpired:
        reason = "timeout"
    except Exception as e:
        reason = f"invalid output: {e}"
    else:
        return _map_batch_results(items, scanned, invalid)

    logging.warning(f"sslyze scan of {len(hosts)} hosts failed ({reason}): checking them one at a time.")
    return [], list(items)


def _scan(items: list[tuple[int, str]],
          processes: _SslyzeProcesses) -> tuple[list[tuple[str, int]], list[tuple[int, str]]]:
    """Scan a work item: (results, items to check one by one)."""
    if len(items) == 1:
        certificate_id, hostname = items[0]
        result = check_certificate_chain(hostname, processes)
        return ([] if result is None else [(result, certificate_id)]), []

    plain = [item for item in items if isinstance(item[1], str) and _PLAIN_HOSTNAME.fullmatch(item[1])]
    if len({hostname.lower() for _, hostname in plain}) < 2:
        return [], list(items)
    results, single = _scan_batch(plain, processes)
    plain_ids = {certificate_id for certificate_id, _ in plain}
    return results, single + [item for item in items if item[0] not in plain_ids]


def _leaf_domains(dao: CertificateDAO) -> Iterator[tuple[int, str]]:
    for batch in dao.iter_leaf_domains():
        yield from batch


def _save_results(dao: CertificateDAO, database: Database, results: list[tuple[str, int]]) -> None:
    if results:
        with database.transaction():
            dao.update_signature_validity(results)
        results.clear()


class _Scans:
    """Work queue of the validation: batches of new domains, then the single hosts to re-check first."""

    def __init__(self, dao: CertificateDAO, executor: ThreadPoolExecutor, processes: _SslyzeProcesses) -> None:
        self.domains = _leaf_domains(dao)
        self.single: deque[tuple[int, str]] = deque()
        self.pending: dict[Future, int] = {}
        self.executor = executor
        self.processes = processes

    def submit(self) -> None:
        """Keep at most two scans per worker queued, so a slow batch never idles the other workers."""
        while len(self.pending) < 2 * CHAIN_VALIDATION_WORKERS:
            items = [self.single.popleft()] if self.single else list(islice(self.domains, SSLYZE_BATCH_SIZE))
            if not items:
                return
            self.pending[self.executor.submit(_scan, items, self.processes)] = len(items)


def _scan_domains(dao: CertificateDAO, database: Database, scans: _Scans, pbar) -> None:
    results: list[tuple[str, int]] = []
    try:
        scans.submit()
        while scans.pending:
            done, _ = wait(scans.pending, return_when=FIRST_COMPLETED)
            for future in done:
                size = scans.pending.pop(future)
                scan_results, single = future.result()
                results.extend(scan_results)
                scans.single.extend(single)
                pbar.update(size - len(single))
            if len(results) >= CHAIN_VALIDATION_SAVE_EVERY:
                _save_results(dao, database, results)
            scans.submit()
    finally:
        # Also on interruption, keep the results already collected
        _save_results(dao, database, results)


def validate_leaf_certificate_chains(dao: CertificateDAO, database: Database) -> None:
    """Validate each leaf domain's chain with sslyze and store the result in signature_valid."""
    logging.info("Starting the certificate chain validation...")

    # Without sslyze every certificate would be overwritten with 'Error'
    if shutil.which("sslyze") is None:
        logging.error("'sslyze' executable not found in PATH: cannot validate the certificate chains.")
        return

    executor = ThreadPoolExecutor(max_workers=CHAIN_VALIDATION_WORKERS)
    processes = _SslyzeProcesses()
    try:
        with progress_bar(dao.get_certificates_count(), " 🔍  [magenta bold]Processing Certificates[/magenta bold]",
                          "magenta") as pbar:
            _scan_domains(dao, database, _Scans(dao, executor, processes), pbar)
    except KeyboardInterrupt:
        logging.info("Interrupt signal (SIGINT) received: shutting down...")
        raise
    except Exception as e:
        logging.error(f"Error validating the certificate chains: {e}")
    finally:
        # The running scans would be discarded: kill them, and drop the queued ones
        processes.stop()
        executor.shutdown(wait=False, cancel_futures=True)
