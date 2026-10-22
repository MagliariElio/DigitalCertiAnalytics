from __future__ import annotations

import json
import logging
import shutil
import subprocess
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
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

# Parallel sslyze scans (network-bound)
CHAIN_VALIDATION_WORKERS = 16

# Per-host sslyze timeout in seconds, so a stuck host can't stall the whole run
SSLYZE_TIMEOUT = 300

# Results saved per transaction, so an interrupted run keeps almost all of its work
CHAIN_VALIDATION_SAVE_EVERY = 100


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
        logging.error("Ricerca dell'issuer non valida: la catena deve essere una lista e l'issuer_dn una stringa.")
        return None

    issuer = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
    return None if issuer is None else issuer.get("raw", "")


def verify_signature(cert: x509.Certificate | None, ca_cert: x509.Certificate | None) -> str:
    """Verify cert's signature with the issuer's public key."""
    if cert is None:
        logging.error("Impossibile verificare la firma: il certificato non è presente")
        return "Error"
    if ca_cert is None:
        logging.error("Impossibile verificare la firma: il certificato Issuer non è presente")
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
        logging.error(f"Errore nella verifica del certificato: {e}")
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


def check_certificate_chain(hostname: str) -> str | None:
    """Validate the host's chain with sslyze: 'Valid', 'Not Valid', 'Error', or None if sslyze was killed."""
    command = ["sslyze", "--certinfo", "--json_out", "-", hostname]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=SSLYZE_TIMEOUT)
        return _sslyze_validation_result(json.loads(result.stdout))
    except subprocess.CalledProcessError as e:
        if e.returncode < 0:
            # Killed by a signal (e.g. Ctrl+C on the process group): no result to store
            return None
        logging.error(f"Errore durante l'esecuzione di sslyze: {e.stderr}")
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout durante l'esecuzione di sslyze per l'hostname {hostname}")
    except json.JSONDecodeError as e:
        logging.error(f"Errore nel decodificare l'output JSON: {e}")
    except Exception as e:
        logging.error(f"Si è verificato un errore durante la verifica del certificate chain per l'hostname {hostname} : {e}")
    return "Error"


def _leaf_domains(dao: CertificateDAO) -> Iterator[tuple[int, str]]:
    for batch in dao.iter_leaf_domains():
        yield from batch


def _save_results(dao: CertificateDAO, database: Database, results: list[tuple[str, int]]) -> None:
    if results:
        with database.transaction():
            dao.update_signature_validity(results)
        results.clear()


def _submit_scans(executor: ThreadPoolExecutor, domains: Iterator[tuple[int, str]], pending: dict[Future, int]) -> None:
    """Keep at most two scans per worker queued, so a slow host never idles the other workers."""
    while len(pending) < 2 * CHAIN_VALIDATION_WORKERS:
        item = next(domains, None)
        if item is None:
            return
        certificate_id, leaf_domain = item
        pending[executor.submit(check_certificate_chain, leaf_domain)] = certificate_id


def _scan_domains(dao: CertificateDAO, database: Database, executor: ThreadPoolExecutor, pbar) -> None:
    domains = _leaf_domains(dao)
    pending: dict[Future, int] = {}
    results: list[tuple[str, int]] = []
    try:
        _submit_scans(executor, domains, pending)
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                certificate_id = pending.pop(future)
                if (result := future.result()) is not None:
                    results.append((result, certificate_id))
                pbar.update(1)
            if len(results) >= CHAIN_VALIDATION_SAVE_EVERY:
                _save_results(dao, database, results)
            _submit_scans(executor, domains, pending)
    finally:
        # Also on interruption, keep the results already collected
        _save_results(dao, database, results)


def validate_leaf_certificate_chains(dao: CertificateDAO, database: Database) -> None:
    """Validate each leaf domain's chain with sslyze and store the result in signature_valid."""
    logging.info("Inizio controllo della validità della catena sui certificati...")

    # Without sslyze every certificate would be overwritten with 'Error'
    if shutil.which("sslyze") is None:
        logging.error("Eseguibile 'sslyze' non trovato nel PATH: impossibile eseguire la validazione delle catene.")
        return

    executor = ThreadPoolExecutor(max_workers=CHAIN_VALIDATION_WORKERS)
    try:
        with progress_bar(dao.get_certificates_count(), " 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]",
                          "magenta") as pbar:
            _scan_domains(dao, database, executor, pbar)
    except KeyboardInterrupt:
        logging.info("Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
        raise
    except Exception as e:
        logging.error(f"Errore durante la validazione delle catene dei certificati: {e}")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
