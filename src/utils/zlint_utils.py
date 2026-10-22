from __future__ import annotations

import json
import logging
import os
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from bean.certificate import Certificate
from dao.certificate_dao import CertificateDAO
from db.MongoDbDatabase import MongoDbDatabase
from utils.utils import progress_bar

# Admin: Anuar Elio Magliari
# Politecnico di Torino

ZLINT_PATH = Path(__file__).resolve().parents[2] / "zlint" / "v3" / "zlint"
ZLINT_WORKERS = os.cpu_count() or 4
ZLINT_TIMEOUT = 60      # Seconds per certificate
BATCH_SIZE = 1000       # Certificates read from the DB and saved to MongoDB per batch

RESULTS_COLLECTION = 'zlint_results'
ERRORS_COLLECTION = 'zlint_errors'


def _timestamp() -> str:
    """Current time in the logging format (e.g. '2024-10-06 12:30:00,123')."""
    now = datetime.now()
    return f"{now:%Y-%m-%d %H:%M:%S},{now.microsecond // 1000:03d}"


def _count_results(zlint_result: object) -> dict[str, int]:
    """Count each lint result (pass, NA, NE, info, ...) in the ZLint output."""
    if not isinstance(zlint_result, dict):
        return {}
    return dict(Counter(lint['result'] for lint in zlint_result.values() if isinstance(lint, dict) and 'result' in lint))


class _ZLintError(Exception):
    """ZLint failure (non-zero exit or invalid output); the message is saved to MongoDB."""


def _run_zlint(raw: str | None) -> object:
    """Run ZLint with the PEM certificate on stdin (no temp file) and return the parsed JSON."""
    result = subprocess.run([os.fspath(ZLINT_PATH)], input=Certificate.to_pem(raw).encode(), capture_output=True,
                            timeout=ZLINT_TIMEOUT)
    if result.returncode != 0:
        raise _ZLintError(f"Errore durante l'esecuzione di ZLint: {result.stderr.decode(errors='replace')}")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise _ZLintError("Errore nel decodificare l'output JSON di ZLint.") from None


def _lint_certificate(row) -> tuple[str, dict]:
    """Lint a certificate, returning the target MongoDB collection and the document to store."""
    certificate_id, leaf_domain, raw, common_name, organization, issuer_dn = row
    try:
        zlint_result = _run_zlint(raw)
    except _ZLintError as e:
        error_message = str(e)
    except Exception as e:
        error_message = f"Errore generale durante l'elaborazione: {e}"
    else:
        return RESULTS_COLLECTION, {
            'count_results': _count_results(zlint_result),
            'certificate_id': certificate_id,
            'leaf_domain': leaf_domain,
            'issuer_common_name': common_name,
            'issuer_organization': organization,
            'issuer_dn': issuer_dn,
            'zlint_results': zlint_result,
        }

    return ERRORS_COLLECTION, {
        'certificate_id': certificate_id,
        'leaf_domain': leaf_domain,
        'error_message': error_message,
        'timestamp': _timestamp(),
    }


def _save_documents(mongo: MongoDbDatabase, documents: dict[str, list[dict]]) -> None:
    for collection_name, collection_documents in documents.items():
        if not collection_documents:
            continue
        try:
            mongo.get_collection(collection_name).insert_many(collection_documents)
        except Exception as e:
            logging.error(f"Errore durante il salvataggio dei risultati in MongoDB: {e}")


def _lint_certificates(dao: CertificateDAO, mongo: MongoDbDatabase) -> None:
    """Lint all certificates in parallel, saving results to MongoDB one batch at a time."""
    executor = ThreadPoolExecutor(max_workers=ZLINT_WORKERS)
    try:
        with progress_bar(dao.get_certificates_count(), " 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]",
                          "magenta") as pbar:
            for batch in dao.iter_raw_certificates(BATCH_SIZE):
                documents = {RESULTS_COLLECTION: [], ERRORS_COLLECTION: []}
                # map keeps input order, so documents are saved by certificate_id
                for collection_name, document in executor.map(_lint_certificate, batch):
                    if collection_name == ERRORS_COLLECTION:
                        logging.error(f"Errore durante l'elaborazione del certificato ID {document['certificate_id']}: "
                                      f"{document['error_message']}")
                    documents[collection_name].append(document)
                    pbar.update()
                _save_documents(mongo, documents)
    finally:
        # On interruption, drop the queued certificates
        executor.shutdown(wait=False, cancel_futures=True)


def run_zlint_check(dao: CertificateDAO) -> None:
    """Run ZLint on the database certificates and save the results to MongoDB."""
    if not (ZLINT_PATH.is_file() and os.access(ZLINT_PATH, os.X_OK)):
        logging.error(f"Eseguibile ZLint non trovato o non eseguibile: '{ZLINT_PATH}'. "
                      "Consultare il README per l'installazione.")
        return

    mongo = MongoDbDatabase(dao.certificate_type)
    try:
        # Check MongoDB up front, otherwise every result would be discarded with an error
        try:
            mongo.connect()
        except Exception:
            logging.error("Impossibile connettersi a MongoDB: verificare che il servizio sia avviato (vedi README).")
            return
        _lint_certificates(dao, mongo)
    except Exception as e:
        logging.error(f"Errore durante l'esecuzione della funzione run_zlint_check: {e}")
    except KeyboardInterrupt:
        logging.info("Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
        raise   # Stop the app instead of moving on to the next analyses
    finally:
        mongo.close()
