from __future__ import annotations

import argparse
import csv
import logging
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from itertools import repeat

from pathlib import Path

from pymongo import MongoClient
from pymongo.collection import Collection

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))    # src/, to share the database names
from db.MongoDbDatabase import ZLINT_DB_NAMES  # noqa: E402
from db.database import DatabaseType  # noqa: E402
from db.mongo_server import (DEFAULT_URI, MongoServerError, app_name, ensure_mongodb,  # noqa: E402
                             stop_signals_as_ctrl_c)

# Admin: Anuar Elio Magliari
# Politecnico di Torino

MONGO_URI = DEFAULT_URI
DEFAULT_DB_NAME = ZLINT_DB_NAMES[DatabaseType.LEAF]
PROJECTION = {'_id': 0, 'issuer_dn': 1, 'zlint_results': 1}


def collect_statistics(collection: Collection) -> tuple[Counter, Counter]:
    """Single pass: occurrences per (result, field, issuer) and certificate count per result."""
    occurrences = Counter()     # (result, field, issuer) -> count, in first-seen order
    certificates = Counter()    # result -> certificates with at least one field with that result
    for doc in collection.find({}, PROJECTION):
        zlint_results = doc.get("zlint_results", {})
        results = [detail.get("result") for detail in zlint_results.values()]
        occurrences.update(zip(results, zlint_results, repeat(doc.get("issuer_dn"))))
        for result in dict.fromkeys(results):
            certificates[result] += 1
    return occurrences, certificates


def _by_descending_count(items: Iterable[tuple]) -> list[tuple]:
    """Sort (key, count) pairs by descending count; ties keep their original order."""
    return sorted(items, key=lambda item: item[1], reverse=True)


def write_field_ranking(occurrences: Counter, path: str = "zlint_results.csv") -> None:
    """Per result, write fields by occurrence count with their top issuer."""
    issuers_by_field = defaultdict(lambda: defaultdict(Counter))
    for (result, field, issuer), count in occurrences.items():
        issuers_by_field[result][field][issuer] = count

    with open(path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["result", "field", "total", "top_issuer", "top_count"])
        for result, fields in issuers_by_field.items():
            totals = _by_descending_count((field, sum(issuers.values())) for field, issuers in fields.items())
            for field, total in totals:
                top_issuer, top_count = fields[field].most_common(1)[0]
                writer.writerow([result, field, total, top_issuer, top_count])


def write_issuer_ranking(occurrences: Counter, path: str = "issuer_ranking_by_result.csv") -> None:
    """Per result, write the issuer ranking by total occurrences."""
    issuers_by_result = defaultdict(Counter)
    for (result, _, issuer), count in occurrences.items():
        issuers_by_result[result][issuer] += count

    with open(path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["result", "issuer", "count", "rank"])
        for result, issuers in issuers_by_result.items():
            for rank, (issuer, count) in enumerate(_by_descending_count(issuers.items()), start=1):
                writer.writerow([result, issuer, count, rank])


def write_certificates_summary(certificates: Counter, path: str = "certificates_result_summary.csv") -> None:
    """Write the number of certificates per result."""
    with open(path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["result", "certificate_count"])
        writer.writerows(_by_descending_count(certificates.items()))


def _read_statistics(db_name: str) -> tuple[Counter, Counter] | None:
    """The statistics of the database's ZLint results; None, after saying why, if there are none."""
    try:
        # Starts the MongoDB server included with the project when no server is running
        server = ensure_mongodb(MONGO_URI)
    except MongoServerError as e:
        print(e, file=sys.stderr)
        return None
    try:
        with MongoClient(MONGO_URI, appname=app_name()) as client:
            collection = client[db_name]['zlint_results']
            if collection.estimated_document_count() == 0:
                print(f"No ZLint results found in the database '{db_name}' "
                      f"(available databases: {client.list_database_names()}).")
                return None
            return collect_statistics(collection)
    finally:
        if server is not None:
            server.release()


def main(argv: list[str] | None = None) -> int:
    """Read ZLint results from MongoDB and write the three summary CSVs to the current directory."""
    parser = argparse.ArgumentParser(description="Write the summary CSVs of the ZLint results stored in MongoDB.")
    parser.add_argument("db_name", nargs="?", default=DEFAULT_DB_NAME,
                        help=f"Name of the MongoDB database to read (default: {DEFAULT_DB_NAME}).")
    db_name = parser.parse_args(argv).db_name
    # Shows when the MongoDB server included with the project is started and stopped
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Closing the terminal window meanwhile works like Ctrl+C: the bundled server is still stopped cleanly
    with stop_signals_as_ctrl_c():
        statistics = _read_statistics(db_name)
    if statistics is None:
        return 1
    occurrences, certificates = statistics

    write_field_ranking(occurrences)
    print("The results by field have been written to 'zlint_results.csv'.")
    write_issuer_ranking(occurrences)
    print("The issuer ranking by result has been written to 'issuer_ranking_by_result.csv'.")
    write_certificates_summary(certificates)
    print("The certificate summary has been written to 'certificates_result_summary.csv'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
