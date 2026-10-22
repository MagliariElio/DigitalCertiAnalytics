from __future__ import annotations

import argparse
import csv
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

# Admin: Anuar Elio Magliari
# Politecnico di Torino

MONGO_URI = 'mongodb://localhost:27017/'
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


def main(argv: list[str] | None = None) -> int:
    """Read ZLint results from MongoDB and write the three summary CSVs to the current directory."""
    parser = argparse.ArgumentParser(description="Genera i CSV di riepilogo dei risultati ZLint salvati in MongoDB.")
    parser.add_argument("db_name", nargs="?", default=DEFAULT_DB_NAME,
                        help=f"Nome del database MongoDB da leggere (default: {DEFAULT_DB_NAME}).")
    db_name = parser.parse_args(argv).db_name

    with MongoClient(MONGO_URI) as client:
        collection = client[db_name]['zlint_results']
        if collection.estimated_document_count() == 0:
            print(f"Nessun risultato ZLint trovato nel database '{db_name}' "
                  f"(database disponibili: {client.list_database_names()}).")
            return 1
        occurrences, certificates = collect_statistics(collection)

    write_field_ranking(occurrences)
    print("The results by field have been written in 'zlint_results.csv'.")
    write_issuer_ranking(occurrences)
    print("The issuer ranking by type has been written in 'issuer_ranking_by_result.csv'")
    write_certificates_summary(certificates)
    print("The certificate summary has been written in 'certificates_result_summary.csv'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
