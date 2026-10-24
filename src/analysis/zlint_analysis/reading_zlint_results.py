"""Write the three summary CSVs of the ZLint results stored in a certificate database (see db.zlint_store).

Usage: reading_zlint_results.py [leaf|intermediate|root] [--db PATH]

The CSVs are written to the current directory: zlint_results.csv, issuer_ranking_by_result.csv and
certificates_result_summary.csv.
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from functools import lru_cache
from itertools import repeat
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))    # src/, to share the database code
from db.database import DatabaseType, OutdatedDatabaseError, database_state  # noqa: E402
from db.zlint_store import ZlintReader, has_tables, zstandard  # noqa: E402

# Admin: Anuar Elio Magliari
# Politecnico di Torino

INSTALLER_HINT = ("Run the installer again (install.sh on macOS and Linux, install.bat on Windows) to repair the "
                  "installation.")
ANALYSIS_DIR = Path(__file__).resolve().parents[1]
DEFAULT_TYPE = DatabaseType.LEAF.value
# The names of the MongoDB databases of earlier versions are accepted for the type
LEGACY_NAMES = {
    'Leaf_Zlint_Checks_Google_3': DatabaseType.LEAF.value,
    'Intermediate_Zlint_Checks_Google_3': DatabaseType.INTERMEDIATE.value,
    'Root_Zlint_Checks': DatabaseType.ROOT.value,
}
# Types whose certificates the analysis checks with ZLint (--<type>_zlint_check)
ZLINT_TYPES = (DatabaseType.LEAF.value, DatabaseType.INTERMEDIATE.value)
# Outputs kept while reading, as lints() (an output is shared by the certificates of many issuers)
BODY_CACHE_SIZE = 4096


def default_db_path(db_type: str) -> Path:
    """The database of the type written by the analysis: src/analysis/<type>/<type>_certificates.db."""
    return ANALYSIS_DIR / db_type / f"{db_type}_certificates.db"


def lints(zlint_results: dict) -> tuple[tuple, tuple, tuple]:
    """(results, fields, distinct results) of a ZLint output, in lint order. The names are interned: a cached output
    then costs only its two tuples, as every output has the same few hundred lint names."""
    fields = tuple(sys.intern(field) for field in zlint_results)
    results = tuple(sys.intern(result) if type(result) is str else result
                    for result in (detail.get("result") for detail in zlint_results.values()))
    return results, fields, tuple(dict.fromkeys(results))


def collect_statistics(groups: Iterable[tuple[tuple, tuple, tuple, object, int]]) -> tuple[Counter, Counter]:
    """Single pass over the (results, fields, distinct results) of each (ZLint output, issuer_dn) group with the
    group's issuer_dn and its number of certificates, in the order of the groups' first certificate: occurrences per
    (result, field, issuer) and certificate count per result.

    Counting each group once with its weight gives the same counters, in the same first-seen order, as counting each
    certificate in certificate_id order: a key is first seen in the first certificate that has it, which is the first
    certificate of its group, and the groups come in the order of their first certificate.
    """
    occurrences = Counter()     # (result, field, issuer) -> count, in first-seen order
    certificates = Counter()    # result -> certificates with at least one field with that result
    for results, fields, distinct_results, issuer_dn, weight in groups:
        for key in zip(results, fields, repeat(issuer_dn)):
            occurrences[key] += weight
        for result in distinct_results:
            certificates[result] += weight
    return occurrences, certificates


def weighted_groups(reader: ZlintReader) -> Iterator[tuple[tuple, tuple, tuple, object, int]]:
    """lints() of the output, issuer_dn and number of certificates of each distinct (output, issuer_dn) pair, in the
    order of their first certificate."""
    # Counter keeps the first-seen order of its keys
    groups = Counter(reader.documents("body_id, issuer_dn", "body_id IS NOT NULL"))
    body_lints = lru_cache(maxsize=BODY_CACHE_SIZE)(lambda body_id: lints(reader.body(body_id)))
    for (body_id, issuer_dn), weight in groups.items():
        yield (*body_lints(body_id), issuer_dn, weight)


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


def _no_results_message(db_type: str, path: Path) -> str:
    hint = (f"run --{db_type}_zlint_check first" if db_type in ZLINT_TYPES
            else "ZLint checks only the leaf and intermediate certificates")
    return f"No ZLint results found in the {db_type} database '{path}' ({hint})."


def _read_statistics(db_type: str, path: Path) -> tuple[Counter, Counter] | None:
    """The statistics of the database's ZLint results; None, after saying why, if there are none."""
    state = database_state(path)
    if state == "outdated":
        print(OutdatedDatabaseError(DatabaseType(db_type), path), file=sys.stderr)
        return None
    if state == "missing":
        print(_no_results_message(db_type, path))
        return None
    if zstandard is None:
        print(f"The Python package 'zstandard' is not installed. {INSTALLER_HINT}", file=sys.stderr)
        return None
    # Read-only: the database is never created or changed here
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        if not has_tables(conn):
            print(_no_results_message(db_type, path))
            return None
        reader = ZlintReader(conn)
        if not reader.has_results():
            print(_no_results_message(db_type, path))
            return None
        return collect_statistics(weighted_groups(reader))
    finally:
        conn.close()


def _database_type(value: str) -> str:
    db_type = LEGACY_NAMES.get(value, value.lower())
    if db_type not in {member.value for member in DatabaseType}:
        raise argparse.ArgumentTypeError(f"unknown certificate type '{value}' (choose leaf, intermediate or root)")
    return db_type


def main(argv: list[str] | None = None) -> int:
    """Read the ZLint results of a certificate database and write the three summary CSVs to the current directory."""
    parser = argparse.ArgumentParser(description="Write the summary CSVs of the ZLint results stored in a certificate "
                                                 "database.")
    parser.add_argument("db_type", nargs="?", default=DEFAULT_TYPE, type=_database_type,
                        help=f"Certificate type: leaf, intermediate or root (default: {DEFAULT_TYPE}).")
    parser.add_argument("--db", type=Path, default=None,
                        help="Path of the certificate database (default: src/analysis/<type>/<type>_certificates.db).")
    args = parser.parse_args(argv)
    path = args.db if args.db is not None else default_db_path(args.db_type)

    statistics = _read_statistics(args.db_type, path)
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
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
