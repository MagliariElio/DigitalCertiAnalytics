from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, NamedTuple

from dao import statistics_facts
from dao.statistics_facts import Facts, Request, Unique
from db.database import DatabaseType

# Admin: Anuar Elio Magliari
# Politecnico di Torino


@dataclass(frozen=True)
class Thresholds:
    """Chart thresholds that depend on the certificate type."""
    top_countries: int          # Countries shown individually, the rest go to 'Others'
    min_validity_count: int     # Min certificates for a validity duration to be shown
    expiration_above: int       # An expiration month is shown above this many certificates
    sct_above: int              # An SCT month is shown above this many SCTs
    top_issuers: int = 20               # Issuers shown individually, the rest go to 'Others'
    top_sct_logs_above: int = 12000     # An SCT log is shown above this many certificates


_THRESHOLDS = {
    DatabaseType.LEAF: Thresholds(top_countries=5, min_validity_count=20, expiration_above=1100, sct_above=20),
    DatabaseType.INTERMEDIATE: Thresholds(top_countries=4, min_validity_count=1, expiration_above=6, sct_above=20),
    DatabaseType.ROOT: Thresholds(top_countries=5, min_validity_count=1, expiration_above=9, sct_above=0),
}

# Validity classes in days as (key, inclusive upper bound; None = unbounded), aligned with the CA/Browser Forum limits
# (398 days since 2020, 825 days before). Negative durations get their own class.
NEGATIVE_VALIDITY = "negative"
VALIDITY_DAY_CLASSES = (("<=90", 90), ("91-200", 200), ("201-398", 398), ("399-825", 825), ("826-1825", 1825),
                        (">1825", None))
_SECONDS_PER_DAY = 86400

# Read-only connections of StatisticsDAO.reading(): page cache (negative = KiB) and memory-mapped reads (clamped by
# SQLite to its compile-time limit; file-backed pages, which the system can reclaim)
READER_PRAGMAS = ("PRAGMA cache_size = -65536", "PRAGMA mmap_size = 2147418112")
# Temporary b-trees and sorts of DISTINCT / GROUP BY on the per-query path (statistics not materialized, see
# materialize()). In memory they are 2.5-3x faster but unbounded: up to 11% of the database file per query (measured:
# 820 MiB on a 7.6 GiB leaf database with 1.96M certificates), and the process keeps that memory after the query. In
# temporary files SQLite keeps at most cache_size of each sort in memory (about 330 MiB per render process whatever the
# size). In memory only for files up to this share of the physical memory.
MEMORY_TEMP_STORE_SHARE = 0.125

# Chart counts tell certificates apart by Subject Key Identifier; those without one (e.g. v1) fall back to the raw
# certificate, otherwise they would all count as one (SKI = ''). The identity is computed in a DISTINCT subquery
# so the full raw is not copied into the GROUP BY sort.
_IDENTITY = f"{statistics_facts.IDENTITY} AS certificate_identity"
_CERTIFICATES = "Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id"
_EXTENSIONS = ("Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id "
               "JOIN Subjects AS s ON c.subject_id = s.subject_id")
# Row sources of the DISTINCT subqueries, with the scan that reads them when the statistics are materialized
_SOURCES = {
    "certificates": (_CERTIFICATES, "certificates"),
    "subjects": ("Subjects AS s JOIN Certificates AS c ON c.subject_id = s.subject_id", "certificates"),
    "extensions": (_EXTENSIONS, "extensions"),
    "policies": ("CertificatePolicies AS p JOIN Extensions AS e ON p.extension_id = e.extension_id "
                 "JOIN Certificates AS c ON e.certificate_id = c.certificate_id "
                 "JOIN Subjects AS s ON c.subject_id = s.subject_id", "policies"),
    "sct_logs": ("SignedCertificateTimestamps AS t INNER JOIN Logs AS l ON t.log_id = l.id "
                 "INNER JOIN Certificates AS c ON t.certificate_id = c.certificate_id "
                 "INNER JOIN Subjects AS s ON c.subject_id = s.subject_id", "sct"),
}
# Materialized rows are aggregated in temporary tables with this count column
_FACTS_COUNT = "facts_count"


class Distinct(NamedTuple):
    """Distinct certificates (by identity) grouped by `columns` ("expression" or "expression AS name")."""
    columns: tuple[str, ...]
    source: str = "certificates"        # key of _SOURCES
    where: str = ""
    group_by: str = ""
    select: str = ""
    having: str = ""
    order_by: str = "count DESC"


def _expression(column: str) -> str:
    """The expression of a column ("expression AS name")."""
    return column.rsplit(" AS ", 1)[0]


def _distinct_count_sql(spec: Distinct, materialized: bool = False) -> str:
    """Count distinct certificates (by identity) grouped by the spec's columns; `materialized`: over the temporary
    table of the materialized rows instead of the DISTINCT subquery."""
    columns = ", ".join(spec.columns)
    group_by = spec.group_by or columns
    where = f" WHERE {spec.where}" if spec.where else ""
    rows = ("temp.facts" if materialized
            else f"(SELECT DISTINCT {columns}, {_IDENTITY} FROM {_SOURCES[spec.source][0]}{where})")
    count = f"SUM({_FACTS_COUNT})" if materialized else "COUNT(certificate_identity)"
    return (f"SELECT {spec.select or group_by}, {count} AS count FROM {rows} "
            f"GROUP BY {group_by}{f' HAVING {spec.having}' if spec.having else ''}"
            f"{f' ORDER BY {spec.order_by}' if spec.order_by else ''}")


def _top_with_others_sql(column: str, source: str, where: str, count: str = "COUNT(*)") -> str:
    """Top N values (N as query parameter) plus the sum of the rest as 'Others'."""
    return f"""
        WITH Counts AS (
            SELECT {column} AS label, {count} AS count FROM {source} WHERE {where}
            GROUP BY {column} ORDER BY count DESC
        ),
        TopCounts AS (SELECT label, count FROM Counts LIMIT ?),
        Others AS (
            SELECT 'Others' AS label, COALESCE(SUM(count), 0) AS count
            FROM Counts WHERE label NOT IN (SELECT label FROM TopCounts)
        )
        SELECT * FROM TopCounts UNION ALL SELECT * FROM Others
    """


def _pairs(rows: list) -> dict:
    return {row[0]: row[1] for row in rows}


def _nonzero_pairs(rows: list) -> dict:
    """Like _pairs, skipping zero counts (e.g. an empty 'Others' row)."""
    return {row[0]: row[1] for row in rows if row[1]}


def _nested_pairs(rows: list) -> dict:
    result = {}
    for row in rows:
        result.setdefault(row[0], {})[row[1]] = row[2]
    return result


def _validity_class_sql() -> str:
    """CASE expression mapping validity_length (seconds) to its VALIDITY_DAY_CLASSES key."""
    bounds = " ".join(f"WHEN validity_length <= {limit * _SECONDS_PER_DAY} THEN '{key}'"
                      for key, limit in VALIDITY_DAY_CLASSES if limit is not None)
    return (f"CASE WHEN validity_length < 0 THEN '{NEGATIVE_VALIDITY}' {bounds} "
            f"ELSE '{VALIDITY_DAY_CLASSES[-1][0]}' END")


def _validity_classes(rows: list) -> dict:
    """Every class in order (zero counts included), or {} when no certificate has a validity length."""
    counts = _pairs(rows)
    result = {key: counts.get(key, 0) for key in (NEGATIVE_VALIDITY, *(key for key, _ in VALIDITY_DAY_CLASSES))}
    return result if any(result.values()) else {}


def _database_file(connection: sqlite3.Connection) -> str:
    """File of the 'main' database; '' for in-memory and temporary databases."""
    for row in connection.execute("PRAGMA database_list").fetchall():
        if row[1] == "main":
            return row[2] or ""
    return ""


def temp_store(path: str) -> str:
    """Where the read-only connections to the database file keep their temporary tables: 'MEMORY' or 'FILE'.

    'FILE' when the file is larger than MEMORY_TEMP_STORE_SHARE of the physical memory, or either size is unknown.
    """
    try:
        memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        size = os.path.getsize(path)
    except (AttributeError, ValueError, OSError):
        return "FILE"
    return "MEMORY" if 0 < memory and size <= memory * MEMORY_TEMP_STORE_SHARE else "FILE"


def _usage_counts(rows: list, ignored: tuple[str, ...] = ()) -> dict:
    """Sum the counts per set of usages (JSON keys), skipping the ignored keys."""
    result = {}
    for row in rows:
        names = json.dumps(", ".join(name for name in json.loads(row[0]).keys() if name not in ignored))
        result[names] = result.get(names, 0) + row[1]     # Different rows can share the same keys
    return result


# ---------------------------------------------------------------- statistics

_DISTINCT = {   # get_* methods counting distinct certificates; validity statistics first (read together)
    "get_validity_days_distribution": Distinct(
        (f"{_validity_class_sql()} AS validity_class",), where="c.validity_length IS NOT NULL",
        group_by="validity_class", order_by=""),
    "get_certificate_expiration_trend": Distinct(
        ("strftime('%Y-%m', validity_end) AS month",), where="validity_end IS NOT NULL", group_by="month",
        having="count > ?", order_by="month ASC"),
    "get_signature_algorithm_distribution": Distinct(("signature_algorithm",), where="signature_algorithm IS NOT NULL"),
    "get_key_algorithm_length_distribution": Distinct(
        ("key_algorithm", "key_length"), order_by="key_algorithm, key_length",
        where="key_algorithm IS NOT NULL AND key_algorithm <> '' AND key_length IS NOT NULL AND key_length <> ''"),
    "get_count_critical_non_critical_extensions": Distinct(("authority_info_access_is_critical",)),
    "get_self_signed_vs_ca_signed": Distinct(
        ("self_signed",), select="CASE WHEN self_signed = 1 THEN 'True' ELSE 'False' END AS is_self_signed", order_by=""),
    "get_validation_level_distribution": Distinct(("validation_level",), order_by=""),
    "get_certificate_version_distribution": Distinct(("version",), order_by=""),
    "get_signature_validity_distribution": Distinct(("signature_valid",)),
    "get_critical_vs_non_critical_san_extensions": Distinct(("subject_alt_name_is_critical",), "subjects"),
    "get_key_usage_distribution": Distinct(("key_usage",), "extensions"),
    "get_critical_vs_non_critical_key_usage": Distinct(("key_usage_is_critical",), "extensions"),
    "get_extended_key_usage_distribution": Distinct(("extended_key_usage",), "extensions"),
    "get_critical_vs_non_critical_extended_key_usage": Distinct(("extended_key_usage_is_critical",), "extensions"),
    "get_basic_constraints_distribution": Distinct(("basic_constraints",), "extensions"),
    "get_critical_vs_non_critical_crl_distribution": Distinct(("crl_distr_point_is_critical",), "extensions"),
    "get_critical_vs_non_critical_cp_policies": Distinct(("is_cp_critical",), "policies"),
    "get_top_sct_logs": Distinct(("description",), "sct_logs", having="count > ?"),
}
# Validity in whole years: SQLite integer division truncates toward zero (-100/31536000 = 0), so negative durations
# are counted apart
_NEGATIVE_VALIDITY = "validity_length < 0"
_VALIDITY_YEARS = Distinct(("validity_length/31536000 AS years",),
                           where="c.validity_length IS NOT NULL AND validity_length >= 0")

_ISSUERS = "Certificates INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id"
_ORGANIZATION = "Issuers.organization"
_ORGANIZATION_WHERE = "Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''"
_COUNTRY = "Issuers.country"
_COUNTRY_WHERE = "TRIM(Issuers.country) <> '' AND TRIM(Issuers.country) <> '--'"
_SCT_MONTH = "strftime('%Y-%m', datetime(timestamp, 'unixepoch'))"
_ERRORS_BY_STATUS = "SELECT status, COUNT(*) AS count FROM Errors GROUP BY status"

# Statistics needing each materialized row set besides _DISTINCT
_PLAIN = {
    "issuers": ("get_issuer_certificate_count", "get_issuer_distribution", "get_certificates_per_country"),
    "ocsp": ("get_ocsp_status_distribution",),
    "errors": ("get_status_analysis",),
    "sct_month": ("get_signed_certificate_timestamp_trend",),
    "sct_operators": ("get_top_sct_log_operators",),
    "sct_per_certificate": ("get_sct_count_per_certificate",),
}


def _facts_request(names: set[str]) -> Request:
    """Row sets to materialize for the given get_* methods."""
    request = Request()
    if "get_validity_duration_distribution" in names:
        request.unique["validity_negative"] = Unique("certificates", (), _NEGATIVE_VALIDITY)
        request.unique["validity_years"] = Unique(
            "certificates", tuple(_expression(c) for c in _VALIDITY_YEARS.columns), _VALIDITY_YEARS.where)
    for name, spec in _DISTINCT.items():
        if name in names:
            request.unique[name] = Unique(_SOURCES[spec.source][1], tuple(_expression(c) for c in spec.columns),
                                          spec.where)
    wanted = {key for key, methods in _PLAIN.items() if names.intersection(methods)}
    request.ocsp = "ocsp_check" if "ocsp" in wanted else ""
    request.issuers = (_ORGANIZATION, _COUNTRY) if "issuers" in wanted else ("", "")
    request.sct_month = _SCT_MONTH if "sct_month" in wanted else ""
    request.sct_operator = "lo.name" if "sct_operators" in wanted else ""
    request.sct_per_certificate = "sct_per_certificate" in wanted
    request.errors_sql = _ERRORS_BY_STATUS if "errors" in wanted else ""
    return request


def statistic_names() -> list[str]:
    """Every get_* method of StatisticsDAO."""
    return sorted(name for name in dir(StatisticsDAO) if name.startswith("get_"))


_ISSUER_FACTS = f"SELECT Issuers.organization AS organization, 0 AS {_FACTS_COUNT} FROM main.Issuers AS Issuers"
_COUNTRY_FACTS = f"SELECT Issuers.country AS country, 0 AS {_FACTS_COUNT} FROM main.Issuers AS Issuers"


def _validity_years_sql(materialized: bool = False) -> str:
    """Certificates per validity in whole years, negative durations as -1 (first row, always present)."""
    if materialized:
        negative, years, count = "temp.facts_negative", "temp.facts", f"SUM({_FACTS_COUNT})"
    else:
        negative = f"(SELECT DISTINCT {_IDENTITY} FROM {_CERTIFICATES} WHERE {_NEGATIVE_VALIDITY})"
        years = f"(SELECT DISTINCT {_VALIDITY_YEARS.columns[0]}, {_IDENTITY} FROM {_CERTIFICATES} " \
                f"WHERE {_VALIDITY_YEARS.where})"
        count = "COUNT(certificate_identity)"
    # The first SELECT has no GROUP BY and always returns a row: (-1, 0) is filtered out by _years
    return (f"SELECT -1, {count} AS count FROM {negative} UNION ALL "
            f"SELECT years, {count} AS count FROM {years} GROUP BY years HAVING count >= ?")


def _years(rows: list) -> dict:
    return {row[0]: row[1] for row in rows if row[0] is not None and row[1] > 0}


class StatisticsDAO:
    """Chart statistics read from a certificate database."""

    def __init__(self, connection: sqlite3.Connection, certificate_type: DatabaseType):
        self._conn = connection
        self.certificate_type = certificate_type
        self._thresholds = _THRESHOLDS[certificate_type]
        self._facts: Facts | None = None

    @property
    def thresholds(self) -> Thresholds:
        """Display thresholds applied by the queries of this certificate type."""
        return self._thresholds

    def shared_database_file(self) -> str | None:
        """File holding this DAO's data that other connections, also in other processes, can read; None otherwise.

        None for in-memory and temporary databases, while this connection has uncommitted changes (other connections
        would not see them) and when the file cannot be opened read-only.
        """
        path = None if self._conn.in_transaction else _database_file(self._conn)
        if not path:
            return None
        try:
            with StatisticsDAO.reading(path, self.certificate_type) as reader:
                reader._conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        except sqlite3.Error as e:
            logging.warning("Read-only connection to the database not available (%s): statistics computed sequentially.", e)
            return None
        return path

    @classmethod
    @contextmanager
    def reading(cls, path: str, certificate_type: DatabaseType) -> Iterator[StatisticsDAO]:
        """DAO on a new read-only connection to the database file, tuned for aggregate queries; closed on exit."""
        with closing(sqlite3.connect(f"{Path(path).as_uri()}?mode=ro", uri=True)) as connection:
            for pragma in (*READER_PRAGMAS, f"PRAGMA temp_store = {temp_store(path)}"):
                connection.execute(pragma)
            yield cls(connection, certificate_type)

    def materialize(self, names: list[str] | None = None, executor=None, workers: int = 1) -> bool:
        """Compute the statistics of the get_* methods `names` (default: all) reading each table once; those methods
        then return them without querying the database again. The scans run in `executor` when given.

        Results are identical to the queries'. False (and the queries are used) when it is not possible: in-memory
        database, uncommitted changes or an error while reading.
        """
        path = None if self._conn.in_transaction else _database_file(self._conn)
        if not path:
            return False
        try:
            self._facts = statistics_facts.collect(path, _facts_request(set(names or statistic_names())), executor,
                                                   workers)
        except Exception as e:     # any failure: the queries give the same results
            logging.warning("Statistics not materialized (%s): running the individual queries.", e)
            self._facts = None
            return False
        return True

    def _materialized(self, rows_key: str | tuple[str, ...], tables: list[tuple[str, ...]], sql: str,
                      params: tuple = (), build: Callable[[list], dict] = _pairs) -> dict | None:
        """Run `sql` over temporary tables holding materialized rows; None when they are not materialized.

        `tables`: (name, SELECT giving the column names and types, from the table the rows come from[, indexed
        columns]) per row set. An index gives the query the plan of the original one where the order of equal rows
        depends on it.
        """
        keys = (rows_key,) if isinstance(rows_key, str) else rows_key
        if self._facts is None or any(key not in self._facts.rows for key in keys):
            return None
        created = []
        try:
            for (table, select, *index), key in zip(tables, keys):
                self._conn.execute(f"DROP TABLE IF EXISTS temp.{table}")
                self._conn.execute(f"CREATE TEMP TABLE {table} AS {select} LIMIT 0")
                created.append(table)
                width = len(self._conn.execute(f"PRAGMA temp.table_info({table})").fetchall())
                self._conn.executemany(f"INSERT INTO temp.{table} VALUES ({', '.join('?' * width)})",
                                       self._facts.rows[key])
                if index:
                    self._conn.execute(f"CREATE INDEX temp.facts_index ON {table}({index[0]})")
        except sqlite3.Error as e:
            logging.debug("Materialized rows not usable (%s)", e)
            self._drop(created)
            return None
        try:
            return self._query(sql, params, build)
        finally:
            self._drop(created)

    def _drop(self, tables: list[str]) -> None:
        for table in tables:
            self._conn.execute(f"DROP TABLE IF EXISTS temp.{table}")
        self._conn.commit()

    def _distinct(self, name: str, params: tuple = (), build: Callable[[list], dict] = _pairs) -> dict:
        """Run a _DISTINCT statistic, from the materialized rows when available."""
        spec = _DISTINCT[name]
        columns = "".join(f"{column}, " for column in spec.columns)
        result = self._materialized(name, [("facts", f"SELECT {columns}0 AS {_FACTS_COUNT} FROM "
                                                     f"{_SOURCES[spec.source][0]}")],
                                    _distinct_count_sql(spec, materialized=True), params, build)
        return self._query(_distinct_count_sql(spec), params, build) if result is None else result

    def _query(self, sql: str, params: tuple = (), build: Callable[[list], dict] = _pairs) -> dict:
        """Run the query and build the result dict; {} on error."""
        try:
            rows = self._conn.execute(sql, params).fetchall()
            logging.debug("Rows returned: %d", len(rows))
            result = build(rows)
            logging.debug("Entries found: %d", len(result))
            return result
        except Exception as e:
            logging.error("Statistics query failed: %s", str(e))
            return {}

    def get_issuer_certificate_count(self) -> dict:
        """Certificates per issuer organization (top issuers plus 'Others')."""
        params = (self._thresholds.top_issuers,)
        # Indexed like Issuers(organization): equal counts keep the order of the plot index's plan
        result = self._materialized("organizations", [("Issuers", _ISSUER_FACTS, f"organization, {_FACTS_COUNT}")],
                                    _top_with_others_sql(_ORGANIZATION, "Issuers", _ORGANIZATION_WHERE,
                                                         f"SUM({_FACTS_COUNT})"), params, _nonzero_pairs)
        return self._query(_top_with_others_sql(_ORGANIZATION, _ISSUERS, _ORGANIZATION_WHERE), params,
                           _nonzero_pairs) if result is None else result

    def get_issuer_distribution(self) -> dict:
        """Certificates per issuer organization for every issuer, most frequent first (same rows as above)."""
        sql = """
            SELECT Issuers.organization, {count} AS count
            FROM {source}
            WHERE {where}
            GROUP BY Issuers.organization
            ORDER BY count DESC, Issuers.organization
        """
        result = self._materialized("organizations", [("Issuers", _ISSUER_FACTS)], sql.format(
            count=f"SUM({_FACTS_COUNT})", source="Issuers", where=_ORGANIZATION_WHERE))
        return self._query(sql.format(count="COUNT(*)", source=_ISSUERS, where=_ORGANIZATION_WHERE)) \
            if result is None else result

    def get_certificates_per_country(self) -> dict:
        """Certificates per issuer country (top countries plus 'Others')."""
        params = (self._thresholds.top_countries,)
        result = self._materialized("countries", [("Issuers", _COUNTRY_FACTS)], _top_with_others_sql(
            _COUNTRY, "Issuers", _COUNTRY_WHERE, f"SUM({_FACTS_COUNT})"), params, _nonzero_pairs)
        return self._query(_top_with_others_sql(_COUNTRY, "Issuers", _COUNTRY_WHERE), params, _nonzero_pairs) \
            if result is None else result

    def get_validity_duration_distribution(self) -> dict:
        """Certificates per validity duration in years; negative durations go to -1."""
        params, build = (self._thresholds.min_validity_count,), _years
        result = self._materialized(
            ("validity_negative", "validity_years"),
            [("facts_negative", f"SELECT 0 AS {_FACTS_COUNT} FROM {_CERTIFICATES}"),
             ("facts", f"SELECT {_VALIDITY_YEARS.columns[0]}, 0 AS {_FACTS_COUNT} FROM {_CERTIFICATES}")],
            _validity_years_sql(materialized=True), params, build)
        return self._query(_validity_years_sql(), params, build) if result is None else result

    def get_validity_days_distribution(self) -> dict:
        """Certificates per validity class in days (VALIDITY_DAY_CLASSES order, NEGATIVE_VALIDITY first)."""
        return self._distinct("get_validity_days_distribution", build=_validity_classes)

    def get_certificate_expiration_trend(self) -> dict:
        """Certificates expiring per month."""
        return self._distinct("get_certificate_expiration_trend", (self._thresholds.expiration_above,))

    def get_signature_algorithm_distribution(self) -> dict:
        """Certificates per signature algorithm."""
        return self._distinct("get_signature_algorithm_distribution")

    def get_key_algorithm_length_distribution(self) -> dict:
        """Certificates per key algorithm and key length."""
        return self._distinct("get_key_algorithm_length_distribution", build=_nested_pairs)

    def get_ocsp_status_distribution(self) -> dict:
        """Certificates per OCSP status (Good, Revoked, ...)."""
        sql = "SELECT ocsp_check, {count} AS count FROM {source} GROUP BY ocsp_check"
        result = self._materialized("ocsp", [("Certificates", f"SELECT ocsp_check, 0 AS {_FACTS_COUNT} FROM "
                                                              "main.Certificates")],
                                    sql.format(count=f"SUM({_FACTS_COUNT})", source="Certificates"))
        return self._query(sql.format(count="COUNT(*)", source="Certificates")) if result is None else result

    def get_count_critical_non_critical_extensions(self) -> dict:
        """Certificates with a critical vs non-critical AIA extension."""
        return self._distinct("get_count_critical_non_critical_extensions")

    def get_self_signed_vs_ca_signed(self) -> dict:
        """Self-signed vs CA-signed certificates."""
        return self._distinct("get_self_signed_vs_ca_signed")

    def get_validation_level_distribution(self) -> dict:
        """Certificates per validation level."""
        return self._distinct("get_validation_level_distribution")

    def get_certificate_version_distribution(self) -> dict:
        """Certificates per X.509 version."""
        return self._distinct("get_certificate_version_distribution")

    def get_signature_validity_distribution(self) -> dict:
        """Certificates per signature validity."""
        return self._distinct("get_signature_validity_distribution")

    def get_status_analysis(self) -> dict:
        """Successful certificates and scan errors per status."""
        sql = """
            SELECT 'success', {count} AS count FROM Certificates
            UNION ALL
            SELECT status, {count} AS count FROM Errors GROUP BY status
        """
        result = self._materialized(
            ("certificates", "errors"), [("Certificates", f"SELECT 0 AS {_FACTS_COUNT}"),
                                         ("Errors", f"SELECT status, 0 AS {_FACTS_COUNT} FROM main.Errors")],
            sql.format(count=f"SUM({_FACTS_COUNT})"))
        return self._query(sql.format(count="COUNT(*)")) if result is None else result

    def get_key_usage_distribution(self) -> dict:
        """Certificates per key usage set."""
        return self._distinct("get_key_usage_distribution", build=lambda rows: _usage_counts(rows, ignored=("value",)))

    def get_critical_vs_non_critical_key_usage(self) -> dict:
        """Critical vs non-critical key usage."""
        return self._distinct("get_critical_vs_non_critical_key_usage")

    def get_extended_key_usage_distribution(self) -> dict:
        """Certificates per extended key usage set."""
        return self._distinct("get_extended_key_usage_distribution", build=_usage_counts)

    def get_critical_vs_non_critical_extended_key_usage(self) -> dict:
        """Critical vs non-critical extended key usage."""
        return self._distinct("get_critical_vs_non_critical_extended_key_usage")

    def get_basic_constraints_distribution(self) -> dict:
        """Certificates per Basic Constraints value."""
        return self._distinct("get_basic_constraints_distribution")

    def get_critical_vs_non_critical_crl_distribution(self) -> dict:
        """Critical vs non-critical CRL Distribution Points."""
        return self._distinct("get_critical_vs_non_critical_crl_distribution")

    def get_signed_certificate_timestamp_trend(self) -> dict:
        """SCTs per month."""
        sql = """
            SELECT {month} AS month_year, {count} AS count
            FROM {source}
            GROUP BY month_year
            HAVING count > ?
            ORDER BY month_year ASC
        """
        params = (self._thresholds.sct_above,)
        result = self._materialized(
            "sct_month", [("facts", f"SELECT {_SCT_MONTH} AS month_year, 0 AS {_FACTS_COUNT} "
                                    "FROM main.SignedCertificateTimestamps")],
            sql.format(month="month_year", count=f"SUM({_FACTS_COUNT})", source="temp.facts"), params)
        return self._query(sql.format(month=_SCT_MONTH, count="COUNT(*)", source="SignedCertificateTimestamps"),
                           params) if result is None else result

    def get_sct_count_per_certificate(self) -> dict:
        """Certificates per number of SCTs."""
        result = self._materialized(
            "sct_per_certificate", [("facts", f"SELECT NULL AS count_sct, NULL AS {_FACTS_COUNT}")],
            f"SELECT count_sct, SUM({_FACTS_COUNT}) AS certificate_count FROM temp.facts GROUP BY count_sct "
            "ORDER BY count_sct ASC")
        return self._query("""
            SELECT count_sct, COUNT(*) AS certificate_count
            FROM (
                SELECT COUNT(t.certificate_id) AS count_sct
                FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps AS t ON t.certificate_id = c.certificate_id
                GROUP BY c.certificate_id
            )
            GROUP BY count_sct
            ORDER BY count_sct ASC
        """) if result is None else result

    def get_top_sct_logs(self) -> dict:
        """Certificates per SCT log, most used logs only."""
        return self._distinct("get_top_sct_logs", (self._thresholds.top_sct_logs_above,))

    def get_top_sct_log_operators(self) -> dict:
        """SCTs per log operator, most used first."""
        result = self._materialized(
            "sct_operators", [("facts", f"SELECT lo.name AS name, 0 AS {_FACTS_COUNT} FROM main.LogsOperators AS lo")],
            f"SELECT name, SUM({_FACTS_COUNT}) AS count FROM temp.facts GROUP BY name ORDER BY count DESC")
        return self._query("""
            SELECT lo.name, COUNT(*) AS count
            FROM SignedCertificateTimestamps AS t INNER JOIN Logs AS l ON t.log_id = l.id
            INNER JOIN LogsOperators AS lo ON l.operator_id = lo.id
            GROUP BY lo.name
            ORDER BY count DESC
        """) if result is None else result

    def get_critical_vs_non_critical_san_extensions(self) -> dict:
        """Critical vs non-critical Subject Alternative Name extensions."""
        return self._distinct("get_critical_vs_non_critical_san_extensions")

    def get_critical_vs_non_critical_cp_policies(self) -> dict:
        """Critical vs non-critical certificate policies."""
        return self._distinct("get_critical_vs_non_critical_cp_policies")
