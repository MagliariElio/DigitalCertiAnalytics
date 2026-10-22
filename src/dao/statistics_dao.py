from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Callable

from db.database import DatabaseType

# Admin: Anuar Elio Magliari
# Politecnico di Torino


@dataclass(frozen=True)
class _Thresholds:
    """Plot thresholds that depend on the certificate type."""
    top_countries: int          # Countries shown individually, the rest go to 'Others'
    min_validity_count: int     # Min certificates for a validity duration to be shown
    expiration_above: int       # An expiration month is shown above this many certificates
    sct_above: int              # An SCT month is shown above this many SCTs


_THRESHOLDS = {
    DatabaseType.LEAF: _Thresholds(top_countries=5, min_validity_count=20, expiration_above=1100, sct_above=20),
    DatabaseType.INTERMEDIATE: _Thresholds(top_countries=4, min_validity_count=1, expiration_above=6, sct_above=20),
    DatabaseType.ROOT: _Thresholds(top_countries=5, min_validity_count=1, expiration_above=9, sct_above=0),
}
_TOP_ISSUERS = 20               # Issuers shown individually, the rest go to 'Others'
_TOP_SCT_LOGS_ABOVE = 12000     # An SCT log is shown above this many certificates

# Plot counts tell certificates apart by Subject Key Identifier; those without one (e.g. v1) fall back to the raw
# certificate, otherwise they would all count as one (SKI = ''). The identity is computed in a DISTINCT subquery
# so the full raw is not copied into the GROUP BY sort.
_IDENTITY = "COALESCE(NULLIF(s.subject_key_id, ''), c.raw) AS certificate_identity"
_CERTIFICATES = "Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id"
_EXTENSIONS = ("Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id "
               "JOIN Subjects AS s ON c.subject_id = s.subject_id")


def _distinct_count_sql(columns: str, source: str = _CERTIFICATES, where: str = "", group_by: str = "",
                        select: str = "", having: str = "", order_by: str = "count DESC") -> str:
    """Count distinct certificates (by identity) grouped by the given columns."""
    group_by = group_by or columns
    return (f"SELECT {select or group_by}, COUNT(certificate_identity) AS count "
            f"FROM (SELECT DISTINCT {columns}, {_IDENTITY} FROM {source}{f' WHERE {where}' if where else ''}) "
            f"GROUP BY {group_by}{f' HAVING {having}' if having else ''}{f' ORDER BY {order_by}' if order_by else ''}")


def _top_with_others_sql(column: str, source: str, where: str) -> str:
    """Top N values (N as query parameter) plus the sum of the rest as 'Others'."""
    return f"""
        WITH Counts AS (
            SELECT {column} AS label, COUNT(*) AS count FROM {source} WHERE {where}
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


def _usage_counts(rows: list, ignored: tuple[str, ...] = ()) -> dict:
    """Sum the counts per set of usages (JSON keys), skipping the ignored keys."""
    result = {}
    for row in rows:
        names = json.dumps(", ".join(name for name in json.loads(row[0]).keys() if name not in ignored))
        result[names] = result.get(names, 0) + row[1]     # Different rows can share the same keys
    return result


class StatisticsDAO:
    """Plot statistics read from a certificate database."""

    def __init__(self, connection: sqlite3.Connection, certificate_type: DatabaseType):
        self._conn = connection
        self.certificate_type = certificate_type
        self._thresholds = _THRESHOLDS[certificate_type]

    def _query(self, sql: str, params: tuple = (), build: Callable[[list], dict] = _pairs) -> dict:
        """Run the query and build the result dict; {} on error."""
        try:
            rows = self._conn.execute(sql, params).fetchall()
            logging.debug("Risultati ottenuti: %d", len(rows))
            result = build(rows)
            logging.debug("Totale trovati: %d", len(result))
            return result
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}

    def get_issuer_certificate_count(self) -> dict:
        """Certificates per issuer organization (top issuers plus 'Others')."""
        return self._query(_top_with_others_sql(
            "Issuers.organization", "Certificates INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id",
            "Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''"
        ), (_TOP_ISSUERS,), _nonzero_pairs)

    def get_certificates_per_country(self) -> dict:
        """Certificates per issuer country (top countries plus 'Others')."""
        return self._query(_top_with_others_sql(
            "Issuers.country", "Issuers", "TRIM(Issuers.country) <> '' AND TRIM(Issuers.country) <> '--'"
        ), (self._thresholds.top_countries,), _nonzero_pairs)

    def get_validity_duration_distribution(self) -> dict:
        """Certificates per validity duration in years; negative durations go to -1."""
        # SQLite integer division truncates toward zero (-100/31536000 = 0), so negative durations need their own
        # bucket. The first SELECT has no GROUP BY and always returns a row: (-1, 0) is filtered out below.
        return self._query(f"""
            SELECT -1, COUNT(certificate_identity) AS count
            FROM (SELECT DISTINCT {_IDENTITY} FROM {_CERTIFICATES} WHERE validity_length < 0)
            UNION ALL
            SELECT years, COUNT(certificate_identity) AS count
            FROM (
                SELECT DISTINCT validity_length/31536000 AS years, {_IDENTITY}
                FROM {_CERTIFICATES}
                WHERE c.validity_length IS NOT NULL AND validity_length >= 0
            )
            GROUP BY years
            HAVING count >= ?
        """, (self._thresholds.min_validity_count,),
            lambda rows: {row[0]: row[1] for row in rows if row[0] is not None and row[1] > 0})

    def get_certificate_expiration_trend(self) -> dict:
        """Certificates expiring per month."""
        return self._query(_distinct_count_sql(
            "strftime('%Y-%m', validity_end) AS month", where="validity_end IS NOT NULL", group_by="month",
            having="count > ?", order_by="month ASC"
        ), (self._thresholds.expiration_above,))

    def get_signature_algorithm_distribution(self) -> dict:
        """Certificates per signature algorithm."""
        return self._query(_distinct_count_sql("signature_algorithm", where="signature_algorithm IS NOT NULL"))

    def get_key_algorithm_length_distribution(self) -> dict:
        """Certificates per key algorithm and key length."""
        return self._query(_distinct_count_sql(
            "key_algorithm, key_length", order_by="key_algorithm, key_length",
            where="key_algorithm IS NOT NULL AND key_algorithm <> '' AND key_length IS NOT NULL AND key_length <> ''"
        ), build=_nested_pairs)

    def get_ocsp_status_distribution(self) -> dict:
        """Certificates per OCSP status (Good, Revoked, ...)."""
        return self._query("SELECT ocsp_check, COUNT(*) AS count FROM Certificates GROUP BY ocsp_check")

    def get_count_critical_non_critical_extensions(self) -> dict:
        """Certificates with a critical vs non-critical AIA extension."""
        return self._query(_distinct_count_sql("authority_info_access_is_critical"))

    def get_self_signed_vs_ca_signed(self) -> dict:
        """Self-signed vs CA-signed certificates."""
        return self._query(_distinct_count_sql(
            "self_signed", select="CASE WHEN self_signed = 1 THEN 'True' ELSE 'False' END AS is_self_signed", order_by=""
        ))

    def get_validation_level_distribution(self) -> dict:
        """Certificates per validation level."""
        return self._query(_distinct_count_sql("validation_level", order_by=""))

    def get_certificate_version_distribution(self) -> dict:
        """Certificates per X.509 version."""
        return self._query(_distinct_count_sql("version", order_by=""))

    def get_signature_validity_distribution(self) -> dict:
        """Certificates per signature validity."""
        return self._query(_distinct_count_sql("signature_valid"))

    def get_status_analysis(self) -> dict:
        """Successful certificates and scan errors per status."""
        return self._query("""
            SELECT 'success', COUNT(*) AS count FROM Certificates
            UNION ALL
            SELECT status, COUNT(*) AS count FROM Errors GROUP BY status
        """)

    def get_key_usage_distribution(self) -> dict:
        """Certificates per key usage set."""
        return self._query(_distinct_count_sql("key_usage", source=_EXTENSIONS),
                           build=lambda rows: _usage_counts(rows, ignored=("value",)))

    def get_critical_vs_non_critical_key_usage(self) -> dict:
        """Critical vs non-critical key usage."""
        return self._query(_distinct_count_sql("key_usage_is_critical", source=_EXTENSIONS))

    def get_extended_key_usage_distribution(self) -> dict:
        """Certificates per extended key usage set."""
        return self._query(_distinct_count_sql("extended_key_usage", source=_EXTENSIONS), build=_usage_counts)

    def get_critical_vs_non_critical_extended_key_usage(self) -> dict:
        """Critical vs non-critical extended key usage."""
        return self._query(_distinct_count_sql("extended_key_usage_is_critical", source=_EXTENSIONS))

    def get_basic_constraints_distribution(self) -> dict:
        """Certificates per Basic Constraints value."""
        return self._query(_distinct_count_sql("basic_constraints", source=_EXTENSIONS))

    def get_critical_vs_non_critical_crl_distribution(self) -> dict:
        """Critical vs non-critical CRL Distribution Points."""
        return self._query(_distinct_count_sql("crl_distr_point_is_critical", source=_EXTENSIONS))

    def get_signed_certificate_timestamp_trend(self) -> dict:
        """SCTs per month."""
        return self._query("""
            SELECT strftime('%Y-%m', datetime(timestamp, 'unixepoch')) AS month_year, COUNT(*) AS count
            FROM SignedCertificateTimestamps
            GROUP BY month_year
            HAVING count > ?
            ORDER BY month_year ASC
        """, (self._thresholds.sct_above,))

    def get_sct_count_per_certificate(self) -> dict:
        """Certificates per number of SCTs."""
        return self._query("""
            SELECT count_sct, COUNT(*) AS certificate_count
            FROM (
                SELECT COUNT(t.certificate_id) AS count_sct
                FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps AS t ON t.certificate_id = c.certificate_id
                GROUP BY c.certificate_id
            )
            GROUP BY count_sct
            ORDER BY count_sct ASC
        """)

    def get_top_sct_logs(self) -> dict:
        """Certificates per SCT log, most used logs only."""
        return self._query(_distinct_count_sql(
            "description", having="count > ?",
            source=("SignedCertificateTimestamps AS t INNER JOIN Logs AS l ON t.log_id = l.id "
                    "INNER JOIN Certificates AS c ON t.certificate_id = c.certificate_id "
                    "INNER JOIN Subjects AS s ON c.subject_id = s.subject_id")
        ), (_TOP_SCT_LOGS_ABOVE,))

    def get_top_sct_log_operators(self) -> dict:
        """SCTs per log operator, most used first."""
        return self._query("""
            SELECT lo.name, COUNT(*) AS count
            FROM SignedCertificateTimestamps AS t INNER JOIN Logs AS l ON t.log_id = l.id
            INNER JOIN LogsOperators AS lo ON l.operator_id = lo.id
            GROUP BY lo.name
            ORDER BY count DESC
        """)

    def get_critical_vs_non_critical_san_extensions(self) -> dict:
        """Critical vs non-critical Subject Alternative Name extensions."""
        return self._query(_distinct_count_sql(
            "subject_alt_name_is_critical", source="Subjects AS s JOIN Certificates AS c ON c.subject_id = s.subject_id"
        ))

    def get_critical_vs_non_critical_cp_policies(self) -> dict:
        """Critical vs non-critical certificate policies."""
        return self._query(_distinct_count_sql(
            "is_cp_critical",
            source=("CertificatePolicies AS p JOIN Extensions AS e ON p.extension_id = e.extension_id "
                    "JOIN Certificates AS c ON e.certificate_id = c.certificate_id "
                    "JOIN Subjects AS s ON c.subject_id = s.subject_id")
        ))
