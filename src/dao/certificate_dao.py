from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterator

from cryptography.x509.extensions import UserNotice
from cryptography.x509.oid import ExtensionOID

from bean.certificate import Certificate
from db.database import DatabaseType
from utils.chain_utils import (count_intermediates_up_to_root, find_raw_cert_issuer, reorder_signature_algorithm,
                               verify_signature)

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


def _without_user_notices(qualifiers: list | None) -> str:
    """JSON of the policy qualifiers without UserNotice objects."""
    return json.dumps([qualifier for qualifier in qualifiers or [] if not isinstance(qualifier, UserNotice)])


def _joined(values: list[str]) -> str:
    """Join attribute values, replacing characters not encodable in UTF-8."""
    return ', '.join(values).encode('utf-8', errors='replace').decode('utf-8')


class CertificateDAO:
    """Certificate data access: zgrab2 JSON inserts, batch iteration and plot statistics."""

    def __init__(self, connection: sqlite3.Connection, certificate_type: DatabaseType):
        self._conn = connection
        self._cursor = connection.cursor()
        self.certificate_type = certificate_type
        self._thresholds = _THRESHOLDS[certificate_type]

    # ------------------------------------------------------------------ insertion

    def insert_sct_logs(self, log_list: dict) -> None:
        """Insert the SCT log operators and logs, plus the 'unknown' operator for logs missing from the list."""
        for operator in log_list.get("operators", []):
            operator_id = self._insert_log_operator(operator.get("name", ""), ', '.join(operator.get("email", [])))
            # Newer log lists also include "tiled" logs (Static CT API)
            for log in operator.get("logs", []) + operator.get("tiled_logs", []):
                self._insert_log(operator_id, log)
        self._insert_log_operator("unknown", "")

    def insert_error_row(self, json_row: dict) -> None:
        """Insert a scan error row (Leaf only)."""
        domain = json_row.get("domain", "")
        tls = json_row.get("data", {}).get("tls", {})
        timestamp = tls.get("timestamp", "")
        self._cursor.execute("""
            INSERT INTO Errors (domain, status, protocol, timestamp, error_message, download_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain, tls.get("status", ""), tls.get("protocol", ""), timestamp, tls.get("error", ""), timestamp))
        logging.debug("Errore inserito per dominio: %s", domain)

    def process_insert_certificate(self, json_row: dict, certificate: dict, chain: list[dict],
                                   certificates_emitted_up_to: int) -> None:
        """Insert the certificate with issuer, subject, extensions, SCTs and policies; chain is the chain above it."""
        parsed = certificate.get("parsed", {})
        # A chain certificate without raw invalidates the whole row (KeyError), as in previous versions
        raw = certificate.get("raw") if self.certificate_type is DatabaseType.LEAF else certificate["raw"]
        digital_certificate = Certificate(raw)
        extensions = parsed.get("extensions", {})

        issuer_id = self._insert_issuer(parsed, chain)
        subject_id = self._insert_subject(parsed, digital_certificate)
        certificate_id = self._insert_certificate(json_row, certificate, parsed, chain, digital_certificate,
                                                  issuer_id, subject_id, certificates_emitted_up_to)
        extension_id = self._insert_extensions(certificate_id, extensions, digital_certificate)
        self._insert_signed_certificate_timestamps(certificate_id, extensions)

        policies = digital_certificate.certificate_policies()
        if policies is not None:
            self._cursor.executemany("""
                INSERT INTO CertificatePolicies (extension_id, policy_identifier, cps, policy_qualifiers, is_cp_critical)
                VALUES (?, ?, ?, ?, ?)
            """, [(extension_id, policy['policy_identifier'], _without_user_notices(policy['cps']),
                   _without_user_notices(policy['policy_qualifiers']), policy['is_cp_critical']) for policy in policies])

    def _insert_issuer(self, parsed: dict, chain: list[dict]) -> int:
        """Insert the issuer, with its raw certificate when found in the chain, and return its id."""
        issuer = parsed.get("issuer", {})
        issuer_dn = parsed.get("issuer_dn", "")
        self._cursor.execute("""
            INSERT INTO Issuers (common_name, organization, country, issuer_dn, locality, province,
                organizational_unit, authority_key_id, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _joined(issuer.get("common_name", [])), _joined(issuer.get("organization", [])),
            _joined(issuer.get("country", [])), issuer_dn, ', '.join(issuer.get("locality", [])),
            ', '.join(issuer.get("province", [])), ', '.join(issuer.get("organizational_unit", [])),
            parsed.get("extensions", {}).get("authority_key_id", ""), find_raw_cert_issuer(chain, issuer_dn)
        ))
        return self._cursor.lastrowid

    def _insert_subject(self, parsed: dict, digital_certificate: Certificate) -> int:
        extensions = parsed.get("extensions", {})
        self._cursor.execute("""
            INSERT INTO Subjects (common_name, subject_dn, subject_key_id, subject_alt_name, subject_alt_name_is_critical)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ', '.join(parsed.get("subject", {}).get("common_name", [])), parsed.get("subject_dn", ""),
            extensions.get("subject_key_id", ""), json.dumps(extensions.get("subject_alt_name", {})),
            digital_certificate.extension_criticality(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        ))
        return self._cursor.lastrowid

    def _insert_certificate(self, json_row: dict, certificate: dict, parsed: dict, chain: list[dict],
                            digital_certificate: Certificate, issuer_id: int, subject_id: int,
                            certificates_emitted_up_to: int) -> int:
        tls = json_row.get("data", {}).get("tls", {})
        handshake_log = tls.get("result", {}).get("handshake_log", {})
        download_date = tls["timestamp"] if "timestamp" in tls else datetime.now().isoformat()
        subject_key_info = parsed.get("subject_key_info", {})
        key_length = subject_key_info.get("rsa_public_key", {}).get("length", 0)
        if key_length == 0:
            key_length = subject_key_info.get("ecdsa_public_key", {}).get("length", 0)
        validity = parsed.get("validity", {})
        certificates_up_to_root_count, has_root_certificate = count_intermediates_up_to_root(chain, certificate)

        self._cursor.execute("""
            INSERT INTO Certificates (
                serial_number, leaf_domain, version, signature_algorithm, key_algorithm, key_length,
                validity_start, validity_end, validity_length, SAN, domain_matches_san, issuer_id,
                subject_id, validation_level, redacted, signature_valid, self_signed, download_date,
                ocsp_stapling, ocsp_must_stapling, authority_info_access_is_critical, authority_info_access,
                ocsp_check, certificates_emitted_up_to, certificates_up_to_root_count, has_root_certificate, raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'No Request Done', ?, ?, ?, ?)
        """, (
            parsed.get("serial_number", ""), json_row.get("domain", ""), parsed.get("version", 0),
            reorder_signature_algorithm(parsed.get("signature_algorithm", {}).get("name", "")),
            subject_key_info.get("key_algorithm", {}).get("name", ""), key_length,
            validity.get("start", ""), validity.get("end", ""), validity.get("length", ""),
            ', '.join(parsed.get("names", [])),
            handshake_log.get("server_certificates", {}).get("validation", {}).get("matches_domain", False),
            issuer_id, subject_id, parsed.get("validation_level", ""), parsed.get("redacted", False),
            self._signature_validity(parsed, digital_certificate), parsed.get("signature", {}).get("self_signed", False),
            download_date, handshake_log.get("server_hello", {}).get("ocsp_stapling", False),
            digital_certificate.ocsp_must_staple(),
            digital_certificate.extension_criticality(ExtensionOID.AUTHORITY_INFORMATION_ACCESS),
            json.dumps(parsed.get("extensions", {}).get("authority_info_access", {})),
            certificates_emitted_up_to, certificates_up_to_root_count, has_root_certificate, digital_certificate.raw
        ))
        logging.debug("Certificato inserito: %s", parsed.get("serial_number", ""))
        return self._cursor.lastrowid

    def _signature_validity(self, parsed: dict, digital_certificate: Certificate) -> str:
        """Roots are verified against their own key; other types use the zgrab2 result."""
        if self.certificate_type is DatabaseType.ROOT:
            return verify_signature(digital_certificate.cert, digital_certificate.cert)
        return "Valid" if parsed.get("signature", {}).get("valid", False) == 1 else "Not Valid"

    def _insert_extensions(self, certificate_id: int, extensions: dict, digital_certificate: Certificate) -> int:
        # max_path_len has its own column: pop it from a copy to leave the JSON untouched
        basic_constraints = extensions.get("basic_constraints", {})
        max_path_length = None
        if "max_path_len" in basic_constraints:
            basic_constraints = dict(basic_constraints)
            max_path_length = basic_constraints.pop("max_path_len")

        self._cursor.execute("""
            INSERT INTO Extensions (
                certificate_id, key_usage, key_usage_is_critical, extended_key_usage, extended_key_usage_is_critical,
                basic_constraints, max_path_length, crl_distribution_points, crl_distr_point_is_critical, crl_revocation_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'No Request Done')
        """, (
            certificate_id, json.dumps(extensions.get("key_usage", {})),
            digital_certificate.extension_criticality(ExtensionOID.KEY_USAGE),
            json.dumps(extensions.get("extended_key_usage", {})),
            digital_certificate.extension_criticality(ExtensionOID.EXTENDED_KEY_USAGE),
            json.dumps(basic_constraints), max_path_length, json.dumps(extensions.get("crl_distribution_points", [])),
            digital_certificate.extension_criticality(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        ))
        return self._cursor.lastrowid

    def _insert_signed_certificate_timestamps(self, certificate_id: int, extensions: dict) -> None:
        """Insert the certificate SCTs, adding the logs missing from the list."""
        rows = [
            (certificate_id, self._log_row_id(sct.get("log_id", "")), sct.get("timestamp", ""), sct.get("version", ""),
             sct.get("signature", ""))
            for sct in extensions.get("signed_certificate_timestamps", [])
        ]
        self._cursor.executemany("""
            INSERT INTO SignedCertificateTimestamps (certificate_id, log_id, timestamp, version, signature)
            VALUES (?, ?, ?, ?, ?)
        """, rows)

    def _log_row_id(self, log_id: str) -> int:
        """Row id of the SCT log; a log missing from the list is inserted under the 'unknown' operator."""
        row = self._cursor.execute("SELECT id FROM Logs WHERE log_id = ?", (log_id,)).fetchone()
        if row is not None:
            return row[0]
        return self._insert_log(self._unknown_operator_id(), {"log_id": log_id})

    def _unknown_operator_id(self) -> int:
        """Id of the 'unknown' operator, -1 if missing."""
        row = self._cursor.execute("SELECT id FROM LogsOperators WHERE name = 'unknown' AND email = ''").fetchone()
        return row[0] if row is not None else -1

    def _insert_log_operator(self, name: str, email: str) -> int:
        self._cursor.execute("INSERT INTO LogsOperators (name, email) VALUES (?, ?)", (name, email))
        return self._cursor.lastrowid

    def _insert_log(self, operator_id: int, log: dict) -> int:
        state = log.get("state", {})
        temporal_interval = log.get("temporal_interval", {})
        self._cursor.execute("""
            INSERT INTO Logs (operator_id, description, log_id, key, url, mmd, state_usable_timestamp,
                state_retired_timestamp, state_qualified_timestamp, temporal_start, temporal_end)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(log_id) DO NOTHING
        """, (
            operator_id, log.get("description", ""), log.get("log_id", ""), log.get("key", ""), log.get("url", ""),
            log.get("mmd", ""), state.get("usable", {}).get("timestamp", ""), state.get("retired", {}).get("timestamp", ""),
            state.get("qualified", {}).get("timestamp", ""), temporal_interval.get("start_inclusive", ""),
            temporal_interval.get("end_exclusive", "")
        ))
        return self._cursor.lastrowid

    # ------------------------------------------------------------------ iteration and updates

    def get_certificates_count(self) -> int:
        """Return the number of certificates (0 on error)."""
        try:
            return self._conn.execute("SELECT COUNT(certificate_id) FROM Certificates").fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Errore generale durante il conteggio dei certificati: {e}")
            return 0

    def iter_leaf_domains(self, batch_size: int = 5000) -> Iterator[list[tuple[int, str]]]:
        """Yield batches of (certificate_id, leaf_domain) for all certificates."""
        return self._iter_batches("""
            SELECT certificate_id, leaf_domain
            FROM Certificates
            WHERE certificate_id > ?
            ORDER BY certificate_id
            LIMIT ?
        """, batch_size)

    def iter_raw_certificates(self, batch_size: int = 5000) -> Iterator[list[tuple[int, str, str, str, str, str]]]:
        """Yield batches of (certificate_id, leaf_domain, raw, common_name, organization, issuer_dn)."""
        return self._iter_batches("""
            SELECT c.certificate_id, c.leaf_domain, c.raw, i.common_name, i.organization, i.issuer_dn
            FROM Certificates AS c INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
            WHERE c.certificate_id > ?
            ORDER BY c.certificate_id
            LIMIT ?
        """, batch_size)

    def update_signature_validity(self, values: list[tuple[str, int]]) -> None:
        """Update signature_valid from (signature_valid, certificate_id) pairs."""
        self._conn.executemany("UPDATE Certificates SET signature_valid = ? WHERE certificate_id = ?", values)

    def _iter_batches(self, sql: str, batch_size: int) -> Iterator[list[tuple]]:
        """Keyset pagination (certificate_id > last seen): OFFSET would rescan every previous row on millions of rows.

        Each batch uses its own cursor and returns plain tuples.
        """
        last_certificate_id = 0
        while True:
            cursor = self._conn.cursor()
            cursor.row_factory = None
            rows = cursor.execute(sql, (last_certificate_id, batch_size)).fetchall()
            if not rows:
                return
            yield rows
            last_certificate_id = rows[-1][0]

    # ------------------------------------------------------------------ plot statistics

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
