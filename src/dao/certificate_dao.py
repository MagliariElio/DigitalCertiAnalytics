from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from typing import Iterator

from cryptography.x509.extensions import UserNotice
from cryptography.x509.oid import ExtensionOID

from bean.certificate import Certificate
from db.database import DatabaseType
from utils.chain_utils import (count_intermediates_up_to_root, find_raw_cert_issuer, reorder_signature_algorithm,
                               verify_signature)

# Admin: Anuar Elio Magliari
# Politecnico di Torino


def _without_user_notices(qualifiers: list | None) -> str:
    """JSON of the policy qualifiers without UserNotice objects."""
    return json.dumps([qualifier for qualifier in qualifiers or [] if not isinstance(qualifier, UserNotice)])


def _joined(values: list[str]) -> str:
    """Join attribute values, replacing characters not encodable in UTF-8."""
    return ', '.join(values).encode('utf-8', errors='replace').decode('utf-8')


class CertificateDAO:
    """Certificate data access: zgrab2 JSON inserts, batch iteration and updates."""

    def __init__(self, connection: sqlite3.Connection, certificate_type: DatabaseType):
        self._conn = connection
        self._cursor = connection.cursor()
        self.certificate_type = certificate_type

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
