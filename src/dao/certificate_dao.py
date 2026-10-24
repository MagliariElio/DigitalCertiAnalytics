from __future__ import annotations

import hashlib
import json
import logging
import marshal
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from operator import itemgetter

from cryptography.x509.extensions import UserNotice
from cryptography.x509.oid import ExtensionOID

from bean.certificate import Certificate
from db import schema
from db.database import DatabaseType
from db.raw_codec import RawCodec
from utils.chain_utils import count_intermediates_up_to_root, find_raw_cert_issuer, reorder_signature_algorithm

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Parameters of certificate_params(), in the order they are bound by the old 'Certificates' insert
CERTIFICATE_PARAM_COLUMNS = (
    "serial_number", "leaf_domain", "version", "signature_algorithm", "key_algorithm", "key_length",
    "validity_start", "validity_end", "validity_length", "SAN", "domain_matches_san", "issuer_id",
    "subject_id", "validation_level", "redacted", "signature_valid", "self_signed", "download_date",
    "ocsp_stapling", "ocsp_must_stapling", "authority_info_access_is_critical", "authority_info_access",
    "certificates_emitted_up_to", "certificates_up_to_root_count", "has_root_certificate", "raw",
)
ISSUER_COLUMNS = ("common_name", "organization", "country", "issuer_dn", "locality", "province", "organizational_unit",
                  "authority_key_id", "raw")
SUBJECT_COLUMNS = ("common_name", "subject_dn", "subject_key_id", "subject_alt_name", "subject_alt_name_is_critical")
EXTENSION_COLUMNS = ("key_usage", "key_usage_is_critical", "extended_key_usage", "extended_key_usage_is_critical",
                     "basic_constraints", "max_path_length", "crl_distribution_points", "crl_distr_point_is_critical")
POLICY_COLUMNS = ("policy_identifier", "cps", "policy_qualifiers", "is_cp_critical")
ERROR_COLUMNS = ("domain", "status", "protocol", "timestamp", "error_message", "download_date")

RAW_INDEX = CERTIFICATE_PARAM_COLUMNS.index("raw")
SIGNATURE_VALID_INDEX = CERTIFICATE_PARAM_COLUMNS.index("signature_valid")

# Lookup kinds of the stored values: inline value, TextValues or NumericValues reference
INLINE, TEXT, NUMERIC = "c", "tv", "nv"
LOOKUP_TABLES = {TEXT: "TextValues", NUMERIC: "NumericValues"}

# Deduplicated kinds and their key tables (digest -> id), in the order the rows of a certificate are stored
KEY_TABLES = ("RawKeys", "IssuerKeys", "PolicyKeys", "PolicySetKeys", "CertificateKeys")

# The old NOT NULL columns of SignedCertificateTimestamps checked in the old insert order (after certificate_id)
_SCT_NOT_NULL = ("log_id", "timestamp", "version", "signature")


def _without_user_notices(qualifiers: list | None) -> str:
    """JSON of the policy qualifiers without UserNotice objects."""
    return json.dumps([qualifier for qualifier in qualifiers or [] if not isinstance(qualifier, UserNotice)])


def _joined(values: list[str]) -> str:
    """Join attribute values, replacing characters not encodable in UTF-8."""
    return ', '.join(values).encode('utf-8', errors='replace').decode('utf-8')


# Row builders shared by CertificateDAO and the parallel ingestion: each one evaluates its values in the order of the
# original single-row inserts, so errors and log messages come out in the same order.

def error_params(json_row: dict) -> tuple:
    """Errors row of a failed scan, in ERROR_COLUMNS order."""
    tls = json_row.get("data", {}).get("tls", {})
    timestamp = tls.get("timestamp", "")
    return (json_row.get("domain", ""), tls.get("status", ""), tls.get("protocol", ""), timestamp, tls.get("error", ""),
            timestamp)


def issuer_params(parsed: dict, chain: list[dict]) -> tuple:
    """Issuers row, in ISSUER_COLUMNS order, with the issuer raw certificate when found in the chain."""
    issuer = parsed.get("issuer", {})
    issuer_dn = parsed.get("issuer_dn", "")
    return (
        _joined(issuer.get("common_name", [])), _joined(issuer.get("organization", [])),
        _joined(issuer.get("country", [])), issuer_dn, ', '.join(issuer.get("locality", [])),
        ', '.join(issuer.get("province", [])), ', '.join(issuer.get("organizational_unit", [])),
        parsed.get("extensions", {}).get("authority_key_id", ""), find_raw_cert_issuer(chain, issuer_dn)
    )


def subject_params(parsed: dict, digital_certificate: Certificate) -> tuple:
    """Subjects row, in SUBJECT_COLUMNS order."""
    extensions = parsed.get("extensions", {})
    return (
        ', '.join(parsed.get("subject", {}).get("common_name", [])), parsed.get("subject_dn", ""),
        extensions.get("subject_key_id", ""), json.dumps(extensions.get("subject_alt_name", {})),
        digital_certificate.extension_criticality(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    )


def signature_validity(certificate_type: DatabaseType, parsed: dict, digital_certificate: Certificate) -> str:
    """Roots are verified against their own key; other types use the zgrab2 result."""
    if certificate_type is DatabaseType.ROOT:
        return digital_certificate.self_signature_validity()
    return "Valid" if parsed.get("signature", {}).get("valid", False) == 1 else "Not Valid"


def certificate_params(json_row: dict, certificate: dict, parsed: dict, chain: list[dict], digital_certificate: Certificate,
                       certificate_type: DatabaseType, issuer_id: int | None, subject_id: int | None,
                       certificates_emitted_up_to: int) -> tuple:
    """Certificates row, in CERTIFICATE_PARAM_COLUMNS order."""
    tls = json_row.get("data", {}).get("tls", {})
    handshake_log = tls.get("result", {}).get("handshake_log", {})
    download_date = tls["timestamp"] if "timestamp" in tls else datetime.now().isoformat()
    subject_key_info = parsed.get("subject_key_info", {})
    key_length = subject_key_info.get("rsa_public_key", {}).get("length", 0)
    if key_length == 0:
        key_length = subject_key_info.get("ecdsa_public_key", {}).get("length", 0)
    validity = parsed.get("validity", {})
    certificates_up_to_root_count, has_root_certificate = count_intermediates_up_to_root(chain, certificate)
    return (
        parsed.get("serial_number", ""), json_row.get("domain", ""), parsed.get("version", 0),
        reorder_signature_algorithm(parsed.get("signature_algorithm", {}).get("name", "")),
        subject_key_info.get("key_algorithm", {}).get("name", ""), key_length,
        validity.get("start", ""), validity.get("end", ""), validity.get("length", ""),
        ', '.join(parsed.get("names", [])),
        handshake_log.get("server_certificates", {}).get("validation", {}).get("matches_domain", False),
        issuer_id, subject_id, parsed.get("validation_level", ""), parsed.get("redacted", False),
        signature_validity(certificate_type, parsed, digital_certificate),
        parsed.get("signature", {}).get("self_signed", False),
        download_date, handshake_log.get("server_hello", {}).get("ocsp_stapling", False),
        digital_certificate.ocsp_must_staple(),
        digital_certificate.extension_criticality(ExtensionOID.AUTHORITY_INFORMATION_ACCESS),
        json.dumps(parsed.get("extensions", {}).get("authority_info_access", {})),
        certificates_emitted_up_to, certificates_up_to_root_count, has_root_certificate, digital_certificate.raw
    )


def extension_params(extensions: dict, digital_certificate: Certificate) -> tuple:
    """Extensions row without certificate_id, in EXTENSION_COLUMNS order."""
    # max_path_len has its own column: pop it from a copy to leave the JSON untouched
    basic_constraints = extensions.get("basic_constraints", {})
    max_path_length = None
    if "max_path_len" in basic_constraints:
        basic_constraints = dict(basic_constraints)
        max_path_length = basic_constraints.pop("max_path_len")
    return (
        json.dumps(extensions.get("key_usage", {})), digital_certificate.extension_criticality(ExtensionOID.KEY_USAGE),
        json.dumps(extensions.get("extended_key_usage", {})),
        digital_certificate.extension_criticality(ExtensionOID.EXTENDED_KEY_USAGE),
        json.dumps(basic_constraints), max_path_length, json.dumps(extensions.get("crl_distribution_points", [])),
        digital_certificate.extension_criticality(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    )


def policy_params(digital_certificate: Certificate) -> list[tuple] | None:
    """CertificatePolicies rows without extension_id, in POLICY_COLUMNS order; None without the extension."""
    policies = digital_certificate.certificate_policies()
    if policies is None:
        return None
    return [(policy['policy_identifier'], _without_user_notices(policy['cps']),
             _without_user_notices(policy['policy_qualifiers']), policy['is_cp_critical']) for policy in policies]


# ---------------------------------------------------------------------------------------------- storage layout

@dataclass(frozen=True)
class StorageLayout:
    """Where each value of a certificate occurrence is stored for one database type (picklable).

    certificate_positions: certificate_params() positions stored per certificate, in CERTIFICATE_PARAM_COLUMNS order;
    certificate_columns: (CertificateData column, kind) of certificate_values(), i.e. those positions, then the
    subject and the extension values; occurrence_positions / occurrence_columns: the same for Occurrences
    (kind 'o' inline, 'code' fixed code, 'nv' NumericValues reference).
    """
    kept: tuple[int, ...]
    dropped: tuple[int, ...]
    certificate_positions: tuple[int, ...]
    certificate_columns: tuple[tuple[str, str], ...]
    occurrence_positions: tuple[int, ...]
    occurrence_columns: tuple[tuple[str, str], ...]

    def certificate_values(self, params: tuple, subject: tuple, extension: tuple) -> tuple:
        """Stored per-certificate values (lookup values as values), in certificate_columns order."""
        return (*itemgetter(*self.certificate_positions)(params), *subject, *extension)

    def occurrence_values(self, params: tuple) -> tuple:
        """Stored per-occurrence values (signature_valid as its code, download_date as value)."""
        return tuple(schema.SIGNATURE_CODES[params[i]] if i == SIGNATURE_VALID_INDEX else params[i]
                     for i in self.occurrence_positions)


def storage_layout(db_type: DatabaseType) -> StorageLayout:
    kinds = {name: kind for name, _, kind in schema.certificate_columns(db_type)}
    kept = tuple(i for i, name in enumerate(CERTIFICATE_PARAM_COLUMNS) if name in kinds)
    dropped = tuple(i for i in range(len(CERTIFICATE_PARAM_COLUMNS)) if i not in kept)
    certificate_positions = tuple(i for i in kept if kinds[CERTIFICATE_PARAM_COLUMNS[i]] in (INLINE, TEXT, NUMERIC))
    certificate_columns = tuple((CERTIFICATE_PARAM_COLUMNS[i], kinds[CERTIFICATE_PARAM_COLUMNS[i]])
                                for i in certificate_positions)
    certificate_columns += tuple((column, kind) for _, _, kind, column in schema.SUBJECT_COLUMNS)
    certificate_columns += tuple((name, kind) for name, _, kind in schema.EXTENSION_COLUMNS)
    occurrence_positions = tuple(i for i in kept if kinds[CERTIFICATE_PARAM_COLUMNS[i]] in ("o", "code", "onv"))
    occurrence_kinds = [kinds[CERTIFICATE_PARAM_COLUMNS[i]] for i in occurrence_positions]
    occurrence_columns = tuple((CERTIFICATE_PARAM_COLUMNS[i], NUMERIC if kind == "onv" else kind)
                               for i, kind in zip(occurrence_positions, occurrence_kinds))
    return StorageLayout(kept, dropped, certificate_positions, certificate_columns, occurrence_positions,
                         occurrence_columns)


# Stored error values (download_date is the same value as timestamp): (ErrorData column, kind), error_params() index
ERROR_STORED = (("domain", INLINE, 0), ("status", TEXT, 1), ("protocol", TEXT, 2), ("timestamp", NUMERIC, 3),
                ("error_message", INLINE, 4))


# ---------------------------------------------------------------------------------------------- deduplication keys

def _digest(value: object) -> bytes:
    """BLAKE2b-128 of the marshal (version 2) serialisation of the value.

    Like repr(), it keeps 1, 1.0, '1', True, None, -0.0 and 0.0 apart and depends only on the contents (version 2
    writes no back-references), at half the cost; lone surrogates are serialised as they are.
    """
    return hashlib.blake2b(marshal.dumps(value, 2), digest_size=16).digest()


def raw_key(raw: object) -> bytes:
    return _digest(raw)


def issuer_key(values: tuple, raw_digest: bytes | None) -> bytes:
    """Key of the 8 issuer values (issuer_params() order without raw) and the raw_key() of the issuer raw (None
    when the raw is None)."""
    return _digest((values, raw_digest))


def policy_key(policy: tuple) -> bytes:
    return _digest(policy)


def policy_set_key(policy_keys: tuple[bytes, ...]) -> bytes:
    return _digest(policy_keys)


def certificate_key(values: tuple, scts: tuple, policies: tuple, raw: bytes | None) -> bytes:
    """Key of the stored per-certificate values, the SCTs (JSON log id, timestamp, version, signature), the policies
    (policy_params() rows, () without policies) and the raw key (None when raw is None)."""
    return _digest((values, scts, policies, raw))


def stored_lookup_value(value: object) -> object:
    """The value a lookup stores: SQLite stores a NaN float as NULL."""
    return None if type(value) is float and value != value else value


def _placeholders(count: int) -> str:
    return ", ".join("?" * count)


def _sct_not_null_error(row: tuple) -> sqlite3.IntegrityError | None:
    """The NOT NULL error the old SignedCertificateTimestamps insert raised for (certificate_id, log_id, ...)."""
    for column, value in zip(_SCT_NOT_NULL, row[1:]):
        if value is None:
            return sqlite3.IntegrityError(f"NOT NULL constraint failed: SignedCertificateTimestamps.{column}")
    return None


class CertificateDAO:
    """Certificate data access: zgrab2 JSON inserts (single-row path) and counts."""

    def __init__(self, connection: sqlite3.Connection, certificate_type: DatabaseType):
        self._conn = connection
        self._cursor = connection.cursor()
        self.certificate_type = certificate_type
        self.layout = storage_layout(certificate_type)
        self.certificate_kept = self.layout.kept
        self.certificate_dropped = self.layout.dropped
        self.raw_codec: RawCodec | None = None
        self._keys = "temp"
        self._recent: str | None = None
        self._create_key_tables()
        self._build_statements()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def use_keys(self, keys_schema: str = "temp", recent_schema: str | None = None) -> None:
        """Keep the deduplication keys in the tables of keys_schema (created if missing), with the most recent ones
        in recent_schema when given (the ingestion merges them into keys_schema now and then)."""
        self._keys = keys_schema
        self._recent = recent_schema
        self._create_key_tables()
        self._build_statements()

    def _create_key_tables(self) -> None:
        for schema_name in dict.fromkeys(filter(None, (self._keys, self._recent))):
            for table in KEY_TABLES:
                self._conn.execute(f"CREATE TABLE IF NOT EXISTS {schema_name}.{table} "
                                   "(digest BLOB PRIMARY KEY, id INTEGER NOT NULL) WITHOUT ROWID")

    def _build_statements(self) -> None:
        layout = self.layout
        columns = [column for column, _ in layout.certificate_columns] + ["raw_id", "policy_set_id"]
        self._certificate_insert = (f"INSERT INTO CertificateData ({', '.join(columns)}) "
                                    f"VALUES ({_placeholders(len(columns))})")
        columns = ["certificate_id", "issuer_id"] + [column for column, _ in layout.occurrence_columns]
        self._occurrence_insert = f"INSERT INTO Occurrences ({', '.join(columns)}) VALUES ({_placeholders(len(columns))})"
        if self._recent is None:
            self._key_select = {table: f"SELECT id FROM {self._keys}.{table} WHERE digest = ?" for table in KEY_TABLES}
        else:
            self._key_select = {table: f"SELECT id FROM {self._recent}.{table} WHERE digest = ?1 UNION ALL "
                                       f"SELECT id FROM {self._keys}.{table} WHERE digest = ?1 LIMIT 1"
                                for table in KEY_TABLES}
        self._key_insert = {table: f"INSERT INTO {self._recent or self._keys}.{table} (digest, id) VALUES (?, ?)"
                            for table in KEY_TABLES}

    def _codec(self) -> RawCodec:
        if self.raw_codec is None:
            self.raw_codec = RawCodec.for_connection(self._conn)
        return self.raw_codec

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
        params = error_params(json_row)
        self._bind_check(params)
        values = [self._lookup(kind, params[index]) if kind != INLINE else params[index] for _, kind, index in ERROR_STORED]
        self._cursor.execute(f"INSERT INTO ErrorData ({', '.join(column for column, _, _ in ERROR_STORED)}) "
                             f"VALUES ({_placeholders(len(ERROR_STORED))})", values)
        logging.debug("Error row inserted for domain: %s", params[0])

    def process_insert_certificate(self, json_row: dict, certificate: dict, chain: list[dict],
                                   certificates_emitted_up_to: int) -> None:
        """Insert an occurrence of the certificate with issuer, subject, extensions, SCTs and policies.

        chain is the chain above it. The values are built and checked in the order of the old single-row inserts, so
        a value that cannot be stored fails the row at the same point with the same error.
        """
        parsed = certificate.get("parsed", {})
        # A chain certificate without raw invalidates the whole row (KeyError), as in previous versions
        raw = certificate.get("raw") if self.certificate_type is DatabaseType.LEAF else certificate["raw"]
        digital_certificate = Certificate(raw)
        extensions = parsed.get("extensions", {})

        issuer = issuer_params(parsed, chain)
        self._bind_check(issuer)
        subject = subject_params(parsed, digital_certificate)
        self._bind_check(subject)
        params = certificate_params(json_row, certificate, parsed, chain, digital_certificate, self.certificate_type,
                                    0, 0, certificates_emitted_up_to)
        self._bind_check(params)
        logging.debug("Certificate inserted: %s", parsed.get("serial_number", ""))
        extension = extension_params(extensions, digital_certificate)
        self._bind_check((0, *extension))
        scts = self._sct_rows(extensions)
        policies = policy_params(digital_certificate)
        if policies is not None:
            for policy in policies:
                self._bind_check((0, *policy))
        self._store(params, subject, extension, scts, policies or (), issuer)

    def _bind_check(self, values: tuple) -> None:
        """Bind the values as the old insert did, raising its error for a value that cannot be stored."""
        self._cursor.execute(f"SELECT {_placeholders(len(values))}", values)

    def _sct_rows(self, extensions: dict) -> list[tuple]:
        """(JSON log id, Logs id, timestamp, version, signature) of every SCT, checked as the old insert did."""
        rows = [
            (log_id, self._log_row_id(log_id), sct.get("timestamp", ""), sct.get("version", ""), sct.get("signature", ""))
            for sct in extensions.get("signed_certificate_timestamps", []) for log_id in (sct.get("log_id", ""),)
        ]
        for row in rows:
            stored = (0, *row[1:])
            self._bind_check(stored)
            error = _sct_not_null_error(stored)
            if error is not None:
                raise error
        return rows

    def _store(self, params: tuple, subject: tuple, extension: tuple, scts: list[tuple], policies, issuer: tuple) -> None:
        """Insert or reuse the deduplicated rows of the occurrence, then the occurrence.

        Order (the ingestion engine assigns its ids in the same one): issuer raw, issuer, certificate (with its own
        raw: a new certificate stores its raw in a new RawCertificates row, the issuer raws are deduplicated), SCTs,
        occurrence.
        """
        layout = self.layout
        raw = params[RAW_INDEX]
        raw_digest = None if raw is None else raw_key(raw)
        issuer_raw = issuer[-1]
        issuer_raw_digest = None if issuer_raw is None else raw_key(issuer_raw)
        issuer_raw_id = None if issuer_raw is None else self._raw_id(issuer_raw, issuer_raw_digest)
        issuer_id = self._issuer_id(issuer[:-1], issuer_raw_digest, issuer_raw_id)

        values = layout.certificate_values(params, subject, extension)
        sct_values = tuple((row[0], *row[2:]) for row in scts)
        key = certificate_key(values, sct_values, tuple(policies), raw_digest)
        certificate_id = self._key_id("CertificateKeys", key)
        if certificate_id is None:
            raw_id = None
            if raw is not None:
                self._cursor.execute("INSERT INTO RawCertificates (der_zstd, raw) VALUES (?, ?)", self._codec().encode(raw))
                raw_id = self._cursor.lastrowid
            policy_set_id = None
            if policies:
                policy_keys = tuple(policy_key(policy) for policy in policies)
                policy_set_id = self._policy_set_id(policy_set_key(policy_keys), policy_keys, policies)
            stored = [value if kind == INLINE else self._lookup(kind, value)
                      for (_, kind), value in zip(layout.certificate_columns, values)]
            self._cursor.execute(self._certificate_insert, (*stored, raw_id, policy_set_id))
            certificate_id = self._cursor.lastrowid
            self._cursor.executemany("INSERT INTO SctData (certificate_id, position, log_id, timestamp, version, signature) "
                                     "VALUES (?, ?, ?, ?, ?, ?)",
                                     [(certificate_id, position, *row[1:]) for position, row in enumerate(scts)])
            self._cursor.execute(self._key_insert["CertificateKeys"], (key, certificate_id))

        occurrence = [value if kind != NUMERIC else self._lookup(kind, value)
                      for (_, kind), value in zip(layout.occurrence_columns, layout.occurrence_values(params))]
        self._cursor.execute(self._occurrence_insert, (certificate_id, issuer_id, *occurrence))

    def _key_id(self, table: str, key: bytes) -> int | None:
        row = self._cursor.execute(self._key_select[table], (key,)).fetchone()
        return None if row is None else row[0]

    def _raw_id(self, raw: object, key: bytes) -> int:
        """Id of an issuer raw (deduplicated by RawKeys, which holds only issuer raws)."""
        raw_id = self._key_id("RawKeys", key)
        if raw_id is None:
            self._cursor.execute("INSERT INTO RawCertificates (der_zstd, raw) VALUES (?, ?)", self._codec().encode(raw))
            raw_id = self._cursor.lastrowid
            self._cursor.execute(self._key_insert["RawKeys"], (key, raw_id))
        return raw_id

    def _issuer_id(self, values: tuple, raw_digest: bytes | None, raw_id: int | None) -> int:
        key = issuer_key(values, raw_digest)
        issuer_id = self._key_id("IssuerKeys", key)
        if issuer_id is None:
            # issuer_params() order -> IssuerData columns
            named = dict(zip(ISSUER_COLUMNS, values))
            columns = [name for name, _ in schema.ISSUER_COLUMNS]
            self._cursor.execute(f"INSERT INTO IssuerData ({', '.join(columns)}, raw_id) "
                                 f"VALUES ({_placeholders(len(columns) + 1)})", (*[named[name] for name in columns], raw_id))
            issuer_id = self._cursor.lastrowid
            self._cursor.execute(self._key_insert["IssuerKeys"], (key, issuer_id))
        return issuer_id

    def _policy_set_id(self, set_key: bytes, policy_keys: tuple[bytes, ...], policies) -> int:
        set_id = self._key_id("PolicySetKeys", set_key)
        if set_id is not None:
            return set_id
        policy_ids = []
        for key, policy in zip(policy_keys, policies):
            policy_id = self._key_id("PolicyKeys", key)
            if policy_id is None:
                self._cursor.execute(f"INSERT INTO PolicyData ({', '.join(POLICY_COLUMNS)}) VALUES ({_placeholders(4)})",
                                     policy)
                policy_id = self._cursor.lastrowid
                self._cursor.execute(self._key_insert["PolicyKeys"], (key, policy_id))
            policy_ids.append(policy_id)
        self._cursor.execute("INSERT INTO PolicySets (policy_count) VALUES (?)", (len(policy_ids),))
        set_id = self._cursor.lastrowid
        self._cursor.executemany("INSERT INTO PolicySetMembers (policy_set_id, position, policy_id) VALUES (?, ?, ?)",
                                 [(set_id, position, policy_id) for position, policy_id in enumerate(policy_ids)])
        self._cursor.execute(self._key_insert["PolicySetKeys"], (set_key, set_id))
        return set_id

    def _lookup(self, kind: str, value: object) -> int | None:
        """Id of the value in TextValues/NumericValues, inserted if missing; None for NULL."""
        value = stored_lookup_value(value)
        if value is None:
            return None
        table = LOOKUP_TABLES[kind]
        select = f"SELECT value_id FROM {table} WHERE value = ?"
        row = self._cursor.execute(select, (value,)).fetchone()
        if row is not None:
            return row[0]
        self._cursor.execute(f"INSERT OR IGNORE INTO {table} (value) VALUES (?)", (value,))
        if self._cursor.rowcount == 1:
            return self._cursor.lastrowid
        return self._cursor.execute(select, (value,)).fetchone()[0]

    def _log_row_id(self, log_id: str) -> int:
        """Row id of the SCT log; a log missing from the list is inserted under the 'unknown' operator."""
        row = self._cursor.execute("SELECT id FROM Logs WHERE log_id = ?", (log_id,)).fetchone()
        if row is not None:
            return row[0]
        return self.insert_unknown_log(log_id)

    def insert_unknown_log(self, log_id: str) -> int:
        """Insert a log missing from the list under the 'unknown' operator and return its row id."""
        return self._insert_log(self.unknown_operator_id(), {"log_id": log_id})

    def unknown_operator_id(self) -> int:
        """Id of the 'unknown' operator, -1 if missing."""
        row = self._cursor.execute("SELECT id FROM LogsOperators WHERE name = 'unknown' AND email = ''").fetchone()
        return row[0] if row is not None else -1

    def log_row_ids(self) -> dict[str, int]:
        """Row id of every stored SCT log by log_id."""
        return {log_id: row_id for log_id, row_id in self._conn.execute("SELECT log_id, id FROM Logs")
                if isinstance(log_id, str)}

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

    # ------------------------------------------------------------------ counts

    def get_certificates_count(self) -> int:
        """Return the number of certificate occurrences (0 on error)."""
        try:
            return self._conn.execute("SELECT COUNT(*) FROM Occurrences").fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error counting the certificates: {e}")
            return 0
