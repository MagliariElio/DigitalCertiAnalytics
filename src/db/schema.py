"""SQLite layout of the certificate databases (schema version 2): tables, fixed codes and compatibility views.

Every distinct certificate is stored once (CertificateData) and every place where it was seen once (Occurrences, one
row per certificate of the old layout, with the same id). Repeated values live in lookup tables (TextValues,
NumericValues, IssuerData, RawCertificates, PolicyData/PolicySets). The tables of the old layout (Certificates,
Issuers, Subjects, Extensions, SignedCertificateTimestamps, CertificatePolicies, Errors) are views with the same
names, columns, column order and values, so queries written for them keep working; only 'raw' is shown as stored
(db.raw_codec decodes it). Views cannot be updated: the program writes the base tables.
"""
from __future__ import annotations

import sqlite3

# Admin: Anuar Elio Magliari
# Politecnico di Torino

SCHEMA_VERSION = 2
APPLICATION_ID = 0x44434132          # 'DCA2', PRAGMA application_id of every database of this layout
PAGE_SIZE = 65536

LEAF, INTERMEDIATE, ROOT = "leaf", "intermediate", "root"

# Fixed codes of the per-occurrence enumerations, stored as the index (code 0 is the insert default)
OCSP_STATUSES = ("No Request Done", "Good", "Revoked", "Unknown", "Impossible Retrieve OCSP Information",
                 "Not Ok OCSP Response", "No Issuer Url Found", "No OCSP Url Found")
SIGNATURE_VALIDITIES = ("Valid", "Not Valid", "Error", "Unsupported Key Type")
OCSP_CODES = {name: code for code, name in enumerate(OCSP_STATUSES)}
SIGNATURE_CODES = {name: code for code, name in enumerate(SIGNATURE_VALIDITIES)}
NO_REQUEST_DONE = OCSP_CODES["No Request Done"]

# Columns of the old 'Certificates' table, in their order, with the declared type and where they are stored:
# 'o' Occurrences, 'c' CertificateData, 'tv'/'nv' CertificateData reference to TextValues/NumericValues, 'onv' the
# same on Occurrences, 'code' fixed code table, 'id' the occurrence id, 'raw' RawCertificates.
CERTIFICATE_COLUMNS = (
    ("certificate_id", "INTEGER", "id"),
    ("serial_number", "VARCHAR", "c"),
    ("leaf_domain", "VARCHAR", "o"),
    ("issuer_id", "INT", "id"),
    ("subject_id", "INT", "id"),
    ("version", "INT", "c"),
    ("signature_algorithm", "VARCHAR", "tv"),
    ("key_algorithm", "VARCHAR", "tv"),
    ("key_length", "INT", "c"),
    ("validity_start", "TIMESTAMP", "c"),
    ("validity_end", "TIMESTAMP", "c"),
    ("validity_length", "INT", "c"),
    ("SAN", "TEXT", "c"),
    ("domain_matches_san", "BOOLEAN", "o"),
    ("authority_info_access_is_critical", "VARCHAR(12)", "tv"),
    ("authority_info_access", "TEXT", "tv"),
    ("ocsp_check", "VARCHAR(36)", "code"),
    ("ocsp_stapling", "INT", "o"),
    ("ocsp_must_stapling", "VARCHAR(9)", "tv"),
    ("validation_level", "VARCHAR", "tv"),
    ("signature_valid", "VARCHAR(20)", "code"),
    ("self_signed", "BOOLEAN", "c"),
    ("redacted", "BOOLEAN", "c"),
    ("certificates_emitted_up_to", "INT", "o"),
    ("certificates_up_to_root_count", "INT", "o"),
    ("has_root_certificate", "BOOLEAN", "o"),
    ("download_date", "TIMESTAMP", "onv"),
    ("raw", "BLOB", "raw"),
)
# Old 'Certificates' columns that a database type does not have
REMOVED_COLUMNS = {
    LEAF: ("certificates_emitted_up_to",),
    INTERMEDIATE: ("ocsp_stapling", "ocsp_must_stapling", "signature_valid", "SAN", "domain_matches_san"),
    ROOT: ("ocsp_stapling", "ocsp_must_stapling", "certificates_up_to_root_count", "has_root_certificate", "SAN",
           "domain_matches_san"),
}
# Old 'Subjects' columns (after subject_id): name, declared type, kind, CertificateData column
SUBJECT_COLUMNS = (
    ("common_name", "VARCHAR", "c", "subject_common_name"),
    ("subject_dn", "TEXT", "c", "subject_dn"),
    ("subject_key_id", "VARCHAR", "c", "subject_key_id"),
    ("subject_alt_name", "TEXT", "c", "subject_alt_name"),
    ("subject_alt_name_is_critical", "VARCHAR(12)", "tv", "subject_alt_name_is_critical"),
)
# Old 'Extensions' columns (after extension_id, certificate_id): name, declared type, kind
EXTENSION_COLUMNS = (
    ("key_usage", "JSONB", "nv"),
    ("key_usage_is_critical", "VARCHAR(12)", "tv"),
    ("extended_key_usage", "JSONB", "nv"),
    ("extended_key_usage_is_critical", "VARCHAR(12)", "tv"),
    ("basic_constraints", "JSONB", "nv"),
    ("max_path_length", "INT", "c"),
    ("crl_distribution_points", "TEXT[]", "c"),
    ("crl_distr_point_is_critical", "VARCHAR(12)", "tv"),
)
# Old 'Issuers' columns (after issuer_id, without raw): name, declared type
ISSUER_COLUMNS = (("common_name", "VARCHAR"), ("organization", "VARCHAR"), ("issuer_dn", "TEXT"),
                  ("country", "VARCHAR"), ("province", "VARCHAR"), ("locality", "VARCHAR"),
                  ("organizational_unit", "VARCHAR"), ("authority_key_id", "VARCHAR"))
# Old 'Errors' columns stored in ErrorData (download_date is always equal to timestamp): name, kind
ERROR_COLUMNS = (("domain", "c"), ("status", "tv"), ("protocol", "tv"), ("timestamp", "nv"), ("error_message", "c"))

# Ids of the 1:N rows in the views: occurrence_id * ROW_ID_STRIDE + position + 1 (unique, in the old relative order)
ROW_ID_STRIDE = 1 << 20

COMMON_DDL = f"""
CREATE TABLE SchemaInfo (key TEXT PRIMARY KEY NOT NULL, value) WITHOUT ROWID;
CREATE TABLE TextValues (value_id INTEGER PRIMARY KEY, value TEXT NOT NULL UNIQUE);
CREATE TABLE NumericValues (value_id INTEGER PRIMARY KEY, value NUMERIC NOT NULL UNIQUE);
CREATE TABLE OcspStatuses (code INTEGER PRIMARY KEY, name VARCHAR(36) NOT NULL UNIQUE);
CREATE TABLE SignatureValidities (code INTEGER PRIMARY KEY, name VARCHAR(20) NOT NULL UNIQUE);
CREATE TABLE RawDictionaries (dictionary_id INTEGER PRIMARY KEY, zstd_dictionary BLOB NOT NULL);
CREATE TABLE RawCertificates (
    raw_id INTEGER PRIMARY KEY,
    der_zstd BLOB,
    raw BLOB,
    CHECK ((der_zstd IS NULL) <> (raw IS NULL))
);
CREATE TABLE IssuerData (
    issuer_id INTEGER PRIMARY KEY,
    {', '.join(f'{name} {kind}' for name, kind in ISSUER_COLUMNS)},
    raw_id INTEGER REFERENCES RawCertificates(raw_id)
);
CREATE TABLE PolicyData (
    policy_id INTEGER PRIMARY KEY,
    policy_identifier VARCHAR,
    cps TEXT[],
    policy_qualifiers TEXT,
    is_cp_critical BOOLEAN
);
CREATE TABLE PolicySets (policy_set_id INTEGER PRIMARY KEY, policy_count INTEGER NOT NULL);
CREATE TABLE PolicySetMembers (
    policy_set_id INTEGER NOT NULL REFERENCES PolicySets(policy_set_id),
    position INTEGER NOT NULL,
    policy_id INTEGER NOT NULL REFERENCES PolicyData(policy_id),
    PRIMARY KEY (policy_set_id, position)
) WITHOUT ROWID;
CREATE TABLE SctData (
    certificate_id INTEGER NOT NULL REFERENCES CertificateData(certificate_id),
    position INTEGER NOT NULL,
    log_id INTEGER NOT NULL REFERENCES Logs(id),
    timestamp INTEGER NOT NULL,
    version INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (certificate_id, position)
) WITHOUT ROWID;
CREATE TABLE LogsOperators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    email TEXT
);
CREATE TABLE Logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id INT NOT NULL,
    description VARCHAR(255) NOT NULL,
    log_id VARCHAR(255) UNIQUE NOT NULL,
    key TEXT NOT NULL,
    url TEXT NOT NULL,
    mmd INT NOT NULL,
    state_usable_timestamp TIMESTAMPTZ,
    state_retired_timestamp TIMESTAMPTZ,
    state_qualified_timestamp TIMESTAMPTZ,
    temporal_start TIMESTAMPTZ NOT NULL,
    temporal_end TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (operator_id) REFERENCES LogsOperators(id)
);
"""

_ERROR_DDL = """CREATE TABLE ErrorData (
    error_id INTEGER PRIMARY KEY,
    domain VARCHAR,
    status INTEGER,
    protocol INTEGER,
    timestamp INTEGER,
    error_message TEXT
);
"""


def type_name(db_type) -> str:
    """'leaf', 'intermediate' or 'root' from a DatabaseType or its value."""
    return getattr(db_type, "value", db_type)


def certificate_columns(db_type) -> list[tuple[str, str, str]]:
    """Old 'Certificates' columns of the type, in their order: (name, declared type, kind)."""
    removed = REMOVED_COLUMNS[type_name(db_type)]
    return [column for column in CERTIFICATE_COLUMNS if column[0] not in removed]


def _stored_type(kind: str, declared: str) -> str:
    return "INTEGER" if kind in ("tv", "nv", "onv", "code") else declared


def ddl(db_type) -> str:
    """CREATE statements of the tables and views of a database type."""
    name = type_name(db_type)
    columns = certificate_columns(name)
    data = [f"{column} {_stored_type(kind, declared)}" for column, declared, kind in columns if kind in ("c", "tv", "nv")]
    data.append("raw_id INTEGER REFERENCES RawCertificates(raw_id)")
    data += [f"{column} {_stored_type(kind, declared)}" for _, declared, kind, column in SUBJECT_COLUMNS]
    data += [f"{column} {_stored_type(kind, declared)}" for column, declared, kind in EXTENSION_COLUMNS]
    data.append("policy_set_id INTEGER REFERENCES PolicySets(policy_set_id)")
    occurrence = ["occurrence_id INTEGER PRIMARY KEY",
                  "certificate_id INTEGER NOT NULL REFERENCES CertificateData(certificate_id)",
                  "issuer_id INTEGER NOT NULL REFERENCES IssuerData(issuer_id)"]
    for column, declared, kind in columns:
        if column == "ocsp_check":
            occurrence.append("ocsp_check INTEGER NOT NULL DEFAULT 0 REFERENCES OcspStatuses(code)")
        elif column == "signature_valid":
            occurrence.append("signature_valid INTEGER NOT NULL REFERENCES SignatureValidities(code)")
        elif kind in ("o", "onv"):
            occurrence.append(f"{column} {_stored_type(kind, declared)}")
    sql = COMMON_DDL
    sql += "CREATE TABLE CertificateData (\n    certificate_id INTEGER PRIMARY KEY,\n    " + ",\n    ".join(data) + "\n);\n"
    sql += "CREATE TABLE Occurrences (\n    " + ",\n    ".join(occurrence) + "\n);\n"
    if name == LEAF:
        sql += _ERROR_DDL
    return sql + views(name)


def _lookup(kind: str, alias: str, column: str, table: str = "c") -> tuple[str, str]:
    """(value expression, LEFT JOIN) of a TextValues/NumericValues reference."""
    lookup = "TextValues" if kind == "tv" else "NumericValues"
    return f"{alias}.value", f"LEFT JOIN {lookup} AS {alias} ON {alias}.value_id = {table}.{column}"


_OCCURRENCE_BASE = "FROM Occurrences AS o JOIN CertificateData AS c ON c.certificate_id = o.certificate_id"


def _certificate_select(name: str, kind: str, alias: str) -> tuple[str, str | None]:
    """(SELECT expression, JOIN or None) of an old 'Certificates' column."""
    if name == "certificate_id":
        return "o.occurrence_id AS certificate_id", None
    if name in ("issuer_id", "subject_id"):
        return f"o.occurrence_id AS {name}", None
    if kind in ("c", "o"):
        return f"{kind}.{name}", None
    if kind in ("tv", "nv", "onv"):
        expression, join = _lookup("nv" if kind == "onv" else kind, alias, name, "o" if kind == "onv" else "c")
        return f"{expression} AS {name}", join
    if name == "ocsp_check":
        return "os.name AS ocsp_check", "JOIN OcspStatuses AS os ON os.code = o.ocsp_check"
    if name == "signature_valid":
        return "sv.name AS signature_valid", "JOIN SignatureValidities AS sv ON sv.code = o.signature_valid"
    return "COALESCE(r.raw, r.der_zstd) AS raw", "LEFT JOIN RawCertificates AS r ON r.raw_id = c.raw_id"


def _certificates_view(db_type: str) -> str:
    select, joins = [], []
    for index, (name, _, kind) in enumerate(certificate_columns(db_type)):
        expression, join = _certificate_select(name, kind, f"v{index}")
        select.append(expression)
        if join is not None:
            joins.append(join)
    return f"CREATE VIEW Certificates AS SELECT {', '.join(select)} {_OCCURRENCE_BASE} {' '.join(joins)};"


def _subjects_view() -> str:
    select = ["o.occurrence_id AS subject_id"]
    joins = []
    for index, (name, _, kind, column) in enumerate(SUBJECT_COLUMNS):
        if kind == "tv":
            expression, join = _lookup(kind, f"s{index}", column)
            select.append(f"{expression} AS {name}")
            joins.append(join)
        else:
            select.append(f"c.{column} AS {name}")
    return f"CREATE VIEW Subjects AS SELECT {', '.join(select)} {_OCCURRENCE_BASE} {' '.join(joins)};"


def _extensions_view() -> str:
    select = ["o.occurrence_id AS extension_id", "o.occurrence_id AS certificate_id"]
    joins = []
    for index, (name, _, kind) in enumerate(EXTENSION_COLUMNS):
        if kind in ("tv", "nv"):
            expression, join = _lookup(kind, f"e{index}", name)
            select.append(f"{expression} AS {name}")
            joins.append(join)
        else:
            select.append(f"c.{name}")
    # The old layout never changed the CRL status from its insert value
    select.append("CAST('No Request Done' AS VARCHAR(26)) AS crl_revocation_status")
    return f"CREATE VIEW Extensions AS SELECT {', '.join(select)} {_OCCURRENCE_BASE} {' '.join(joins)};"


def views(db_type) -> str:
    """CREATE VIEW statements of the old tables."""
    name = type_name(db_type)
    out = [_certificates_view(name), _subjects_view(), _extensions_view()]
    out.append("CREATE VIEW Issuers AS SELECT o.occurrence_id AS issuer_id, "
               + ", ".join(f"i.{column}" for column, _ in ISSUER_COLUMNS)
               + ", COALESCE(r.raw, r.der_zstd) AS raw FROM Occurrences AS o "
               "JOIN IssuerData AS i ON i.issuer_id = o.issuer_id LEFT JOIN RawCertificates AS r ON r.raw_id = i.raw_id;")
    out.append(f"CREATE VIEW SignedCertificateTimestamps AS SELECT CAST(o.occurrence_id * {ROW_ID_STRIDE} + t.position + 1 "
               "AS INTEGER) AS id, o.occurrence_id AS certificate_id, CAST(t.log_id AS TEXT) AS log_id, t.timestamp, "
               "t.version, t.signature FROM Occurrences AS o JOIN SctData AS t ON t.certificate_id = o.certificate_id;")
    out.append(f"CREATE VIEW CertificatePolicies AS SELECT CAST(o.occurrence_id * {ROW_ID_STRIDE} + m.position + 1 "
               "AS INTEGER) AS policy_id, o.occurrence_id AS extension_id, p.policy_identifier, p.cps, p.policy_qualifiers, "
               f"p.is_cp_critical {_OCCURRENCE_BASE} JOIN PolicySetMembers AS m ON m.policy_set_id = c.policy_set_id "
               "JOIN PolicyData AS p ON p.policy_id = m.policy_id;")
    if name == LEAF:
        out.append("CREATE VIEW Errors AS SELECT e.error_id, e.domain, st.value AS status, pr.value AS protocol, "
                   "ts.value AS timestamp, e.error_message, ts.value AS download_date FROM ErrorData AS e "
                   "LEFT JOIN TextValues AS st ON st.value_id = e.status "
                   "LEFT JOIN TextValues AS pr ON pr.value_id = e.protocol "
                   "LEFT JOIN NumericValues AS ts ON ts.value_id = e.timestamp;")
    return "\n".join(out) + "\n"


def create(conn: sqlite3.Connection, db_type) -> None:
    """Create the layout on an empty database: page size first, then the tables, the codes and SchemaInfo."""
    name = type_name(db_type)
    if conn.in_transaction:
        conn.commit()
    conn.execute(f"PRAGMA page_size = {PAGE_SIZE}")
    conn.executescript("BEGIN;" + ddl(name) + "COMMIT;")
    conn.execute("BEGIN")
    try:
        conn.executemany("INSERT INTO OcspStatuses VALUES (?, ?)", enumerate(OCSP_STATUSES))
        conn.executemany("INSERT INTO SignatureValidities VALUES (?, ?)", enumerate(SIGNATURE_VALIDITIES))
        conn.executemany("INSERT INTO SchemaInfo VALUES (?, ?)",
                         [("schema_version", SCHEMA_VERSION), ("database_type", name)])
        conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
