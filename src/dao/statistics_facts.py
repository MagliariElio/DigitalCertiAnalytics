"""Statistics facts: the base tables of the database are read once, in parallel row ranges, and reduced to integer
identities, value codes and occurrence weights; the counts of the statistics are then computed from them with exact
deduplication by certificate identity.

Every distinct certificate is stored once (CertificateData) and every place where it was seen once (Occurrences); the
tables the statistics' queries read are views over them (db.schema). The facts are the results of those queries:
* the DISTINCT subqueries of StatisticsDAO count certificates by IDENTITY. Their values are stored per certificate,
  so they are counted over the CertificateData rows that appear in the Certificates view (at least one occurrence),
  except the values stored per occurrence (OCSP status, signature validity), counted over the occurrences;
* the other statistics count rows of the views (OCSP statuses, issuer organizations and countries, SCT months and
  operators, SCTs per certificate): every certificate row weighs as many rows as it has occurrences.

The identity of a certificate, COALESCE(NULLIF(subject_key_id, ''), raw), is keyed by SQLite type plus a 128-bit
BLAKE2b digest of its bytes (numbers by value); the raw is the original text (decoded from RawCertificates), so two
identities are merged exactly as the DISTINCT of the old tables merged them, barring a digest collision (probability
about n^2 / 2^129, 1e-25 for 6.5M certificates). The views show the raw as stored (compressed DER): their DISTINCT
differs only if a Subject Key Identifier equals the base64 text of another certificate. The keys become dense
integers; identities occurring on one row are counted directly, the others are deduplicated per (identity, value).
The value tuples keep their SQLite types, so StatisticsDAO runs the final GROUP BY / ORDER BY of each statistic on
them unchanged.

The statistics' expressions are evaluated on relations that have the columns of the views, with the same names,
values and affinities: `c` (per certificate: the Certificates, Subjects and Extensions columns stored per certificate;
per occurrence: ocsp_check and signature_valid), `Issuers`, `t` (SignedCertificateTimestamps), `p`
(CertificatePolicies) and `l` (Logs). An expression that does not fit one of them is left to its query.
"""
from __future__ import annotations

import hashlib
import sqlite3
from array import array
from concurrent.futures import Executor
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import numpy as np

from db import schema
from db.raw_codec import RawCodec

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Certificate identity of the DISTINCT subqueries of StatisticsDAO on the views, COALESCE(NULLIF(s.subject_key_id,
# ''), c.raw): the raw is read only for the certificates without a Subject Key Identifier (the views would otherwise
# look up the raw certificate of every row)
IDENTITY = ("COALESCE(NULLIF(s.subject_key_id, ''), (SELECT identity_row.raw FROM Certificates AS identity_row "
            "WHERE identity_row.certificate_id = c.certificate_id))")
NULL_IDENTITY = -1      # IDENTITY IS NULL: the row takes part in DISTINCT, COUNT ignores it
EXCLUDED = -2           # not in the inner join (e.g. a certificate without occurrences)
NO_POLICIES = -1        # policy set key of a certificate without policies

# Scan connections: small page cache (KiB; each page is read once, the operating system caches the file) and no
# memory map (sequential scans of large rows are about twice as fast with read() as with page faults)
_SCAN_CACHE_KIB = 4096
# Estimated seconds per key of each scan (SCTs: per certificate id, about 3 SCTs each), to split the tables into tasks
# of similar duration
_ROW_COST = {"occurrences": 0.4e-6, "certificates": 3e-6, "issuers": 0.9e-6, "sct": 2.7e-6, "policies": 1e-6}
_TASK_SECONDS = 0.5
# Expressions read as one value tuple (one dictionary lookup per row); a statistic never spans two groups
_GROUP_SIZE = 8
# Rows per step of the vectorized lookups and deduplications, identity digests per sort (bound the temporary arrays)
_CHUNK = 1 << 21
_DIGEST_CHUNK = 1 << 20
# Largest identities x values bitmap of a deduplication (bytes)
_BITMAP_CELLS = 1 << 26
_DIGEST_SIZE = 16

# Identity of a CertificateData row: (kind, content). The kind is the SQLite type of the Subject Key Identifier, or
# 'zstd' (content: the compressed DER, decoded to the original text) or the type of the raw kept verbatim; NULL when
# there is no raw. Numbers by value, everything else as bytes. The raw is read only for certificates without a
# Subject Key Identifier.
_SKI = "NULLIF(c.subject_key_id, '')"
_RAW = "FROM RawCertificates AS r WHERE r.raw_id = c.facts_raw_id"
_IDENTITY_COLUMNS = (
    f"CASE WHEN {_SKI} IS NOT NULL THEN typeof(c.subject_key_id) "
    f"ELSE (SELECT CASE WHEN r.der_zstd IS NOT NULL THEN 'zstd' ELSE typeof(r.raw) END {_RAW}) END",
    f"CASE WHEN {_SKI} IS NOT NULL THEN (CASE WHEN typeof(c.subject_key_id) IN ('integer', 'real') "
    "THEN c.subject_key_id ELSE CAST(c.subject_key_id AS BLOB) END) "
    "ELSE (SELECT CASE WHEN r.der_zstd IS NOT NULL THEN r.der_zstd WHEN typeof(r.raw) IN ('integer', 'real') "
    f"THEN r.raw ELSE CAST(r.raw AS BLOB) END {_RAW}) END")


class Unique(NamedTuple):
    """Distinct certificates per value of `columns` among the rows of a scan matching `where`."""
    scan: str                       # 'certificates' (relation c), 'policies' (p) or 'sct' (columns over Logs AS l)
    columns: tuple[str, ...]        # value expressions; none: a single count
    where: str = ""


@dataclass
class Request:
    """What to materialize: Unique statistics by name and the row counts of the other statistics."""
    unique: dict[str, Unique] = field(default_factory=dict)
    ocsp: str = ""                  # expression over c counted over all rows of the Certificates view
    issuers: tuple[str, str] = ("", "")     # organization (certificate rows joined to issuers), country (all issuers)
    sct_month: str = ""             # expression over t counted over all SCT rows
    sct_operator: str = ""          # expression over LogsOperators AS lo, for SCT rows with a log and an operator
    sct_per_certificate: bool = False
    errors_sql: str = ""            # Errors part, run as it is


@dataclass
class Facts:
    """Rows (values..., count) per statistic name ('certificates': the number of rows of the Certificates view); a
    statistic that could not be materialized is missing."""
    rows: dict[str, list[tuple]] = field(default_factory=dict)


# ---------------------------------------------------------------- relations

def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def _certificate_relation(present: set[str]) -> str:
    """Per CertificateData row: the view columns stored per certificate (names, values and affinities of the views;
    db.schema), plus the keys. LEFT JOINs whose values an expression does not use are left out by SQLite."""
    select = ["c.certificate_id AS facts_certificate_id", "c.policy_set_id AS facts_policy_set_id",
              "c.raw_id AS facts_raw_id"]
    joins = []
    columns = [(name, kind, name) for name, _, kind in schema.CERTIFICATE_COLUMNS if kind in ("c", "tv", "nv")]
    columns += [(name, kind, column) for name, _, kind, column in schema.SUBJECT_COLUMNS]
    columns += [(name, kind, name) for name, _, kind in schema.EXTENSION_COLUMNS]
    for index, (name, kind, column) in enumerate(columns):
        if column not in present:
            continue
        if kind == "c":
            select.append(f"c.{column} AS {name}")
        else:
            alias = f"lookup{index}"
            select.append(f"{alias}.value AS {name}")
            joins.append(f"LEFT JOIN {'TextValues' if kind == 'tv' else 'NumericValues'} AS {alias} "
                         f"ON {alias}.value_id = c.{column}")
    return (f"SELECT {', '.join(select)} FROM CertificateData AS c {' '.join(joins)} "
            "WHERE c.certificate_id BETWEEN ? AND ?")


def _code_relation(signature: bool) -> str:
    """Every combination of the per-occurrence codes, with the view columns (ocsp_check, signature_valid)."""
    if signature:
        return ("SELECT os.code AS facts_ocsp_code, sv.code AS facts_signature_code, os.name AS ocsp_check, "
                "sv.name AS signature_valid FROM OcspStatuses AS os CROSS JOIN SignatureValidities AS sv "
                "ORDER BY os.code, sv.code")
    return "SELECT os.code AS facts_ocsp_code, 0 AS facts_signature_code, os.name AS ocsp_check " \
           "FROM OcspStatuses AS os ORDER BY os.code"


_ISSUER_RELATION = ("SELECT issuer_id AS facts_issuer_id, "
                    + ", ".join(column for column, _ in schema.ISSUER_COLUMNS)
                    + " FROM IssuerData WHERE issuer_id BETWEEN ? AND ?")
_SCT_RELATION = ("SELECT certificate_id AS facts_certificate_id, log_id AS facts_log_id, CAST(log_id AS TEXT) AS log_id, "
                 "timestamp, version, signature FROM SctData WHERE certificate_id BETWEEN ? AND ?")
_POLICY_RELATION = ("SELECT m.policy_set_id AS facts_policy_set_id, d.policy_identifier, d.cps, d.policy_qualifiers, "
                    "d.is_cp_critical FROM PolicySetMembers AS m JOIN PolicyData AS d ON d.policy_id = m.policy_id "
                    "WHERE m.policy_set_id BETWEEN ? AND ?")


class _Kind(NamedTuple):
    """A scan: SELECT with the key columns first ({columns} = value expressions; {relation} = the relation), the table
    and column of its ranges, number of key columns (the first one is the table's own id when `own`)."""
    sql: str
    table: str
    column: str
    keys: int
    own: bool


_KINDS = {
    "occurrences": _Kind("SELECT o.certificate_id, o.issuer_id, o.ocsp_check, {signature} FROM Occurrences AS o "
                         "WHERE o.occurrence_id BETWEEN ? AND ?", "Occurrences", "occurrence_id", 4, False),
    "certificates": _Kind(f"SELECT c.facts_certificate_id, IFNULL(c.facts_policy_set_id, {NO_POLICIES}), "
                          f"{', '.join(_IDENTITY_COLUMNS)}{{columns}} FROM ({{relation}}) AS c",
                          "CertificateData", "certificate_id", 2, True),
    "issuers": _Kind(f"SELECT Issuers.facts_issuer_id{{columns}} FROM ({_ISSUER_RELATION}) AS Issuers",
                     "IssuerData", "issuer_id", 1, True),
    "sct": _Kind(f"SELECT t.facts_certificate_id, t.facts_log_id{{columns}} FROM ({_SCT_RELATION}) AS t",
                 "SctData", "certificate_id", 2, False),
    "policies": _Kind(f"SELECT p.facts_policy_set_id{{columns}} FROM ({_POLICY_RELATION}) AS p",
                      "PolicySetMembers", "policy_set_id", 1, False),
}


# ---------------------------------------------------------------- worker side

def _connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{Path(path).as_uri()}?mode=ro", uri=True)
    connection.execute(f"PRAGMA cache_size = {-_SCAN_CACHE_KIB}")
    return connection


def _pack(values: array, dense: bool = False) -> tuple:
    """Integer column in its smallest form: ('range', first) for consecutive ids, else (dtype, bytes)."""
    column = np.frombuffer(values, dtype=np.int64) if values.typecode == "q" else np.frombuffer(values, dtype=np.int32)
    if dense and len(column) and int(column[-1]) - int(column[0]) == len(column) - 1 \
            and bool((np.diff(column) == 1).all()):
        return ("range", int(column[0]))
    for dtype in (np.int8, np.int16, np.int32):
        info = np.iinfo(dtype)
        if not len(column) or (info.min <= column.min() and column.max() <= info.max):
            return (np.dtype(dtype).str, column.astype(dtype).tobytes())
    return (column.dtype.str, column.tobytes())


def scan(path: str, sql: str, keys: int, own: bool, identity: bool, sizes: list[int], low: int, high: int) -> dict:
    """Read the rows low..high of one scan: packed key columns (plus the local identity numbers when `identity`) and
    the codes of the value tuples of each group of `sizes` expressions."""
    columns = keys + (1 if identity else 0)
    arrays = [array("q") for _ in range(columns)]
    tables: list[dict[tuple, int]] = [{} for _ in sizes]
    codes = [array("i") for _ in sizes]
    bounds, start = [], columns
    for size in sizes:
        bounds.append((start, start + size))
        start += size
    identities: dict[bytes, int] = {}
    connection = _connect(path)
    try:
        cursor = connection.execute(sql, (low, high))
        if identity:
            cursor = _identities(cursor, keys, identities, connection)
        _read(cursor, columns, arrays, tables, codes, bounds)
    finally:
        connection.close()
    return {"rows": len(arrays[0]), "keys": [_pack(a, dense=own and i == 0) for i, a in enumerate(arrays)],
            "codes": [_pack(c) for c in codes], "values": [list(t) for t in tables], "identities": b"".join(identities)}


def _read(cursor, columns: int, arrays: list[array], tables: list[dict], codes: list[array],
          bounds: list[tuple[int, int]]) -> None:
    keys = [(i, a.append) for i, a in enumerate(arrays[:columns])]
    groups = [(table, code.append, low, high) for table, code, (low, high) in zip(tables, codes, bounds)]
    if not groups and columns == 4:     # the occurrences: integer keys only
        append0, append1, append2, append3 = (a.append for a in arrays)
        for row in cursor:
            append0(row[0])
            append1(row[1])
            append2(row[2])
            append3(row[3])
        return
    for row in cursor:
        for i, append in keys:
            append(row[i])
        for table, append, low, high in groups:
            value = row[low:high]
            code = table.get(value)
            if code is None:
                code = table[value] = len(table)
            append(code)


def _identity_key(kind: str, value) -> bytes:
    """Digest with the equality of SQLite's DISTINCT: same type and bytes; numbers by value (7 = 7.0)."""
    if kind in ("integer", "real"):
        if isinstance(value, float) and value.is_integer() and -2 ** 63 <= value < 2 ** 63:
            value = int(value)
        data = b"n" + repr(value).encode()
    else:
        data = kind[0].encode() + value
    return hashlib.blake2b(data, digest_size=_DIGEST_SIZE).digest()


def _identities(cursor: sqlite3.Cursor, keys: int, identities: dict[bytes, int], connection: sqlite3.Connection):
    """Rows of the certificates scan with the identity as a local number (0, 1, ... in order of appearance; -1 NULL)
    in place of its two columns after the keys; `identities` gets the digest of each number."""
    codec = None
    for row in cursor:
        kind = row[keys]
        if kind is None or kind == "null":
            number = NULL_IDENTITY
        else:
            value = row[keys + 1]
            if kind == "zstd":      # the original base64 text of the DER
                if codec is None:
                    codec = RawCodec.for_connection(connection)
                kind, value = "text", codec.decode(value, None).encode("ascii")
            key = _identity_key(kind, value)
            number = identities.get(key)
            if number is None:
                number = identities[key] = len(identities)
        yield (*row[:keys], number, *row[keys + 2:])


def query(path: str, sql: str) -> list[tuple]:
    connection = _connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


# ---------------------------------------------------------------- planning

def _flag(where: str) -> str:
    return f"CASE WHEN ({where}) THEN 1 ELSE 0 END"


class _Scan:
    """SQL of one scan, its expression groups and, per statistic, its group, value positions and flag position."""

    def __init__(self, kind: str, relation: str = "", signature: bool = False) -> None:
        self.kind = kind
        self.relation = relation
        self.signature = signature
        self.groups: list[list[str]] = []
        self.positions: dict[str, tuple[int, list[int], int | None]] = {}

    def sql(self, expressions: list[str] | None = None) -> str:
        columns = "".join(f", {e}" for e in (expressions if expressions is not None else
                                             [e for group in self.groups for e in group]))
        return _KINDS[self.kind].sql.format(columns=columns, relation=self.relation,
                                            signature="o.signature_valid" if self.signature else "0")

    def add(self, name: str, columns: tuple[str, ...], where: str) -> None:
        expressions = [*columns, *([_flag(where)] if where else [])]
        if not self.groups or len(set(self.groups[-1]) | set(expressions)) > _GROUP_SIZE:
            self.groups.append([])
        group = self.groups[-1]
        for expression in expressions:
            if expression not in group:
                group.append(expression)
        self.positions[name] = (len(self.groups) - 1, [group.index(c) for c in columns],
                                group.index(expressions[-1]) if where else None)


def _readable(connection: sqlite3.Connection, scan_: _Scan, expressions: list[str]) -> bool:
    """Whether the scan can read the expressions (a column can be missing in a database type)."""
    try:
        connection.execute(f"SELECT * FROM ({scan_.sql(expressions)}) LIMIT 0", (0, -1)).fetchall()
        return True
    except sqlite3.Error:
        return False


def _expressions(unique: Unique) -> list[str]:
    return [*unique.columns, *([_flag(unique.where)] if unique.where else [])]


class _Codes:
    """Statistics over the per-occurrence codes: every combination of the codes (ocsp_check, signature_valid) with
    the value tuple of each statistic, evaluated once on the code relation."""

    def __init__(self, connection: sqlite3.Connection, signature: bool) -> None:
        self.relation = _code_relation(signature)
        self.ocsp = np.array([row[0] for row in connection.execute("SELECT code FROM OcspStatuses ORDER BY code")],
                             dtype=np.int64)
        self.signature = np.array([row[0] for row in connection.execute(
            "SELECT code FROM SignatureValidities ORDER BY code")] if signature else [0], dtype=np.int64)
        self.values: dict[str, list[tuple | None]] = {}     # per combination: value tuple, None if not matching

    def add(self, connection: sqlite3.Connection, name: str, columns: tuple[str, ...], where: str = "") -> bool:
        """Evaluate a statistic on every combination; False if its expressions do not fit the relation."""
        try:
            rows = connection.execute(f"SELECT {', '.join([*columns, _flag(where or '1')])} "
                                      f"FROM ({self.relation}) AS c").fetchall()
        except sqlite3.Error:
            return False
        if len(rows) != len(self.ocsp) * len(self.signature):
            return False
        self.values[name] = [tuple(row[:-1]) if row[-1] == 1 else None for row in rows]
        return True

    def combinations(self, ocsp: np.ndarray, signature: np.ndarray) -> np.ndarray:
        """Combination of each occurrence's codes; -1 when a code is not in its table (not in the view)."""
        ocsp_index, signature_index = _sorted_positions(self.ocsp, ocsp), _sorted_positions(self.signature, signature)
        combined = ocsp_index.astype(np.int64) * len(self.signature) + signature_index
        return np.where((ocsp_index >= 0) & (signature_index >= 0), combined, -1)

    def statistic(self, name: str) -> tuple[np.ndarray, list[tuple]]:
        """Per combination the code of the statistic's value tuple (-1 when not matching); the tuples."""
        index: dict[tuple, int] = {}
        lookup = np.array([-1 if value is None else index.setdefault(value, len(index)) for value in self.values[name]],
                          dtype=np.int32)
        return lookup, list(index)


def _sorted_positions(sorted_ids: np.ndarray, keys: np.ndarray) -> np.ndarray:
    """Position of each key in the sorted unique ids, -1 when absent."""
    if not len(sorted_ids):
        return np.full(len(keys), -1, dtype=np.int64)
    sorted_ids, keys = sorted_ids.astype(np.int64), keys.astype(np.int64)
    position = np.searchsorted(sorted_ids, keys).clip(0, len(sorted_ids) - 1)
    return np.where(sorted_ids[position] == keys, position, -1)


def _log_values(connection: sqlite3.Connection, unique: Unique) -> dict | None:
    """Value tuple of a statistic per log id (None for the logs it excludes); None if its expressions fail on Logs."""
    try:
        rows = connection.execute(f"SELECT l.id, {', '.join(unique.columns)}, {_flag(unique.where or '1')} "
                                  "FROM Logs AS l").fetchall()
    except sqlite3.Error:
        return None
    return {row[0]: tuple(row[1:-1]) if row[-1] == 1 else None for row in rows}


@dataclass
class _Plan:
    scans: dict[str, _Scan]
    codes: _Codes
    unique: dict[str, Unique] = field(default_factory=dict)
    occurrence_unique: list[str] = field(default_factory=list)  # Unique statistics over the per-occurrence codes
    logs: dict[str, dict] = field(default_factory=dict)         # SCT statistics: log id -> value tuple
    operators: dict | None = None                               # log id -> operator value


def _plan_unique(connection: sqlite3.Connection, request: Request, plan: _Plan) -> None:
    for name, unique in request.unique.items():
        if unique.scan == "sct":
            values = _log_values(connection, unique)
            if values is not None:
                plan.logs[name] = values
                plan.unique[name] = unique
        elif unique.scan in plan.scans and _readable(connection, plan.scans[unique.scan], _expressions(unique)):
            plan.scans[unique.scan].add(name, unique.columns, unique.where)
            plan.unique[name] = unique
        elif unique.scan == "certificates" and plan.codes.add(connection, name, unique.columns, unique.where):
            plan.occurrence_unique.append(name)
            plan.unique[name] = unique
    if request.sct_operator:
        try:
            plan.operators = dict(connection.execute(
                f"SELECT l.id, {request.sct_operator} FROM Logs AS l JOIN LogsOperators AS lo "
                "ON l.operator_id = lo.id").fetchall())
        except sqlite3.Error:
            pass
    if request.sct_per_certificate:
        plan.unique["sct_per_certificate"] = Unique("sct", ())


def _plan(connection: sqlite3.Connection, request: Request) -> _Plan:
    """Scans to run; statistics whose expressions cannot be read are left out (the caller runs their SQL)."""
    signature = "signature_valid" in _table_columns(connection, "Occurrences")
    present = _table_columns(connection, "CertificateData")
    if not present:
        raise ValueError("the database has no CertificateData table")
    scans = {"occurrences": _Scan("occurrences", signature=signature),
             "certificates": _Scan("certificates", _certificate_relation(present)),
             "issuers": _Scan("issuers"), "sct": _Scan("sct"), "policies": _Scan("policies")}
    plan = _Plan(scans, _Codes(connection, signature))
    _plan_unique(connection, request, plan)
    if request.ocsp:
        plan.codes.add(connection, "ocsp", (request.ocsp,))
    added = (("issuers", "issuers", request.issuers), ("sct_month", "sct", (request.sct_month,)))
    for name, kind, columns in added:
        if columns[0] and _readable(connection, plan.scans[kind], list(columns)):
            plan.scans[kind].add(name, columns, "")
    needed = {kind for kind, s in plan.scans.items() if s.positions} | {u.scan for u in plan.unique.values()}
    needed |= {"sct"} if plan.operators is not None else set()
    if needed or "ocsp" in plan.codes.values or request.errors_sql:     # 'certificates': rows of the view
        needed |= {"occurrences", "certificates"}
    plan.scans = {kind: plan.scans[kind] for kind in _KINDS if kind in needed}
    return plan


def _ranges(connection: sqlite3.Connection, kind: str, workers: int) -> list[tuple[int, int]]:
    spec = _KINDS[kind]
    # Two subqueries: SQLite reads MIN or MAX of the key from the b-tree ends only when it is alone
    low, high = connection.execute(f"SELECT (SELECT MIN({spec.column}) FROM {spec.table}), "
                                   f"(SELECT MAX({spec.column}) FROM {spec.table})").fetchone()
    if low is None:
        return []
    keys = high - low + 1
    tasks = max(1, min(4 * workers, round(keys * _ROW_COST[kind] / _TASK_SECONDS)))
    step = -(-keys // tasks)
    return [(start, min(start + step - 1, high)) for start in range(low, high + 1, step)]


class _Done:
    """Task run in this process; like a Future, its error is raised by result()."""

    def __init__(self, function, *args) -> None:
        self._value, self._error = None, None
        try:
            self._value = function(*args)
        except Exception as e:
            self._error = e

    def result(self):
        if self._error is not None:
            raise self._error
        return self._value

    @staticmethod
    def cancel() -> bool:
        return False


def collect(path: str, request: Request, executor: Executor | None = None, workers: int = 1) -> Facts:
    """Materialize the requested statistics of the database file, reading each table once.

    The scans run in `executor` (e.g. the render processes) or here when it is None. Raises on any error: the caller
    then runs the statistics' own queries.
    """
    connection = _connect(path)
    try:
        plan = _plan(connection, request)
        ranges = {kind: _ranges(connection, kind, workers) for kind in plan.scans}
    finally:
        connection.close()

    def submit(function, *args):
        return _Done(function, *args) if executor is None else executor.submit(function, *args)

    tasks = sorted(((kind, task) for kind, items in ranges.items() for task in items),
                   key=lambda item: -(item[1][1] - item[1][0]) * _ROW_COST[item[0]])
    errors = submit(query, path, request.errors_sql) if request.errors_sql else None
    futures = {}
    for kind, task in tasks:
        scan_ = plan.scans[kind]
        spec = _KINDS[kind]
        futures[(kind, task)] = submit(scan, path, scan_.sql(), spec.keys, spec.own,
                                       kind == "certificates", [len(g) for g in scan_.groups],
                                       *task)

    def rows(kind: str) -> _Rows:
        return _Rows([futures.pop((kind, task)).result() for task in ranges[kind]], plan.scans[kind])

    try:
        return _gather(plan, errors, rows)
    except BaseException:
        for future in futures.values():     # scans not started yet would delay the queries that replace them
            future.cancel()
        raise


def _gather(plan: _Plan, errors, rows) -> Facts:
    facts = Facts()
    if errors is not None:
        try:
            facts.rows["errors"] = errors.result()
        except sqlite3.Error:
            pass
    if plan.scans:
        _aggregate(facts, plan, rows)
    return facts


def _aggregate(facts: Facts, plan: _Plan, rows) -> None:
    certificates = _Certificates(rows("certificates"))
    occurrences = _Occurrences(rows("occurrences"), certificates, plan.codes)
    facts.rows["certificates"] = [(occurrences.count,)]
    certificates.add_facts(facts, plan, occurrences.weights > 0)
    occurrences.add_facts(facts, plan, certificates)
    if "issuers" in plan.scans:
        _issuer_facts(facts, rows("issuers"), occurrences)
    if "policies" in plan.scans:
        _policy_facts(facts, rows("policies"), certificates, occurrences.weights > 0, plan)
    if "sct" in plan.scans:
        _sct_facts(facts, rows("sct"), certificates, occurrences, plan)


# ---------------------------------------------------------------- aggregation

def _unpack(packed: tuple, rows: int) -> np.ndarray:
    if packed[0] == "range":
        return np.arange(packed[1], packed[1] + rows, dtype=np.int64)
    return np.frombuffer(packed[1], dtype=np.dtype(packed[0]))


def _narrow(values: np.ndarray) -> np.ndarray:
    """int32 when the values fit."""
    if len(values) and values.dtype.itemsize > 4 and np.iinfo(np.int32).min <= values.min() \
            and values.max() <= np.iinfo(np.int32).max:
        return values.astype(np.int32)
    return values


class _Index:
    """Sorted unique ids (a table's rowid): a range when consecutive, else an array."""

    def __init__(self, low: int | None, count: int, ids: np.ndarray | None = None) -> None:
        self.low, self.count, self.ids = low, count, ids

    @classmethod
    def of(cls, parts: list[tuple[tuple, int]]) -> _Index:
        """From the packed id columns of the tasks, in order."""
        count = sum(rows for _, rows in parts)
        low = parts[0][0][1] if parts and parts[0][0][0] == "range" else None
        expected = low
        for packed, rows in parts:
            if expected is None or packed[0] != "range" or packed[1] != expected:
                return cls(None, count, np.concatenate([_unpack(packed, rows).astype(np.int64) for packed, rows in parts]))
            expected += rows
        return cls(low, count)

    def positions(self, keys: np.ndarray) -> np.ndarray:
        """Row of each key (int32/int64), -1 when absent."""
        result = np.empty(len(keys), dtype=np.int32 if self.count < 2 ** 31 else np.int64)
        for start in range(0, len(keys), _CHUNK):
            chunk = keys[start:start + _CHUNK].astype(np.int64)
            if self.low is not None:
                position = chunk - self.low
                found = (position >= 0) & (position < self.count)
            elif self.count:
                position = np.searchsorted(self.ids, chunk).clip(0, self.count - 1)
                found = self.ids[position] == chunk
            else:
                position, found = chunk, np.zeros(len(chunk), dtype=bool)
            result[start:start + _CHUNK] = np.where(found, position, -1)
        return result


class _Rows:
    """Rows of one scan in key order: key columns and value codes renumbered over all its tasks."""

    def __init__(self, results: list[dict], scan_: _Scan) -> None:
        self.scan = scan_
        self.count = sum(result["rows"] for result in results)
        own = _KINDS[scan_.kind].own
        self.index = _Index.of([(result["keys"][0], result["rows"]) for result in results]) if own else None
        columns = len(results[0]["keys"]) if results else _KINDS[scan_.kind].keys
        self.keys = [None if own and i == 0 else
                     _narrow(np.concatenate([_unpack(r["keys"][i], r["rows"]) for r in results]))
                     if results else np.zeros(0, np.int64) for i in range(columns)]
        self.values: list[list[tuple]] = []
        self.codes: list[np.ndarray] = []
        for g in range(len(scan_.groups)):
            index: dict[tuple, int] = {}
            parts = []
            for result in results:
                local = np.array([index.setdefault(value, len(index)) for value in result["values"][g]], dtype=np.int32)
                codes = _unpack(result["codes"][g], result["rows"])
                parts.append(local[codes] if len(local) else codes.astype(np.int32))
            self.values.append(list(index))
            self.codes.append(np.concatenate(parts) if parts else np.zeros(0, np.int32))
        self.identities = [(result.get("identities", b""), result["rows"]) for result in results]

    def statistic(self, name: str) -> tuple[np.ndarray, np.ndarray, list[tuple]]:
        """Per row: the code of the statistic's value tuple and whether the row matches its condition; the tuples."""
        group, columns, flag = self.scan.positions[name]
        index: dict[tuple, int] = {}
        lookup = np.empty(len(self.values[group]), dtype=np.int32)
        valid = np.empty(len(self.values[group]), dtype=bool)
        for code, value in enumerate(self.values[group]):
            lookup[code] = index.setdefault(tuple(value[p] for p in columns), len(index))
            valid[code] = flag is None or value[flag] == 1
        codes = self.codes[group]
        return lookup[codes], valid[codes], list(index)

    def counts(self, name: str, weights: np.ndarray, rows: np.ndarray | None = None) -> list[tuple]:
        """Weighted rows per value tuple (no deduplication), only `rows` (a mask) when given."""
        codes, _, values = self.statistic(name)
        if rows is not None:
            codes, weights = codes[rows], weights[rows]
        return _weighted(codes, weights, values)


def _weighted(codes: np.ndarray, weights: np.ndarray, values: list[tuple]) -> list[tuple]:
    """(values..., sum of the weights) per value tuple with a positive sum, in tuple order."""
    counts = np.bincount(codes, weights=weights, minlength=len(values)) if len(codes) else np.zeros(len(values))
    return [(*value, int(round(counts[code]))) for code, value in enumerate(values) if counts[code]]


class _Repeated:
    """Rows whose identity (>= 0) occurs on other rows too; identities are dense numbers below `count`."""

    def __init__(self, identities: np.ndarray, count: int) -> None:
        self.count = count
        self.mask = np.zeros(len(identities), dtype=bool)
        counted = identities >= 0
        if counted.any():
            ids = identities[counted]
            self.mask[counted] = (np.bincount(ids, minlength=count) > 1)[ids]


def _distinct_pairs(ids: np.ndarray, codes: np.ndarray, size: int, count: int) -> np.ndarray:
    """Distinct identities (dense numbers below `count`) per value code: with a bitmap of identities x values when it
    is small, else by sorting (identity, value) keys in identity ranges of about _CHUNK rows."""
    if count * size <= _BITMAP_CELLS:
        seen = np.zeros(count * size, dtype=bool)
        seen[ids.astype(np.int64) * size + codes.astype(np.int64)] = True
        return seen.reshape(count, size).sum(axis=0)
    counts = np.zeros(size, dtype=np.int64)
    buckets = max(1, -(-len(ids) // _CHUNK))
    width = count // buckets + 1
    for bucket in range(buckets):
        selected = np.flatnonzero((ids >= bucket * width) & (ids < (bucket + 1) * width)) if buckets > 1 else slice(None)
        keys = ids[selected].astype(np.int64) * size + codes[selected].astype(np.int64)
        counts += np.bincount(np.unique(keys) % size, minlength=size)
    return counts


def _unique_rows(identities: np.ndarray, count: int, codes: np.ndarray, valid: np.ndarray, values: list[tuple],
                 always: bool = False) -> list[tuple]:
    """(values..., distinct non-NULL identities) per value tuple over the rows with `valid` (identities: dense numbers
    below `count`, NULL_IDENTITY or EXCLUDED); tuples seen only with a NULL identity count 0."""
    valid = valid & (identities != EXCLUDED)
    identities, codes = identities[valid], codes[valid]
    size = len(values)
    present = np.zeros(size, dtype=bool)
    present[codes[identities == NULL_IDENTITY]] = True
    counted = identities >= 0
    identities, codes = identities[counted], codes[counted]
    repeated = _Repeated(identities, count).mask
    counts = np.bincount(codes[~repeated], minlength=size).astype(np.int64)
    if repeated.any():
        counts += _distinct_pairs(identities[repeated], codes[repeated], size, count)
    rows = [(*value, int(counts[code])) for code, value in enumerate(values) if counts[code] or present[code]]
    return rows if rows or not always else [(0,)]


class _Certificates:
    """CertificateData rows in certificate_id order with their identity numbered 0..n-1 (or NULL_IDENTITY)."""

    def __init__(self, rows: _Rows) -> None:
        self.rows = rows
        self.policy_sets = rows.keys[1]
        identities = rows.keys[2].astype(np.int64) if len(rows.keys) > 2 else np.full(rows.count, NULL_IDENTITY)
        self.count = _number_identities(identities, rows.identities)
        rows.identities = []
        self.identities = _narrow(identities)

    def add_facts(self, facts: Facts, plan: _Plan, members: np.ndarray) -> None:
        """Unique statistics of the values stored per certificate, over the certificates with occurrences."""
        for name in self.rows.scan.positions:
            codes, valid, values = self.rows.statistic(name)
            facts.rows[name] = _unique_rows(self.identities, self.count, codes, valid & members, values,
                                            always=not plan.unique[name].columns)

    def identities_of(self, positions: np.ndarray, members: np.ndarray) -> np.ndarray:
        """Identity of the certificate at each position; EXCLUDED without a certificate or occurrences."""
        found = positions >= 0
        result = np.full(len(positions), EXCLUDED, dtype=np.int64)
        result[found] = np.where(members[positions[found]], self.identities[positions[found]], EXCLUDED)
        return _narrow(result)


class _Occurrences:
    """Occurrences joined to their certificate: the rows of the Certificates view and the weights of the certificate
    rows (their rows in the view)."""

    def __init__(self, rows: _Rows, certificates: _Certificates, codes: _Codes) -> None:
        self.rows = rows
        self.codes = codes
        self.certificate_ids = rows.keys[0]
        self.issuer_ids = rows.keys[1]
        self.certificate = certificates.rows.index.positions(self.certificate_ids)
        self.combinations = codes.combinations(rows.keys[2], rows.keys[3])
        self.view = (self.certificate >= 0) & (self.combinations >= 0)
        self.count = int(self.view.sum())
        self.weights = np.bincount(self.certificate[self.view], minlength=certificates.rows.count)
        self.positions = self.certificate[self.view]

    def add_facts(self, facts: Facts, plan: _Plan, certificates: _Certificates) -> None:
        """OCSP rows and the Unique statistics of the values stored per occurrence."""
        combinations = self.combinations[self.view]
        if "ocsp" in self.codes.values:
            lookup, values = self.codes.statistic("ocsp")
            codes = lookup[combinations]
            facts.rows["ocsp"] = _weighted(codes[codes >= 0], np.ones(int((codes >= 0).sum())), values)
        if plan.occurrence_unique:
            identities = certificates.identities[self.positions]
            for name in plan.occurrence_unique:
                lookup, values = self.codes.statistic(name)
                codes = lookup[combinations]
                facts.rows[name] = _unique_rows(identities, certificates.count, np.maximum(codes, 0), codes >= 0,
                                                values, always=not plan.unique[name].columns)

    def certificate_counts(self, certificate_ids: np.ndarray, positions: np.ndarray) -> np.ndarray:
        """Occurrences (all, in the view or not) of each certificate id (`positions`: its CertificateData row)."""
        known = self.certificate >= 0
        every = np.bincount(self.certificate[known], minlength=len(self.weights))
        result = np.zeros(len(certificate_ids), dtype=np.int64)
        found = positions >= 0
        result[found] = every[positions[found]]
        if not found.all() and not known.all():     # ids without a certificate row on both sides
            missing, counts = np.unique(self.certificate_ids[~known], return_counts=True)
            position = _sorted_positions(missing, certificate_ids[~found])
            result[~found] = np.where(position >= 0, counts[position], 0)
        return result


def _number_identities(identities: np.ndarray, tasks: list[tuple[bytes, int]]) -> int:
    """Replace the local identity numbers of every task (>= 0) by global ones 0..n-1, equal for equal digests; n."""
    joined = b"".join(digest for digest, _ in tasks)
    digests = np.frombuffer(joined, dtype=f"V{_DIGEST_SIZE}")
    numbers = np.empty(len(digests), dtype=np.int64)
    buckets = max(1, -(-len(digests) // _DIGEST_CHUNK))
    # Bucket of each digest from its first two bytes: uniform, so the buckets are balanced
    leading = np.frombuffer(joined, dtype=">u2")[::_DIGEST_SIZE // 2].astype(np.int64) % buckets if buckets > 1 else None
    count = 0
    for bucket in range(buckets):
        selected = np.flatnonzero(leading == bucket) if buckets > 1 else slice(None)
        unique, inverse = np.unique(digests[selected], return_inverse=True)
        numbers[selected] = count + inverse.reshape(-1)
        count += len(unique)
    offset, start = 0, 0
    for digest, rows in tasks:
        size = len(digest) // _DIGEST_SIZE
        part = identities[offset:offset + rows]
        local = part >= 0
        part[local] = numbers[start:start + size][part[local]]
        offset, start = offset + rows, start + size
    return count


def _issuer_facts(facts: Facts, issuers: _Rows, occurrences: _Occurrences) -> None:
    """Organizations over the rows of the Certificates view joined to their issuer, countries over all rows of the
    Issuers view (every occurrence with its issuer row)."""
    codes, _, values = issuers.statistic("issuers")
    position = issuers.index.positions(occurrences.issuer_ids)
    found = position >= 0
    joined = np.bincount(codes[position[found & occurrences.view]], minlength=len(values))
    every = np.bincount(codes[position[found]], minlength=len(values))
    organizations: dict = {}
    countries: dict = {}
    for code, (organization, country) in enumerate(values):
        if joined[code]:
            organizations[organization] = organizations.get(organization, 0) + int(joined[code])
        if every[code]:
            countries[country] = countries.get(country, 0) + int(every[code])
    facts.rows["organizations"] = list(organizations.items())
    facts.rows["countries"] = list(countries.items())


def _policy_facts(facts: Facts, policies: _Rows, certificates: _Certificates, members: np.ndarray,
                  plan: _Plan) -> None:
    """Unique statistics over the policies of the certificates with occurrences (the members of their policy set)."""
    order = np.argsort(policies.keys[0], kind="stable")
    set_ids = policies.keys[0][order]
    sets, first, sizes = np.unique(set_ids, return_index=True, return_counts=True)
    position = _sorted_positions(sets, certificates.policy_sets)
    selected = np.flatnonzero((position >= 0) & members)
    counts = sizes[position[selected]]
    identities = np.repeat(certificates.identities[selected], counts)
    # Member rows of every selected certificate: the start of its set plus 0, 1, ... within it
    starts = np.repeat(first[position[selected]] - (np.cumsum(counts) - counts), counts)
    member = order[starts + np.arange(len(identities))]
    for name in policies.scan.positions:
        codes, valid, values = policies.statistic(name)
        facts.rows[name] = _unique_rows(identities, certificates.count, codes[member], valid[member], values,
                                        always=not plan.unique[name].columns)


def _sct_facts(facts: Facts, sct: _Rows, certificates: _Certificates, occurrences: _Occurrences,
               plan: _Plan) -> None:
    """Unique statistics over the logs, per-month and per-operator SCT counts (rows of the SCT view: every SCT of a
    certificate once per occurrence), SCTs per row of the Certificates view."""
    certificate_ids, log_ids = sct.keys
    position = certificates.rows.index.positions(certificate_ids)
    weights = occurrences.certificate_counts(certificate_ids, position)
    if "sct_month" in sct.scan.positions:
        facts.rows["sct_month"] = sct.counts("sct_month", weights)
    logs, log_codes = _log_codes(log_ids)
    if plan.operators is not None:
        per_log = np.bincount(log_codes, weights=weights, minlength=len(logs) + 1) if len(log_codes) else \
            np.zeros(len(logs) + 1)
        operators: dict = {}
        for code, log in enumerate(logs.tolist()):
            if log in plan.operators and per_log[code]:
                operators[plan.operators[log]] = operators.get(plan.operators[log], 0) + int(round(per_log[code]))
        facts.rows["sct_operators"] = list(operators.items())
    if "sct_per_certificate" in plan.unique:
        per_certificate = np.bincount(position[position >= 0], minlength=certificates.rows.count)
        histogram = np.bincount(per_certificate, weights=occurrences.weights) if len(per_certificate) else []
        facts.rows["sct_per_certificate"] = [(count, int(round(n))) for count, n in enumerate(histogram) if n]
    if plan.logs:
        identities = certificates.identities_of(position, occurrences.weights > 0)
        _log_facts(facts, plan, identities, certificates.count, logs, log_codes)


def _log_codes(log_ids: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Sorted distinct log ids and, per SCT row, the index of its log."""
    if not len(log_ids):
        return np.zeros(0, np.int64), np.zeros(0, np.int32)
    logs, codes = np.unique(log_ids.astype(np.int64), return_inverse=True)
    return logs, codes.reshape(-1).astype(np.int32)


def _log_facts(facts: Facts, plan: _Plan, identities: np.ndarray, count: int, logs: np.ndarray,
               log_codes: np.ndarray) -> None:
    """Unique statistics whose values come from the log of each SCT."""
    for name, values_by_log in plan.logs.items():
        index: dict[tuple, int] = {}
        lookup = np.full(len(logs) + 1, -1, dtype=np.int32)
        for code, log in enumerate(logs.tolist()):
            value = values_by_log.get(log)
            if value is not None:
                lookup[code] = index.setdefault(value, len(index))
        codes = lookup[log_codes]
        facts.rows[name] = _unique_rows(identities, count, np.maximum(codes, 0), codes >= 0, list(index),
                                        always=not plan.unique[name].columns)
