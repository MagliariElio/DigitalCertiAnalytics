"""Statistics facts: every table is read once, in parallel row ranges, and reduced to per-row integer identities and
value codes; the counts of the statistics are then computed from them with exact deduplication by certificate
identity.

The DISTINCT subqueries of StatisticsDAO count certificates by IDENTITY, COALESCE(NULLIF(subject_key_id, ''), raw).
The scans compute that expression in SQL and key it by SQLite type plus a 128-bit BLAKE2b digest of its bytes (numbers
by value), so two identities are merged exactly when SQLite's DISTINCT would merge them, barring a digest collision
(probability about n^2 / 2^129, 1e-25 for 6.5M certificates). The keys become dense integers; identities occurring on
one row are counted directly, the others are deduplicated per (identity, value). The value tuples keep their SQLite
types, so StatisticsDAO runs the final GROUP BY / ORDER BY of each statistic on them unchanged.
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

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Certificate identity of the DISTINCT subqueries (StatisticsDAO uses this expression)
IDENTITY = "COALESCE(NULLIF(s.subject_key_id, ''), c.raw)"
NULL_IDENTITY = -1      # IDENTITY IS NULL: the row takes part in DISTINCT, COUNT ignores it
EXCLUDED = -2           # not in the inner join (certificate without subject, row without certificate)
NO_KEY = -(2 ** 63)     # join key matching no row (NULL, text or real)

# Scan connections: small page cache (KiB; each page is read once, the operating system caches the file) and no
# memory map (sequential scans of large rows are about twice as fast with read() as with page faults)
_SCAN_CACHE_KIB = 4096
# Estimated seconds per row of each scan, to split the tables into tasks of similar duration
_ROW_COST = {"certificates": 2.5e-6, "extensions": 1.5e-6, "policies": 0.7e-6, "sct": 0.9e-6, "issuers": 0.9e-6}
_TASK_SECONDS = 0.5
# Expressions read as one value tuple (one dictionary lookup per row); a statistic never spans two groups
_GROUP_SIZE = 8
# Rows per step of the vectorized lookups and deduplications, identity digests per sort (bound the temporary arrays)
_CHUNK = 1 << 21
_DIGEST_CHUNK = 1 << 20
# Largest identities x values bitmap of a deduplication (bytes)
_BITMAP_CELLS = 1 << 26

# Certificates scan: type and content of the identity ('excluded' without subject; numbers by value)
_IDENTITY_COLUMNS = (f"CASE WHEN s.subject_id IS NULL THEN 'excluded' ELSE typeof({IDENTITY}) END, "
                     f"CASE WHEN typeof({IDENTITY}) IN ('integer', 'real') THEN {IDENTITY} "
                     f"ELSE CAST({IDENTITY} AS BLOB) END")
_IDENTITY_COUNT = 2
_DIGEST_SIZE = 16
# Per kind: SELECT with the key columns first ({columns} = value expressions), table, number of key columns
# (the first one is the table's own rowid for the kinds in _OWN_ID)
_OWN_ID = ("certificates", "extensions", "issuers")
_SCANS = {
    "certificates": (
        f"SELECT c.certificate_id, 0, CASE WHEN typeof(c.issuer_id) = 'integer' THEN c.issuer_id ELSE {NO_KEY} END, "
        f"{_IDENTITY_COLUMNS}{{columns}} "
        "FROM Certificates AS c LEFT JOIN Subjects AS s ON c.subject_id = s.subject_id "
        "WHERE c.certificate_id BETWEEN ? AND ?", "Certificates", 3),
    "extensions": (
        f"SELECT e.extension_id, CASE WHEN typeof(e.certificate_id) = 'integer' THEN e.certificate_id ELSE {NO_KEY} END"
        "{columns} FROM Extensions AS e WHERE e.extension_id BETWEEN ? AND ?", "Extensions", 2),
    "policies": (
        f"SELECT CASE WHEN typeof(p.extension_id) = 'integer' THEN p.extension_id ELSE {NO_KEY} END{{columns}} "
        "FROM CertificatePolicies AS p WHERE p.policy_id BETWEEN ? AND ?", "CertificatePolicies", 1),
    "sct": (
        f"SELECT CASE WHEN typeof(t.certificate_id) = 'integer' THEN t.certificate_id ELSE {NO_KEY} END, "
        f"COALESCE(l.id, {NO_KEY}){{columns}} FROM SignedCertificateTimestamps AS t LEFT JOIN Logs AS l "
        "ON t.log_id = l.id WHERE t.id BETWEEN ? AND ?", "SignedCertificateTimestamps", 2),
    "issuers": ("SELECT Issuers.issuer_id{columns} FROM Issuers WHERE Issuers.issuer_id BETWEEN ? AND ?", "Issuers", 1),
}
# Keys read in rowid ranges or joined as unique: they must be the rowid (INTEGER PRIMARY KEY). Databases of older
# versions can have Certificates without it; their statistics are left to the queries.
_ROWID_KEYS = (("Certificates", "certificate_id"), ("Subjects", "subject_id"), ("Extensions", "extension_id"),
               ("CertificatePolicies", "policy_id"), ("SignedCertificateTimestamps", "id"), ("Issuers", "issuer_id"),
               ("Logs", "id"), ("LogsOperators", "id"))


class Unique(NamedTuple):
    """Distinct certificates per value of `columns` among the rows of a scan matching `where`."""
    scan: str                       # 'certificates', 'extensions', 'policies' or 'sct' (columns over Logs AS l)
    columns: tuple[str, ...]        # value expressions; none: a single count
    where: str = ""


@dataclass
class Request:
    """What to materialize: Unique statistics by name and the row counts of the other statistics."""
    unique: dict[str, Unique] = field(default_factory=dict)
    ocsp: str = ""                  # expression counted over all certificate rows
    issuers: tuple[str, str] = ("", "")     # organization (certificate rows joined to issuers), country (all issuers)
    sct_month: str = ""             # expression counted over all SCT rows
    sct_operator: str = ""          # expression over LogsOperators AS lo, for SCT rows with a log and an operator
    sct_per_certificate: bool = False
    errors_sql: str = ""            # Errors part, run as it is


@dataclass
class Facts:
    """Rows (values..., count) per statistic name ('certificates': the number of certificate rows); a statistic that
    could not be materialized is missing."""
    rows: dict[str, list[tuple]] = field(default_factory=dict)


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


def scan(path: str, kind: str, groups: list[list[str]], low: int, high: int) -> dict:
    """Read the rows low..high of one table: packed key columns and the codes of the value tuples of each group."""
    sql, _, keys = _SCANS[kind]
    columns = "".join(f", {expression}" for group in groups for expression in group)
    arrays = [array("q") for _ in range(keys)]
    tables: list[dict[tuple, int]] = [{} for _ in groups]
    codes = [array("i") for _ in groups]
    bounds, start = [], keys + (_IDENTITY_COUNT if kind == "certificates" else 0)
    for group in groups:
        bounds.append((start, start + len(group)))
        start += len(group)
    identities: dict[bytes, int] = {}
    connection = _connect(path)
    try:
        cursor = connection.execute(sql.format(columns=columns), (low, high))
        _read(_identities(cursor, identities) if kind == "certificates" else cursor, arrays, tables, codes, bounds)
    finally:
        connection.close()
    return {"rows": len(arrays[0]), "keys": [_pack(a, dense=kind in _OWN_ID and i == 0) for i, a in enumerate(arrays)],
            "codes": [_pack(c) for c in codes], "values": [list(t) for t in tables], "identities": b"".join(identities)}


def _read(cursor, arrays: list[array], tables: list[dict], codes: list[array], bounds: list[tuple[int, int]]) -> None:
    keys = [(i, a.append) for i, a in enumerate(arrays)]
    groups = [(table, code.append, low, high) for table, code, (low, high) in zip(tables, codes, bounds)]
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


def _identities(cursor: sqlite3.Cursor, identities: dict[bytes, int]):
    """Rows of the certificates scan with the identity as a local number (0, 1, ... in order of appearance; -1 NULL,
    -2 excluded); `identities` gets the digest of each number."""
    for row in cursor:
        kind = row[3]
        if kind == "excluded":
            number = EXCLUDED
        elif kind == "null":
            number = NULL_IDENTITY
        else:
            key = _identity_key(kind, row[4])
            number = identities.get(key)
            if number is None:
                number = identities[key] = len(identities)
        yield (row[0], number, *row[2:])


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
    """Expression groups read by one scan and, per statistic, its group, value positions and flag position."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.groups: list[list[str]] = []
        self.positions: dict[str, tuple[int, list[int], int | None]] = {}

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


def _readable(connection: sqlite3.Connection, kind: str, expressions: list[str]) -> bool:
    """Whether the scan can read the expressions (a column can be missing in a database type)."""
    sql = _SCANS[kind][0].format(columns="".join(f", {e}" for e in expressions))
    try:
        connection.execute(f"SELECT * FROM ({sql}) LIMIT 0", (0, -1)).fetchall()
        return True
    except sqlite3.Error:
        return False


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
    unique: dict[str, Unique] = field(default_factory=dict)
    logs: dict[str, dict] = field(default_factory=dict)         # SCT statistics: log id -> value tuple
    operators: dict | None = None                               # log id -> operator value


def _plan_unique(connection: sqlite3.Connection, request: Request, plan: _Plan) -> None:
    sct = _readable(connection, "sct", [])
    for name, unique in request.unique.items():
        if unique.scan == "sct":
            values = _log_values(connection, unique) if sct else None
            if values is not None:
                plan.logs[name] = values
                plan.unique[name] = unique
        elif _readable(connection, unique.scan, [*unique.columns, *([_flag(unique.where)] if unique.where else [])]):
            plan.scans[unique.scan].add(name, unique.columns, unique.where)
            plan.unique[name] = unique
    if request.sct_operator and sct:
        try:
            plan.operators = dict(connection.execute(
                f"SELECT l.id, {request.sct_operator} FROM Logs AS l JOIN LogsOperators AS lo "
                "ON l.operator_id = lo.id").fetchall())
        except sqlite3.Error:
            pass
    if request.sct_per_certificate and sct:
        plan.unique["sct_per_certificate"] = Unique("sct", ())


def _plan(connection: sqlite3.Connection, request: Request) -> _Plan:
    """Scans to run; statistics whose expressions cannot be read are left out (the caller runs their SQL)."""
    plan = _Plan({kind: _Scan(kind) for kind in _SCANS})
    _plan_unique(connection, request, plan)
    added = (("ocsp", "certificates", (request.ocsp,)), ("issuers", "issuers", request.issuers),
             ("sct_month", "sct", (request.sct_month,)))
    for name, kind, columns in added:
        if columns[0] and _readable(connection, kind, list(columns)):
            plan.scans[kind].add(name, columns, "")
    needed = {kind for kind, s in plan.scans.items() if s.positions} | {u.scan for u in plan.unique.values()}
    needed |= {"sct"} if plan.operators is not None else set()
    needed |= {"certificates"} if needed else set()
    needed |= {"extensions"} if "policies" in needed else set()
    plan.scans = {kind: plan.scans[kind] for kind in _SCANS if kind in needed}
    return plan


def _check_keys(connection: sqlite3.Connection) -> None:
    """Raise if a table that exists has another key than its rowid (see _ROWID_KEYS), or a key equal to NO_KEY."""
    for table, column in _ROWID_KEYS:
        columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if not columns:
            continue
        keys = [row for row in columns if row[5]]
        # An INTEGER PRIMARY KEY DESC is not an alias of the rowid: SQLite gives it an index of origin 'pk'
        if (not (len(keys) == 1 and keys[0][1] == column and str(keys[0][2]).upper() == "INTEGER")
                or any(row[3] == "pk" for row in connection.execute(f"PRAGMA index_list({table})"))):
            raise ValueError(f"{table}.{column} is not the rowid of the table")
        # NO_KEY is the smallest integer, so only the smallest key can be equal to it
        if connection.execute(f"SELECT MIN(rowid) FROM {table}").fetchone()[0] == NO_KEY:
            raise ValueError(f"{table}.{column} has a row whose key is {NO_KEY}")


def _ranges(connection: sqlite3.Connection, kind: str, workers: int) -> list[tuple[int, int]]:
    table = _SCANS[kind][1]
    # Two subqueries: SQLite reads MIN or MAX of the rowid from the b-tree ends only when it is alone
    low, high = connection.execute(f"SELECT (SELECT MIN(rowid) FROM {table}), (SELECT MAX(rowid) FROM {table})").fetchone()
    if low is None:
        return []
    rows = high - low + 1
    tasks = max(1, min(4 * workers, round(rows * _ROW_COST[kind] / _TASK_SECONDS)))
    step = -(-rows // tasks)
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
        _check_keys(connection)
        plan = _plan(connection, request)
        ranges = {kind: _ranges(connection, kind, workers) for kind in plan.scans}
    finally:
        connection.close()

    def submit(function, *args):
        return _Done(function, *args) if executor is None else executor.submit(function, *args)

    tasks = sorted(((kind, task) for kind, items in ranges.items() for task in items),
                   key=lambda item: -(item[1][1] - item[1][0]) * _ROW_COST[item[0]])
    errors = submit(query, path, request.errors_sql) if request.errors_sql else None
    futures = {(kind, task): submit(scan, path, kind, plan.scans[kind].groups, *task) for kind, task in tasks}

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
    facts.rows["certificates"] = [(certificates.rows.count,)]
    certificates.add_facts(facts, plan)
    if "issuers" in plan.scans:
        _issuer_facts(facts, rows("issuers"), certificates)
    if "extensions" in plan.scans:
        extensions = _Joined(rows("extensions"), certificates)
        extensions.add_facts(facts, plan)
        if "policies" in plan.scans:
            _Joined(rows("policies"), certificates, extensions).add_facts(facts, plan)
    if "sct" in plan.scans:
        _sct_facts(facts, rows("sct"), certificates, plan)


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
    """Rows of one scan in rowid order: key columns and value codes renumbered over all its tasks."""

    def __init__(self, results: list[dict], scan_: _Scan) -> None:
        self.scan = scan_
        self.count = sum(result["rows"] for result in results)
        own = scan_.kind in _OWN_ID
        self.index = _Index.of([(result["keys"][0], result["rows"]) for result in results]) if own else None
        self.keys = [None if own and i == 0 else
                     _narrow(np.concatenate([_unpack(r["keys"][i], r["rows"]) for r in results]))
                     if results else np.zeros(0, np.int64) for i in range(_SCANS[scan_.kind][2])]
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

    def counts(self, name: str) -> list[tuple]:
        """Rows per value tuple (no deduplication)."""
        codes, _, values = self.statistic(name)
        counts = np.bincount(codes, minlength=len(values))
        return [(*value, int(counts[code])) for code, value in enumerate(values) if counts[code]]


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


def _unique_rows(identities: np.ndarray, repeated: _Repeated, codes: np.ndarray, valid: np.ndarray,
                 values: list[tuple], always: bool = False) -> list[tuple]:
    """(values..., distinct non-NULL identities) per value tuple; tuples seen only with a NULL identity count 0."""
    size = len(values)
    present = np.zeros(size, dtype=bool)
    present[codes[valid & (identities == NULL_IDENTITY)]] = True
    counted = valid & (identities >= 0)
    counts = np.bincount(codes[counted & ~repeated.mask], minlength=size).astype(np.int64)
    several = counted & repeated.mask
    if several.any():
        counts += _distinct_pairs(identities[several], codes[several], size, repeated.count)
    rows = [(*value, int(counts[code])) for code, value in enumerate(values) if counts[code] or present[code]]
    return rows if rows or not always else [(0,)]


class _Certificates:
    """Certificate rows in certificate_id order with their identity numbered 0..n-1 (or NULL_IDENTITY, EXCLUDED)."""

    def __init__(self, rows: _Rows) -> None:
        self.rows = rows
        identities = rows.keys[1].astype(np.int64)
        self.count = _number_identities(identities, rows.identities)
        rows.identities = []
        self.identities = _narrow(identities)
        self.repeated = _Repeated(self.identities, self.count)

    def add_facts(self, facts: Facts, plan: _Plan) -> None:
        for name in self.rows.scan.positions:
            if name == "ocsp":
                facts.rows["ocsp"] = self.rows.counts(name)
            else:
                codes, valid, values = self.rows.statistic(name)
                facts.rows[name] = _unique_rows(self.identities, self.repeated, codes, valid, values,
                                                always=not plan.unique[name].columns)

    def identities_of(self, certificate_ids: np.ndarray) -> np.ndarray:
        """Identity of the certificate of each key; EXCLUDED when there is no such certificate."""
        if not len(self.identities):
            return np.full(len(certificate_ids), EXCLUDED, dtype=self.identities.dtype)
        position = self.rows.index.positions(certificate_ids)
        return np.where(position >= 0, self.identities[position], EXCLUDED).astype(self.identities.dtype)


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


class _Joined:
    """Rows of a table joined to the certificates: extensions by certificate_id, policies through extensions."""

    def __init__(self, rows: _Rows, certificates: _Certificates, extensions: _Joined | None = None) -> None:
        self.rows = rows
        if extensions is None:
            self.identities = certificates.identities_of(rows.keys[1])
        elif not len(extensions.identities):
            self.identities = np.full(rows.count, EXCLUDED, dtype=extensions.identities.dtype)
        else:
            position = extensions.rows.index.positions(rows.keys[0])
            self.identities = np.where(position >= 0, extensions.identities[position], EXCLUDED).astype(
                extensions.identities.dtype)
        self.repeated = _Repeated(self.identities, certificates.count)

    def add_facts(self, facts: Facts, plan: _Plan) -> None:
        for name in self.rows.scan.positions:
            codes, valid, values = self.rows.statistic(name)
            facts.rows[name] = _unique_rows(self.identities, self.repeated, codes, valid, values,
                                            always=not plan.unique[name].columns)


def _issuer_facts(facts: Facts, issuers: _Rows, certificates: _Certificates) -> None:
    """Organizations over the certificate rows joined to their issuer, countries over all issuer rows."""
    codes, _, values = issuers.statistic("issuers")
    position = issuers.index.positions(certificates.rows.keys[2])
    joined = np.bincount(codes[position[position >= 0]], minlength=len(values))
    every = np.bincount(codes, minlength=len(values))
    organizations: dict = {}
    countries: dict = {}
    for code, (organization, country) in enumerate(values):
        if joined[code]:
            organizations[organization] = organizations.get(organization, 0) + int(joined[code])
        countries[country] = countries.get(country, 0) + int(every[code])
    facts.rows["organizations"] = list(organizations.items())
    facts.rows["countries"] = list(countries.items())


def _sct_facts(facts: Facts, sct: _Rows, certificates: _Certificates, plan: _Plan) -> None:
    """Unique statistics over the logs, per-month and per-operator SCT counts, SCTs per certificate."""
    certificate_ids, log_ids = sct.keys
    if "sct_month" in sct.scan.positions:
        facts.rows["sct_month"] = sct.counts("sct_month")
    logs, log_codes = _log_codes(log_ids)
    if plan.operators is not None:
        per_log = np.bincount(log_codes, minlength=len(logs) + 1)
        operators: dict = {}
        for code, log in enumerate(logs.tolist()):
            if log in plan.operators and per_log[code]:
                operators[plan.operators[log]] = operators.get(plan.operators[log], 0) + int(per_log[code])
        facts.rows["sct_operators"] = list(operators.items())
    if "sct_per_certificate" in plan.unique:
        position = certificates.rows.index.positions(certificate_ids)
        per_certificate = np.bincount(position[position >= 0], minlength=certificates.rows.count)
        facts.rows["sct_per_certificate"] = [(count, int(n)) for count, n in enumerate(np.bincount(per_certificate))
                                             if n]
    if plan.logs:
        _log_facts(facts, plan, certificates.identities_of(certificate_ids), certificates.count, logs, log_codes)


def _log_codes(log_ids: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Sorted distinct log ids and, per SCT row, the index of its log (len(logs) without a log)."""
    known = log_ids != NO_KEY
    if not known.any():
        return np.zeros(0, np.int64), np.zeros(len(log_ids), np.int32)
    low, high = int(log_ids[known].min()), int(log_ids[known].max())
    if high - low > 4 * len(log_ids) + 1024:        # sparse ids: by sorting
        logs = np.unique(log_ids[known])
        codes = np.searchsorted(logs, log_ids).astype(np.int32)
        codes[~known] = len(logs)
        return logs, codes
    offsets = np.where(known, log_ids - low, high - low + 1)
    present = np.bincount(offsets, minlength=high - low + 2)[:-1] > 0
    logs = np.flatnonzero(present) + low
    lookup = np.full(high - low + 2, len(logs), dtype=np.int32)
    lookup[logs - low] = np.arange(len(logs), dtype=np.int32)
    return logs, lookup[offsets]


def _log_facts(facts: Facts, plan: _Plan, identities: np.ndarray, count: int, logs: np.ndarray,
               log_codes: np.ndarray) -> None:
    """Unique statistics whose values come from the log of each SCT."""
    repeated = _Repeated(identities, count)
    for name, values_by_log in plan.logs.items():
        index: dict[tuple, int] = {}
        lookup = np.full(len(logs) + 1, -1, dtype=np.int32)
        for code, log in enumerate(logs.tolist()):
            value = values_by_log.get(log)
            if value is not None:
                lookup[code] = index.setdefault(value, len(index))
        codes = lookup[log_codes]
        facts.rows[name] = _unique_rows(identities, repeated, np.maximum(codes, 0), codes >= 0, list(index),
                                        always=not plan.unique[name].columns)
