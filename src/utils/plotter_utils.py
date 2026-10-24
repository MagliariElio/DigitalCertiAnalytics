from __future__ import annotations

import csv
import logging
import multiprocessing
import os
import shutil
import sqlite3
import time
from concurrent.futures import CancelledError, Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from logging.handlers import QueueHandler
from pathlib import Path
from typing import Callable, NamedTuple

from dao.statistics_dao import StatisticsDAO
from db.database import DatabaseType
from utils.process_utils import init_worker_process, sigint_blocked

# Admin: Anuar Elio Magliari
# Politecnico di Torino

_ALL_TYPES = frozenset(DatabaseType)
_LEAF = frozenset({DatabaseType.LEAF})
_LEAF_AND_ROOT = frozenset({DatabaseType.LEAF, DatabaseType.ROOT})

# Adjective of each certificate type, used in captions and titles
TYPE_LABELS = {DatabaseType.LEAF: "leaf", DatabaseType.INTERMEDIATE: "intermediate", DatabaseType.ROOT: "root"}
CAPTIONS_FILE = "captions.tex"

_UNIQUE = "Unique certificates"
_FLAG = "Criticality"
_OCCURRENCES = "Occurrences"


@dataclass(frozen=True)
class Chart:
    """Declarative chart spec: data source, drawing, output files and texts."""
    query: str                  # StatisticsDAO get_* method returning the data
    kind: str                   # graph_plotter drawing: 'bars', 'line', 'upset', 'concentration', 'families' or
    #                             'validity_limit'
    name: str                   # base name of the .png/.pdf/.csv/.tex files
    title: str                  # chart name in the log messages
    caption: str                # figure caption, str.format template: type, n, note, threshold, the nouns of
    #                             graph_plotter.render_chart and the drawing fields
    category: str               # heading of the category column (tables)
    axis: str = _UNIQUE         # value axis label
    unit: str = "Certificates"  # heading of the value column (tables)
    labels: str = "plain"       # category label scheme (graph_plotter)
    ordered: bool = False       # ordinal categories keep the query order instead of being sorted by value
    # StatisticsDAO.thresholds field quoted in the caption as {threshold}, with its noun (singular, plural)
    threshold: tuple[str, ...] = ()
    types: frozenset[DatabaseType] = _ALL_TYPES     # certificate types the chart is generated for
    table: str = ""             # table caption template, when the figure caption describes the drawing


# Rows are certificate occurrences: one per scanned domain whose server presented the certificate
_REPEATED = "a certificate presented by several domains is counted once for each of them"
_EXTENSION_CAPTION = "Criticality of the {} extension in {{type}} certificates (unique certificates, N = {{n}}).{{note}}"
_UPSET_CAPTION = ("Combinations of the {} extension flags in {{type}} certificates (UpSet diagram): the bars give the "
                  "certificates of each combination, the matrix the flags it contains (unique certificates, "
                  "N = {{n}}).{{note}}")
_UPSET_TABLE = "Combinations of the {} extension flags in {{type}} certificates (unique certificates, N = {{n}}).{{note}}"
_HHI = "The Herfindahl-Hirschman index{computed} is {hhi} ({level} concentration; N = {n} {occurrences}: "

# In generation order: charts for every type, then leaf only, then leaf and root
CHARTS = (
    Chart("get_issuer_certificate_count", "bars", "issuer_certificates_count", "Certificates by Issuer",
          "Occurrences of {type} certificates by issuer organization (at most {threshold}, the others aggregated; "
          f"N = {{n}} {{occurrences}}: {_REPEATED}).", "Issuer", _OCCURRENCES, _OCCURRENCES, labels="issuers",
          threshold=("top_issuers", "issuer", "issuers")),
    Chart("get_issuer_distribution", "concentration", "issuer_concentration", "Issuer Concentration",
          "Concentration curve of the issuers of {type} certificates: cumulative share of the occurrences {curve}. "
          f"{_HHI}{_REPEATED}).", "Issuer", _OCCURRENCES, _OCCURRENCES,
          table=f"Occurrences of {{type}} certificates by issuer organization{{rows}}. {_HHI}{_REPEATED})."),
    Chart("get_certificate_version_distribution", "bars", "certificate_version_distribution",
          "Certificate Versions",
          "X.509 version of {type} certificates (unique certificates, N = {n}).", "Version", labels="version",
          ordered=True),
    Chart("get_count_critical_non_critical_extensions", "bars", "count_critical_non_critical_extensions",
          "Criticality of the Authority Information Access Extension",
          _EXTENSION_CAPTION.format("Authority Information Access"), _FLAG, labels="flags"),
    Chart("get_certificates_per_country", "bars", "certificates_per_country",
          "Certificates by Issuer Country",
          "Occurrences of {type} certificates by issuer country, as ISO 3166 code (at most {threshold}, the others "
          f"aggregated; N = {{n}} {{occurrences}}: {_REPEATED}).", "Country", _OCCURRENCES, _OCCURRENCES,
          labels="countries", threshold=("top_countries", "country", "countries")),
    Chart("get_certificate_expiration_trend", "line", "certificate_expiration_trend",
          "Certificate Expiration Trend",
          "Expiring {type} certificates {period} (unique certificates; only the months with more than {threshold} are "
          "shown).{note}", "Month", "Expiring certificates",
          threshold=("expiration_above", "expiration", "expirations")),
    Chart("get_validity_duration_distribution", "bars", "validity_duration_distribution",
          "Validity Duration in Years",
          "Validity duration in whole years of {type} certificates (unique certificates, N = {n}; durations with at "
          "least {threshold}).{note}", "Duration", labels="years", ordered=True,
          threshold=("min_validity_count", "certificate", "certificates")),
    Chart("get_validity_days_distribution", "bars", "validity_days_distribution", "Validity Duration in Days",
          "Validity duration in days of {type} certificates, in classes aligned with the 398-day and 825-day limits of "
          "the CA/Browser Forum (unique certificates, N = {n}).{note}", "Validity duration", labels="days",
          ordered=True),
    Chart("get_signature_algorithm_distribution", "bars", "signature_algorithm_distribution",
          "Signature Algorithms", "Signature algorithms of {type} certificates (unique certificates, N = {n}).{note}",
          "Signature algorithm", labels="signatures"),
    Chart("get_signature_algorithm_distribution", "families", "signature_family_share",
          "Signature Algorithm Families",
          "Signature algorithm families of {type} certificates: {share} are signed with {family} (unique certificates, "
          "N = {n}).{note}", "Family"),
    Chart("get_key_algorithm_length_distribution", "bars", "key_algorithm_length_distribution",
          "Public Key Algorithm and Length",
          "Algorithm and length in bits of the public key of {type} certificates (unique certificates, N = {n}).",
          "Public key", labels="key_lengths"),
    Chart("get_key_usage_distribution", "upset", "key_usage_distribution", "Key Usage Combinations",
          _UPSET_CAPTION.format("Key Usage"), "Key Usage combination", table=_UPSET_TABLE.format("Key Usage")),
    Chart("get_critical_vs_non_critical_key_usage", "bars", "critical_vs_non_critical_key_usage",
          "Criticality of the Key Usage Extension", _EXTENSION_CAPTION.format("Key Usage"), _FLAG,
          labels="flags"),
    Chart("get_extended_key_usage_distribution", "upset", "extended_key_usage_distribution",
          "Extended Key Usage Combinations", _UPSET_CAPTION.format("Extended Key Usage"),
          "Extended Key Usage combination", table=_UPSET_TABLE.format("Extended Key Usage")),
    Chart("get_critical_vs_non_critical_extended_key_usage", "bars", "critical_vs_non_critical_extended_key_usage",
          "Criticality of the Extended Key Usage Extension", _EXTENSION_CAPTION.format("Extended Key Usage"),
          _FLAG, labels="flags"),
    Chart("get_critical_vs_non_critical_san_extensions", "bars", "critical_vs_non_critical_san_extensions",
          "Criticality of the Subject Alternative Name Extension",
          _EXTENSION_CAPTION.format("Subject Alternative Name"), _FLAG, labels="flags"),
    Chart("get_critical_vs_non_critical_cp_policies", "bars", "critical_vs_non_critical_cp_policies",
          "Criticality of the Certificate Policies Extension",
          _EXTENSION_CAPTION.format("Certificate Policies"), _FLAG, labels="flags"),
    Chart("get_validation_level_distribution", "bars", "validation_level_distribution",
          "Validation Levels",
          "Validation level (DV, OV, EV) of {type} certificates (unique certificates, N = {n}).", "Validation level"),
    Chart("get_basic_constraints_distribution", "bars", "basic_constraints_distribution",
          "Basic Constraints",
          "Values of the Basic Constraints extension of {type} certificates (unique certificates, N = {n}).",
          "Basic Constraints", labels="basic_constraints"),
    Chart("get_critical_vs_non_critical_crl_distribution", "bars", "critical_vs_non_critical_crl_distribution",
          "Criticality of the CRL Distribution Points Extension",
          _EXTENSION_CAPTION.format("CRL Distribution Points"), _FLAG, labels="flags"),
    Chart("get_ocsp_status_distribution", "bars", "ocsp_status_distribution", "OCSP Status",
          f"Outcome of the OCSP check of {{type}} certificates (N = {{n}} {{occurrences}}: {_REPEATED}).{{note}}",
          "OCSP status", _OCCURRENCES, _OCCURRENCES, labels="ocsp"),
    # Leaf only
    Chart("get_validity_days_distribution", "validity_limit", "validity_beyond_398_days",
          "Certificates Beyond 398 Days",
          "Validity duration of {type} certificates against the 398-day limit of the CA/Browser Forum Baseline "
          "Requirements: {beyond} (unique certificates, N = {n}).{note}", "Duration class", types=_LEAF),
    Chart("get_status_analysis", "bars", "status_analysis", "TLS Scan Outcome",
          "Outcome of the TLS scan of the domains: successful handshakes and error types (N = {n} {domains}).",
          "Outcome", "Scanned domains", "Domains", labels="status", types=_LEAF),
    Chart("get_self_signed_vs_ca_signed", "bars", "self_signed_vs_ca_signed", "Self-Signed vs CA-Signed Certificates",
          "Self-signed and CA-signed {type} certificates (unique certificates, N = {n}).", "Signature",
          labels="self_signed", types=_LEAF),
    Chart("get_top_sct_logs", "bars", "top_sct_logs", "Top SCT Logs",
          "Certificate Transparency logs most used by {type} certificates (logs with more than {threshold}).", "Log",
          threshold=("top_sct_logs_above", "unique certificate", "unique certificates"), types=_LEAF),
    Chart("get_top_sct_log_operators", "bars", "top_sct_log_operators", "Top SCT Log Operators",
          "Signed Certificate Timestamps (SCTs) of {type} certificates by log operator (N = {n} {scts}).",
          "Operator", "SCTs", "SCTs", labels="operators", types=_LEAF),
    Chart("get_signed_certificate_timestamp_trend", "line", "sct_trend",
          "SCT Trend by Month",
          "Signed Certificate Timestamps (SCTs) of {type} certificates {period} (only the months with more than "
          "{threshold} are shown).{note}", "Month", "SCTs", "SCTs", threshold=("sct_above", "SCT", "SCTs"), types=_LEAF),
    Chart("get_sct_count_per_certificate", "bars", "sct_count_per_certificate",
          "SCTs per Certificate",
          f"Number of Signed Certificate Timestamps (SCTs) per {{type}} certificate (N = {{n}} {{occurrences}}: "
          f"{_REPEATED}).", "SCTs per certificate", _OCCURRENCES, _OCCURRENCES, ordered=True, types=_LEAF),
    # Leaf and root
    Chart("get_signature_validity_distribution", "bars", "signature_validity_distribution",
          "Signature Validity",
          "Signature validity of {type} certificates (unique certificates, N = {n}).{note}", "Signature validity",
          labels="signature_validity", types=_LEAF_AND_ROOT),
)


# ---------------------------------------------------------------- numbers, CSV and LaTeX

def format_number(value: float, decimals: int = 0) -> str:
    """4245727 -> '4,245,727'; 45.04 with one decimal -> '45.0'."""
    return f"{value:,.{decimals}f}"


def format_share(value: float, total: float) -> str:
    """Percentage: '45.0%', '0.02%', '< 0.01%'."""
    share = 100 * value / total if total else 0
    if share == 0:
        return "0%"
    if share < 0.01:
        return "< 0.01%"
    return f"{format_number(share, 1 if share >= 0.1 else 2)}%"


_LATEX_ESCAPES = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{",
                  "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}", "<": r"\textless{}",
                  ">": r"\textgreater{}", "≤": r"$\leq$", "–": "--", "…": r"\ldots{}"}


def latex_escape(text: str) -> str:
    return "".join(_LATEX_ESCAPES.get(character, character) for character in str(text))


def latex_label(kind: str, certificate_type: DatabaseType, name: str) -> str:
    """'fig'/'tab' label qualified by the certificate type: leaf, intermediate and root share the chart names."""
    return f"{kind}:{certificate_type.value}-{name}"


def write_csv(path: str, rows: list[tuple[str, int]]) -> None:
    """Plotted data as category, count, share (percentage of the plotted total); the count is in the chart's unit."""
    total = sum(value for _, value in rows)
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("category", "count", "share"))
        for label, value in rows:
            writer.writerow((label, value, f"{100 * value / total:.4f}" if total else "0"))


def _table_share(value: int, total: int) -> str:
    share = 100 * value / total if total else 0
    return "< 0.01" if 0 < share < 0.005 else f"{share:.2f}"


def latex_table(rows: list[tuple[str, int]], chart: Chart, caption: str, label: str,
                column: tuple[str, list[str]] | None = None) -> str:
    """booktabs + siunitx table of the plotted data, with comma thousands separators and a total row.

    `column` adds a text column (heading, one value per row), e.g. the status of the signature algorithms.
    """
    total = sum(value for _, value in rows)
    shares = [_table_share(value, total) for _, value in rows]
    share_format = "<3.2" if any(share.startswith("<") for share in shares) else "3.2"
    first = "l" if max(len(str(category)) for category, _ in rows) <= 45 else r"p{0.5\textwidth}"
    heading, values = "", [""] * len(rows)
    if column:
        heading, values = f" & {latex_escape(column[0])}", [f" & {latex_escape(value)}" for value in column[1]]
    lines = [
        r"% Requires \usepackage{booktabs} and \usepackage{siunitx}",
        r"\begin{table}[htbp]",
        r"  \centering",
        r"  \sisetup{output-decimal-marker={.}, group-separator={,}, group-minimum-digits=4}",
        f"  \\caption{{{latex_escape(caption)}}}",
        f"  \\label{{{label}}}",
        f"  \\begin{{tabular}}{{{first} S[table-format={len(str(total))}.0] S[table-format={share_format}]"
        f"{' l' if column else ''}}}",
        r"    \toprule",
        f"    {latex_escape(chart.category)} & {{{latex_escape(chart.unit)}}} & {{Share (\\%)}}{heading} \\\\",
        r"    \midrule",
        *(f"    {latex_escape(category)} & {value} & {share}{extra} \\\\"
          for (category, value), share, extra in zip(rows, shares, values)),
        r"    \midrule",
        f"    Total & {total} & 100.00{' &' if column else ''} \\\\",
        r"    \bottomrule",
        r"  \end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines) + "\n"


def plots_macro(certificate_type: DatabaseType) -> str:
    """LaTeX macro holding the folder of the figures of a certificate type (\\plotsfolderleaf, ...)."""
    return f"\\plotsfolder{certificate_type.value}"


def latex_figure(name: str, caption: str, label: str, folder: str = "") -> str:
    path = f"{folder}/{name}.pdf" if folder else f"{name}.pdf"
    return "\n".join((r"\begin{figure}[htbp]", r"  \centering", f"  \\includegraphics[width=\\textwidth]{{{path}}}",
                      f"  \\caption{{{latex_escape(caption)}}}", f"  \\label{{{label}}}", r"\end{figure}")) + "\n"


def _write_captions(plots_path: str | os.PathLike, certificate_type: DatabaseType,
                    outcomes: list[tuple[Chart, _Result]]) -> None:
    """captions.tex: a ready figure environment with the caption of every generated chart.

    The figures are referenced through a per-type folder macro: leaf, intermediate and root share the file names, so
    bare names would make LaTeX take the first match along \\graphicspath.
    """
    macro, folder = plots_macro(certificate_type), Path(os.path.abspath(plots_path))
    lines = [f"% Figures of the {TYPE_LABELS[certificate_type]} certificates generated by DigitalCertiAnalytics.",
             r"% Requires \usepackage{graphicx}. The figures are looked up in the folder " + macro + ",",
             f"% by default '{folder.parent.name}/{folder.name}' relative to \\graphicspath; for another folder, "
             f"define {macro} before \\input.",
             f"\\providecommand{{{macro}}}{{{folder.parent.name}/{folder.name}}}", ""]
    lines += [latex_figure(chart.name, outcome.caption, latex_label("fig", certificate_type, chart.name), macro)
              for chart, outcome in outcomes]
    with open(os.path.join(plots_path, CAPTIONS_FILE), "w", encoding="utf-8") as file:
        file.write("\n".join(lines))


# ---------------------------------------------------------------- rendering

# Per-query path (statistics not materialized): queries running at the same time. Each keeps up to its page cache and
# one sort buffer (64 MiB each) in memory, plus, on databases small enough for in-memory temporary tables
# (statistics_dao.temp_store), its DISTINCT / GROUP BY b-trees (measured: up to 11% of the database file).
STATISTICS_WORKERS = 4
# Per-query path: queries submitted first. They read every SCT (several per certificate) and take 3-4 times longer
# than the others, so starting them last would leave them running alone at the end
_SLOW_QUERIES = ("get_top_sct_logs",)

# Persistent process pool (workers, executor), shared by the plot_certificates calls of this process
_pool: tuple[int, ProcessPoolExecutor] | None = None
# Render process state: semaphore bounding the concurrent queries, log records of the current job
_query_slots = None


class _Result(NamedTuple):
    """One chart: PNG path and caption, or the error that stopped it (neither: nothing to plot)."""
    image: str | None = None
    caption: str = ""
    error: str = ""


class _Records(list):
    """Log records of the current job, returned to the main process with its result (QueueHandler target)."""

    def put_nowait(self, record: logging.LogRecord) -> None:
        self.append(record)


_records = _Records()

# Charts of one query, each with its caption fields
_Job = list[tuple[Chart, dict]]


def _silence_libraries() -> None:
    # fontTools subsets the fonts embedded in every PDF and logs each step at DEBUG level
    for name in ('PIL', 'matplotlib', 'fontTools'):
        logging.getLogger(name).setLevel(logging.ERROR)


def _init_worker(query_slots, parent_pid: int) -> None:
    """Render process set-up: Ctrl+C is handled by the main process, log records go back with each job result."""
    global _query_slots
    init_worker_process(parent_pid)
    _query_slots = query_slots
    # The main process formats the records: here only the message (plus any traceback)
    logging.basicConfig(format="%(message)s", handlers=[QueueHandler(_records)], force=True)
    _silence_libraries()


def _query_job(path: str, certificate_type: DatabaseType, query: str, job: _Job, directory: str,
               level: int) -> tuple[list[_Result], list[logging.LogRecord]]:
    """Render process: run the query on a read-only connection to the database file, then draw its charts."""
    _records.clear()
    logging.getLogger().setLevel(level)
    with _query_slots, StatisticsDAO.reading(path, certificate_type) as dao:
        data = getattr(dao, query)()
    return _render(job, data, certificate_type, directory), list(_records)


def _render_job(job: _Job, data: dict, certificate_type: DatabaseType, directory: str,
                level: int) -> tuple[list[_Result], list[logging.LogRecord]]:
    """Render process: draw the charts of data computed by the main process."""
    _records.clear()
    logging.getLogger().setLevel(level)
    return _render(job, data, certificate_type, directory), list(_records)


def _render(job: _Job, data: dict, certificate_type: DatabaseType, directory: str) -> list[_Result]:
    """Draw the charts of one query; an error stops only its own chart."""
    if not data:
        return [_Result()] * len(job)
    from utils.graph_plotter import render_chart     # matplotlib is loaded only where charts are drawn
    results = []
    for chart, fields in job:
        try:
            outcome = render_chart(chart, data, certificate_type, directory, fields)
            results.append(_Result(outcome.image, outcome.caption))
        except Exception as e:
            results.append(_Result(error=str(e)))
    return results


def _executor(workers: int) -> ProcessPoolExecutor | None:
    """Pool of `workers` spawned processes, reused by the next calls; None for fewer than 2 workers."""
    global _pool
    if workers < 2:
        return None
    if _pool is not None and _pool[0] == workers:
        return _pool[1]
    _discard_pool()
    try:
        context = multiprocessing.get_context("spawn")
        with sigint_blocked():
            slots = context.BoundedSemaphore(min(workers, STATISTICS_WORKERS))
            _pool = (workers, ProcessPoolExecutor(workers, mp_context=context, initializer=_init_worker,
                                                  initargs=(slots, os.getpid())))
    except (OSError, RuntimeError, ValueError) as e:
        logging.warning(f"Render processes not available ({e}): charts generated sequentially.")
        return None
    return _pool[1]


def _spawn_safe_submit(executor: ProcessPoolExecutor, function: Callable, *args) -> Future:
    """Submit a job; a submit may start a render process, which must not see a Ctrl+C before its set-up."""
    with sigint_blocked():
        return executor.submit(function, *args)


class _SpawnSafeExecutor:
    """The render pool for StatisticsDAO.materialize(): every submit as _spawn_safe_submit."""

    def __init__(self, executor: ProcessPoolExecutor) -> None:
        self._executor = executor

    def submit(self, function: Callable, *args) -> Future:
        return _spawn_safe_submit(self._executor, function, *args)


def _discard_pool(terminate: bool = False) -> None:
    """Shut the pool down; `terminate` also stops the running jobs (Ctrl+C, broken pool)."""
    global _pool
    if _pool is None:
        return
    executor, _pool = _pool[1], None
    if terminate:
        if hasattr(executor, "terminate_workers"):      # Python 3.14+
            executor.terminate_workers()
        else:
            for process in list((executor._processes or {}).values()):
                try:
                    process.terminate()
                except ValueError:      # already closed
                    pass
    executor.shutdown(wait=not terminate, cancel_futures=True)


def shutdown_render_pool() -> None:
    """Stop the render processes kept for the next plot_certificates calls.

    Safe to call at any time and more than once: without a pool (never started, already stopped, stopped by Ctrl+C)
    it does nothing.
    """
    _discard_pool()


class _Plotter:
    """Computes the statistics and draws the charts of one database.

    The statistics are first materialized: each table of the database file is read once (StatisticsDAO.materialize,
    by the render processes when there is a pool), the main process aggregates the rows, and the charts are then
    drawn in the pool. If that is not possible, each query runs in a render process on its own read-only connection
    to the database file (at most STATISTICS_WORKERS at the same time), followed by its charts. In-memory databases
    and connections with uncommitted changes are queried here and only the drawing goes to the pool. Without a pool
    everything runs here, one query at a time when its first chart is reached if the statistics are not materialized.
    """

    def __init__(self, dao: StatisticsDAO, directory: str, workers: int) -> None:
        self._dao = dao
        self._directory = directory
        self._workers = workers
        self._executor = _executor(workers)
        self._path = dao.shared_database_file()
        self._data: dict[str, dict] = {}

    def run(self, charts: list[Chart], jobs: dict[str, _Job]) -> dict[str, _Result]:
        """Outcome of every generated chart by name; the charts are logged in their order, whatever the order in
        which their jobs (submitted as `jobs` is ordered) complete."""
        try:
            self._materialize(list(jobs))
            futures = {query: self._submit(query, job) for query, job in jobs.items()}
            results: dict[str, list[_Result]] = {}
            outcomes = {}
            for chart in charts:
                logging.info(f"Generating chart '{chart.title}'")
                job = jobs[chart.query]
                if chart.query not in results:
                    results[chart.query] = self._collect(futures[chart.query], chart.query, job)
                result = results[chart.query][[item for item, _ in job].index(chart)]
                if self._log(chart, result):
                    outcomes[chart.name] = result
            return outcomes
        except BaseException:
            _discard_pool(terminate=True)       # e.g. Ctrl+C: no query keeps running in the background
            raise

    def _materialize(self, queries: list[str]) -> None:
        """Statistics of every query from one read of each table, scanned by the render processes (here without a
        pool)."""
        if not self._path:
            return
        logging.info("Computing the statistics (one read per table)...")
        start = time.monotonic()
        try:
            with StatisticsDAO.reading(self._path, self._dao.certificate_type) as reader:
                executor = None if self._executor is None else _SpawnSafeExecutor(self._executor)
                if reader.materialize(queries, executor, self._workers if executor is not None else 1):
                    self._data = {query: getattr(reader, query)() for query in queries}
                    logging.info(f"Statistics computed in {time.monotonic() - start:.1f} s.")
        except sqlite3.Error as e:      # the queries run one by one instead
            logging.warning(f"Statistics not materialized ({e}): running the individual queries.")

    def _submit(self, query: str, job: _Job) -> Future | None:
        """Job submitted to the pool; None when it runs here."""
        if self._executor is None:
            return None
        certificate_type, level = self._dao.certificate_type, logging.getLogger().getEffectiveLevel()
        try:
            if query in self._data:
                return _spawn_safe_submit(self._executor, _render_job, job, self._data[query], certificate_type,
                                          self._directory, level)
            if self._path:
                return _spawn_safe_submit(self._executor, _query_job, self._path, certificate_type, query, job,
                                          self._directory, level)
            data = getattr(self._dao, query)()
            return _spawn_safe_submit(self._executor, _render_job, job, data, certificate_type, self._directory, level)
        except (BrokenProcessPool, OSError, RuntimeError) as e:
            self._pool_failed(e)
            return None

    def _collect(self, future: Future | None, query: str, job: _Job) -> list[_Result]:
        """Results of the job's charts, after forwarding the log records of its render process."""
        if future is None:
            return self._run_here(query, job)
        try:
            results, records = future.result()
        except (BrokenProcessPool, CancelledError) as e:     # cancelled: the pool failed meanwhile
            self._pool_failed(e)
            return self._run_here(query, job)
        except Exception as e:
            return [_Result(error=str(e))] * len(job)
        for record in records:
            logging.getLogger(record.name).handle(record)
        return results

    @staticmethod
    def _log(chart: Chart, result: _Result) -> bool:
        """Log the outcome of one chart; True when it was generated."""
        if result.error:
            logging.error(f"Error generating chart '{chart.title}': {result.error}")
        elif result.image is None:
            logging.warning(f"No data available for chart '{chart.title}': chart not generated.")
        else:
            logging.info(f"Chart '{chart.title}' generated and saved to file://{result.image}.")
            return True
        return False

    def _run_here(self, query: str, job: _Job) -> list[_Result]:
        data = self._data[query] if query in self._data else getattr(self._dao, query)()
        return _render(job, data, self._dao.certificate_type, self._directory)

    def _pool_failed(self, error: BaseException) -> None:
        if self._executor is not None:
            logging.warning(f"Render processes stopped ({error}): the remaining charts are generated sequentially.")
            self._executor = None
            _discard_pool(terminate=True)


def _reset_directory(path: str | os.PathLike) -> None:
    if os.path.exists(path):
        shutil.rmtree(path)
        logging.info(f"Folder '{path}' removed.")
    os.makedirs(path)
    logging.info(f"Folder '{path}' created.")


def _caption_fields(chart: Chart, dao: StatisticsDAO) -> dict:
    """{threshold}: the chart's threshold with its noun, e.g. '20 issuers', '1 certificate'."""
    if not chart.threshold:
        return {}
    field, singular, plural = chart.threshold
    value = getattr(dao.thresholds, field)
    return {"threshold": f"{format_number(value)} {singular if value == 1 else plural}"}


def plot_certificates(dao: StatisticsDAO, plots_path: str | os.PathLike, is_verbose: bool,
                      workers: int | None = None) -> None:
    """Regenerate in plots_path every chart applicable to the DAO's certificate type.

    The statistics and the drawing run in a pool of up to `workers` processes (default: one per CPU; 0/1 = in the
    current process), kept for the next calls until shutdown_render_pool(). For every chart: <name>.png (300 dpi),
    <name>.pdf, <name>.csv and <name>.tex; plus captions.tex. `is_verbose` is kept for the CLI: the plotting libraries
    never log below ERROR.
    """
    _reset_directory(plots_path)
    _silence_libraries()
    certificate_type = dao.certificate_type
    charts = [chart for chart in CHARTS if certificate_type in chart.types]
    jobs: dict[str, _Job] = {}
    for chart in sorted(charts, key=lambda chart: chart.query not in _SLOW_QUERIES):
        jobs.setdefault(chart.query, []).append((chart, _caption_fields(chart, dao)))
    workers = (os.cpu_count() or 1) if workers is None else workers
    outcomes = _Plotter(dao, os.path.abspath(plots_path), workers).run(charts, jobs)
    _write_captions(plots_path, certificate_type, [(chart, outcomes[chart.name]) for chart in charts
                                                   if chart.name in outcomes])
    logging.info(f"Chart generation for the {certificate_type.value.capitalize()} certificate analysis completed.")
