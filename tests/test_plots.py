"""Tests for the charts: number formatting, tables, drawings and their generation in parallel processes."""
import json
import logging
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image
from test_statistics import create_database

from dao import statistics_facts
from dao.statistics_dao import StatisticsDAO
from db.database import DatabaseType
from utils import graph_plotter, plotter_utils
from utils.graph_plotter import (NEGATIVE, _combinations, _consecutive_months, _draw_line, _draw_validity_limit, _items,
                                 _use_log, render_chart)
from utils.plotter_utils import (CAPTIONS_FILE, CHARTS, format_number, format_share, latex_escape, latex_table,
                                 plot_certificates, shutdown_render_pool, write_csv)

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
FORMATS = (".png", ".pdf", ".csv", ".tex")
# Log lines of the chart generation, in the order the charts must be reported
CHART_LOGS = ("Generating chart '", "Chart '", "No data available for chart '", "Error generating chart '")


@pytest.fixture(scope="module", autouse=True)
def stop_render_pool():
    yield
    shutdown_render_pool()


def chart(name):
    return next(chart for chart in CHARTS if chart.name == name)


def usage_key(*names):
    """Key of get_key_usage_distribution / get_extended_key_usage_distribution."""
    return json.dumps(", ".join(names))


def _crash_job(*args):
    """Stands in for a render process that dies (e.g. killed for lack of memory)."""
    os._exit(1)


def _signal_state():
    """Render process job: is SIGINT blocked since the start, and ignored after the set-up?"""
    return (signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, []),
            signal.getsignal(signal.SIGINT) == signal.SIG_IGN)


def test_numbers_and_shares():
    assert format_number(4245727) == "4,245,727"
    assert format_number(45.04, 1) == "45.0"
    assert format_share(4245727, 9434949) == "45.0%"
    assert format_share(2, 10000) == "0.02%"
    assert format_share(1, 100000) == "< 0.01%"
    assert format_share(0, 10) == "0%"


def test_csv_and_latex_table(tmp_path):
    rows = [("RSA-SHA256", 3000), ("RSA_SHA1 & co", 1)]
    write_csv(str(tmp_path / "t.csv"), rows)
    assert (tmp_path / "t.csv").read_text().splitlines() == [
        "category,count,share", "RSA-SHA256,3000,99.9667", "RSA_SHA1 & co,1,0.0333"]
    table = latex_table(rows, chart("signature_algorithm_distribution"), "Caption at 50%", "tab:leaf-t")
    for text in (r"\toprule", r"\midrule", r"\bottomrule", r"\label{tab:leaf-t}", r"\caption{Caption at 50\%}",
                 r"S[table-format=4.0]", r"RSA\_SHA1 \& co & 1 & 0.03 \\", r"Total & 3001 & 100.00 \\",
                 r"\sisetup{output-decimal-marker={.}, group-separator={,}, group-minimum-digits=4}"):
        assert text in table
    assert latex_escape("a_b ≤ 90 – 5") == r"a\_b $\leq$ 90 -- 5"
    with_status = latex_table(rows, chart("signature_algorithm_distribution"), "c", "tab:leaf-t",
                              ("Status", ["recommended", "deprecated"]))
    for text in (r"S[table-format=3.2] l}", r"{Share (\%)} & Status \\", r"RSA\_SHA1 \& co & 1 & 0.03 & deprecated \\",
                 r"Total & 3001 & 100.00 & \\"):
        assert text in with_status


def test_categories_are_sorted_labelled_and_coloured():
    items = _items(chart("signature_algorithm_distribution"), {"RSA-SHA1": 10, "RSA-SHA256": 70, "ECDSA-SHA256": 20})
    assert [(item.label, item.role) for item in items] == [
        ("RSA-SHA256", "main"), ("ECDSA-SHA256", "secondary"), ("RSA-SHA1", "negative")]
    issuers = _items(chart("issuer_certificates_count"), {"Others": 500, "Small CA": 2, "Big CA": 300})
    assert [item.label for item in issuers] == ["Big CA", "Small CA", "Other issuers"]
    assert issuers[-1].role == "other"
    ocsp = _items(chart("ocsp_status_distribution"), {"Good": 5, "Revoked": 1, "No OCSP Url Found": 0})
    assert [(item.label, item.role) for item in ocsp] == [("Good", "main"), ("Revoked", "negative")]
    days = _items(chart("validity_days_distribution"), {"negative": 1, "<=90": 4, "91-200": 0, ">1825": 2})
    assert [item.label for item in days] == ["Negative duration", "≤ 90 days", "> 5 years"]
    flags = _items(chart("critical_vs_non_critical_key_usage"), {"Critical": 3, "Not Found": 2, "Error": 1})
    assert [(item.label, item.role) for item in flags] == [("Critical", "main"), ("Not Found", "secondary"),
                                                           ("Error", "negative")]


def test_log_scale_above_three_orders_of_magnitude():
    assert not _use_log([1, 1000])
    assert _use_log([1, 1001])
    assert not _use_log([0, 5])


def test_upset_combinations_from_usage_keys():
    data = {usage_key("digital_signature", "key_encipherment"): 5, usage_key("digital_signature"): 3,
            usage_key(): 1, usage_key("certificate_sign", "crl_sign"): 3}
    assert _combinations(data) == [(("digitalSignature", "keyEncipherment"), 5), (("digitalSignature",), 3),
                                   (("keyCertSign", "cRLSign"), 3), ((), 1)]


@pytest.mark.parametrize("name, data, expected", [
    ("signature_algorithm_distribution", {"RSA-SHA256": 70, "ECDSA-SHA256": 20, "RSA-SHA1": 10},
     "In red, the deprecated algorithms (SHA-1)."),
    ("certificate_expiration_trend", {"2025-01": 5, "2025-02": 7, "2025-04": 3},
     "Expiring leaf certificates per month, from January 2025 to April 2025 (unique certificates; only the months "
     "with more than 1,100 expirations are shown). The line is broken at the omitted months."),
    ("key_usage_distribution", {usage_key("digital_signature", "key_encipherment"): 5, usage_key("crl_sign"): 2},
     "N = 7"),
    ("issuer_concentration", {"A": 50, "B": 30, "C": 20}, "is 3,800 (high concentration; N = 100 occurrences"),
    ("signature_family_share", {"RSA-SHA256": 70, "ECDSA-SHA256": 20, "RSA-SHA1": 10},
     "20.0% are signed with ECDSA (unique certificates, N = 100). 10 certificates (10.0%) are still signed with SHA-1."),
    ("validity_beyond_398_days", {"negative": 0, "<=90": 10, "91-200": 0, "201-398": 60, "399-825": 20,
                                  "826-1825": 10, ">1825": 0}, "30 certificates (30.0%) exceed it"),
])
def test_render_chart_writes_every_format(tmp_path, name, data, expected):
    outcome = render_chart(chart(name), data, DatabaseType.LEAF, str(tmp_path), {"threshold": "1,100 expirations"})
    assert outcome.image == str(tmp_path / f"{name}.png")
    assert expected in outcome.caption and "{" not in outcome.caption
    assert sorted(os.listdir(tmp_path)) == sorted(f"{name}{extension}" for extension in FORMATS)
    with Image.open(outcome.image) as image:
        assert image.size[0] == round(graph_plotter.WIDTH * 300)
        assert image.info["dpi"] == pytest.approx((300, 300), abs=0.01)
    assert (tmp_path / f"{name}.pdf").read_bytes().startswith(b"%PDF")
    assert f"\\label{{tab:leaf-{name}}}" in (tmp_path / f"{name}.tex").read_text()


def test_render_chart_without_data_writes_nothing(tmp_path):
    outcome = render_chart(chart("ocsp_status_distribution"), {"Good": 0}, DatabaseType.ROOT, str(tmp_path))
    assert outcome.image is None and os.listdir(tmp_path) == []


def test_line_is_broken_where_months_are_missing():
    data = {"2025-01": 5, "2025-02": 7, "2025-04": 3, "2025-11": 9, "2025-12": 4, "2026-01": 6}
    points = sorted((graph_plotter._month(key), value) for key, value in data.items())
    assert [len(run) for run in _consecutive_months(points)] == [2, 1, 3]
    drawing = _draw_line(chart("certificate_expiration_trend"), data, {})
    lines = drawing.figure.axes[0].lines
    assert [len(line.get_xdata()) for line in lines] == [2, 1, 3]
    assert lines[1].get_marker() == "o"
    assert drawing.fields["note"] == " The line is broken at the omitted months."
    # Long series without markers: an isolated month still gets one
    long = {f"{2010 + month // 12}-{month % 12 + 1:02d}": 10 for month in range(80) if month != 78}
    lines = _draw_line(chart("sct_trend"), long, {}).figure.axes[0].lines
    assert [(len(line.get_xdata()), line.get_marker()) for line in lines] == [(78, "None"), (1, "o")]
    single = _draw_line(chart("sct_trend"), {"2024-09": 3}, {})
    assert single.fields["period"] == "in September 2024" and "note" not in single.fields
    ticks = [label.get_text() for label in _draw_line(chart("sct_trend"), data, {}).figure.axes[0].get_xticklabels()]
    assert "Jan 2025" in ticks


def test_beyond_398_note_overlaps_no_bar_or_label():
    data = {"negative": 3, "<=90": 20, "91-200": 5, "201-398": 120, "399-825": 300, "826-1825": 40, ">1825": 700}
    for values in (data, {**data, "<=90": 5000}, {**data, "<=90": 700}):
        drawing = _draw_validity_limit(chart("validity_beyond_398_days"), values, {"type": "leaf"})
        figure = drawing.figure
        ax = figure.axes[0]
        renderer = figure.canvas.get_renderer()
        note = next(text for text in ax.texts if "beyond the 398-day limit" in text.get_text())
        assert note.get_color() == NEGATIVE
        box = note.get_window_extent(renderer)
        others = [text for text in ax.texts if text is not note] + list(ax.patches)
        assert not any(box.overlaps(artist.get_window_extent(renderer)) for artist in others)
    assert drawing.fields["note"] == " In red, the classes beyond the limit and the negative durations."
    assert drawing.figure.axes[0].get_title() == "55.7% of the leaf certificates exceed 398 days"


@pytest.mark.parametrize("name, kind, data, figure_text, table_text", [
    ("issuer_concentration", DatabaseType.INTERMEDIATE, {"Only CA": 42},
     "cumulative share of the occurrences of the only issuer. The Herfindahl-Hirschman index is 10,000",
     "Occurrences of intermediate certificates by issuer organization. The Herfindahl-Hirschman index is"),
    ("issuer_concentration", DatabaseType.ROOT, {f"CA {i}": 30 - i for i in range(25)},
     "of the first 20 issuers. The Herfindahl-Hirschman index, computed over all 25 issuers, is",
     "(the first 20 issuers, the others aggregated)"),
    ("validity_duration_distribution", DatabaseType.ROOT, {-1: 1, 0: 2},
     "durations with at least 1 certificate). In red, the negative durations.", "durations with at least 1 certificate)."),
    ("validity_beyond_398_days", DatabaseType.LEAF, {"<=90": 9, "399-825": 1},
     "1 certificate (10.0%) exceeds it", "1 certificate (10.0\\%) exceeds it"),
    ("signature_algorithm_distribution", DatabaseType.LEAF, {"RSA-SHA256": 7, "RSA-MD5": 1},
     "In red, the deprecated algorithms (MD5).", "RSA-MD5 & 1 & 12.50 & deprecated"),
    ("key_usage_distribution", DatabaseType.LEAF,
     {usage_key(f"usage_{index}"): 20 - index for index in range(13)},
     "(UpSet diagram)", "The 3 least frequent combinations are aggregated in the last row."),
    ("ocsp_status_distribution", DatabaseType.INTERMEDIATE, {"Good": 3, "Revoked": 1},
     "(N = 4 occurrences: a certificate presented by several domains is counted once for each of them). In red, the "
     "Revoked status.", "Outcome of the OCSP check of intermediate certificates (N = 4 occurrences"),
    ("signature_validity_distribution", DatabaseType.ROOT, {"Valid": 3, "Not Valid": 2, "Error": 1},
     "In red, the invalid signatures and the errors.", "Signature validity of root certificates"),
    # A single row: the total takes the singular noun
    ("issuer_certificates_count", DatabaseType.LEAF, {"Only": 1},
     "(at most 20 issuers, the others aggregated; N = 1 occurrence: a certificate", "N = 1 occurrence: a"),
    ("status_analysis", DatabaseType.LEAF, {"success": 1}, "(N = 1 domain).", "(N = 1 domain)."),
    ("top_sct_log_operators", DatabaseType.LEAF, {"Google": 1, "Cloudflare": 2}, "(N = 3 SCTs).", "(N = 3 SCTs)."),
])
def test_figure_and_table_captions(tmp_path, name, kind, data, figure_text, table_text):
    item = chart(name)
    fields = plotter_utils._caption_fields(item, StatisticsDAO(None, kind))
    outcome = render_chart(item, data, kind, str(tmp_path), fields)
    table = (tmp_path / f"{name}.tex").read_text(encoding="utf-8")
    assert figure_text in outcome.caption
    assert table_text in table
    # Tables never describe the drawing: no colours, columns of an UpSet diagram or curves
    caption = table.split(r"\caption{")[1].split("\n")[0]
    for drawing_word in ("In red", "diagram", "column", "curve", "line"):
        assert not re.search(rf"\b{drawing_word}\b", caption)


def test_thresholds_in_captions_agree_in_number():
    def threshold(name, kind):
        return plotter_utils._caption_fields(chart(name), StatisticsDAO(None, kind))["threshold"]

    assert threshold("validity_duration_distribution", DatabaseType.INTERMEDIATE) == "1 certificate"
    assert threshold("validity_duration_distribution", DatabaseType.LEAF) == "20 certificates"
    assert threshold("certificate_expiration_trend", DatabaseType.LEAF) == "1,100 expirations"
    assert threshold("certificates_per_country", DatabaseType.INTERMEDIATE) == "4 countries"
    assert threshold("top_sct_logs", DatabaseType.LEAF) == "12,000 unique certificates"


def generated(directory):
    """Chart names with their CSV and TeX contents."""
    directory = Path(directory)
    names = {path.stem for path in directory.glob("*.png")}
    for name in names:
        assert all((directory / f"{name}{extension}").exists() for extension in FORMATS)
    return {name: [(directory / f"{name}{extension}").read_text(encoding="utf-8") for extension in (".csv", ".tex")]
            for name in names}


def assert_chart_log(records, expected):
    """The chart generation messages start with the expected texts, in the same order."""
    messages = [record.getMessage() for record in records if record.getMessage().startswith(CHART_LOGS)]
    assert len(messages) == len(expected)
    assert [message[:len(prefix)] for message, prefix in zip(messages, expected)] == expected


def figures(captions_file):
    """The figure environments of captions.tex, without the header that names the folder."""
    return [line for line in captions_file.read_text().splitlines() if not line.startswith(("%", "\\providecommand"))]


def expected_chart_log(certificate_type, generated_names):
    """'Generating' followed by the outcome of each chart, in CHARTS order."""
    lines = []
    for item in CHARTS:
        if certificate_type in item.types:
            lines.append(f"Generating chart '{item.title}'")
            lines.append(f"Chart '{item.title}'" if item.name in generated_names
                         else f"No data available for chart '{item.title}'")
    return lines


@pytest.fixture
def database(tmp_path):
    connection = create_database(tmp_path / "leaf.db")
    yield connection
    connection.close()


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture(scope="module")
def in_process(tmp_path_factory):
    """Charts generated in the current process from the test database, by certificate type, with the log records
    and the plots folder; computed once for the module, as the reference of the other ways of generating them."""
    cache = {}

    def run(certificate_type):
        if certificate_type not in cache:
            directory = tmp_path_factory.mktemp(certificate_type.value)
            connection = create_database(directory / "certificates.db")
            root, handler = logging.getLogger(), _Records()
            level = root.level
            root.addHandler(handler)
            root.setLevel(logging.INFO)
            try:
                plot_certificates(StatisticsDAO(connection, certificate_type), directory / "plots", False, workers=0)
            finally:
                root.removeHandler(handler)
                root.setLevel(level)
                connection.close()
            cache[certificate_type] = SimpleNamespace(charts=generated(directory / "plots"), records=handler.records,
                                                      folder=directory / "plots")
        return cache[certificate_type]

    return run


def test_plot_certificates_in_process(in_process):
    reference = in_process(DatabaseType.LEAF)
    assert {"issuer_certificates_count", "validity_days_distribution", "key_usage_distribution", "issuer_concentration",
            "signature_family_share", "validity_beyond_398_days"} <= set(reference.charts)
    assert_chart_log(reference.records, expected_chart_log(DatabaseType.LEAF, reference.charts))
    captions = (reference.folder / CAPTIONS_FILE).read_text()
    assert captions.count(r"\begin{figure}") == len(reference.charts)
    assert r"\label{fig:leaf-validity_days_distribution}" in captions
    # Leaf, intermediate and root share the file names: each type has its own folder macro
    assert r"\providecommand{\plotsfolderleaf}{" + f"{reference.folder.parent.name}/plots" + "}" in captions
    assert r"\includegraphics[width=\textwidth]{\plotsfolderleaf/validity_days_distribution.pdf}" in captions
    assert reference.records[-1].getMessage() == "Chart generation for the Leaf certificate analysis completed."


def test_one_failing_chart_does_not_stop_the_others(database, tmp_path, monkeypatch, caplog, in_process):
    reference = in_process(DatabaseType.ROOT).charts       # before the failure is injected
    caplog.clear()
    # A few charts are enough: the failing one shares its query with the chart before it
    names = ("issuer_certificates_count", "signature_algorithm_distribution", "signature_family_share",
             "validity_days_distribution")
    monkeypatch.setattr(plotter_utils, "CHARTS", tuple(chart(name) for name in names))

    def render(chart, *args, **kwargs):
        if chart.name == "signature_family_share":
            raise ValueError("boom")
        return original(chart, *args, **kwargs)

    original = graph_plotter.render_chart
    monkeypatch.setattr(graph_plotter, "render_chart", render)
    with caplog.at_level(logging.INFO):
        plot_certificates(StatisticsDAO(database, DatabaseType.ROOT), tmp_path / "plots", False, workers=1)
    charts = generated(tmp_path / "plots")
    assert charts == {name: reference[name] for name in names if name != "signature_family_share"}
    assert "Error generating chart 'Signature Algorithm Families': boom" in caplog.text
    assert "signature_family_share" not in (tmp_path / "plots" / CAPTIONS_FILE).read_text()
    assert_chart_log(caplog.records, [line for item in (chart(name) for name in names)
                                      for line in (f"Generating chart '{item.title}'",
                                                   ("Error generating chart '" if item.name == names[2]
                                                    else "Chart '") + item.title)])


def test_process_pool_gives_the_same_files(database, tmp_path, caplog, in_process):
    reference = in_process(DatabaseType.LEAF)
    caplog.clear()      # the reference may have been computed just now, while caplog was capturing
    with caplog.at_level(logging.DEBUG):
        plot_certificates(StatisticsDAO(database, DatabaseType.LEAF), tmp_path / "pool", False, workers=2)
    assert generated(tmp_path / "pool") == reference.charts
    assert figures(tmp_path / "pool" / CAPTIONS_FILE) == figures(reference.folder / CAPTIONS_FILE)
    # The render processes read the tables once, then drew the charts
    assert any(record.getMessage().startswith("Statistics computed in") for record in caplog.records)
    assert not [record for record in caplog.records if record.name.startswith(("matplotlib", "fontTools", "PIL"))]
    # Logged in chart order, although the jobs ran in parallel
    assert_chart_log(caplog.records, expected_chart_log(DatabaseType.LEAF, generated(tmp_path / "pool")))


def test_queries_run_in_the_pool_when_not_materialized(database, tmp_path, caplog, monkeypatch, in_process):
    reference = in_process(DatabaseType.LEAF)
    caplog.clear()
    monkeypatch.setattr(StatisticsDAO, "materialize", lambda self, *args, **kwargs: False)
    with caplog.at_level(logging.DEBUG):
        plot_certificates(StatisticsDAO(database, DatabaseType.LEAF), tmp_path / "pool", False, workers=2)
    assert generated(tmp_path / "pool") == reference.charts
    # The queries ran in the render processes and their log records reached the main process
    forwarded = [record for record in caplog.records if record.getMessage().startswith("Rows returned")]
    assert forwarded and all(record.processName != "MainProcess" for record in forwarded)
    # Logged in chart order, although the jobs ran in parallel and the slowest one was submitted first
    assert_chart_log(caplog.records, expected_chart_log(DatabaseType.LEAF, generated(tmp_path / "pool")))


def test_memory_database_is_queried_here_and_drawn_in_processes(tmp_path, in_process):
    memory = create_database(":memory:")
    try:
        plot_certificates(StatisticsDAO(memory, DatabaseType.INTERMEDIATE), tmp_path / "memory", False, workers=2)
    finally:
        memory.close()
    assert generated(tmp_path / "memory") == in_process(DatabaseType.INTERMEDIATE).charts


def test_unreadable_file_is_queried_in_the_main_process(tmp_path, caplog, in_process):
    path = tmp_path / "gone.db"
    connection = create_database(path)
    try:
        path.unlink()
        plot_certificates(StatisticsDAO(connection, DatabaseType.ROOT), tmp_path / "plots", False, workers=2)
    finally:
        connection.close()
    assert "statistics computed sequentially" in caplog.text
    assert generated(tmp_path / "plots") == in_process(DatabaseType.ROOT).charts


def stopped(process, timeout=10):
    """True once the process has exited; the executor may reap it concurrently, so poll instead of a single join."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if not process.is_alive():
                return True
        except ValueError:      # closed by the executor: already joined
            return True
        time.sleep(0.05)
    return False


def test_pool_is_reused_and_stopped_on_interrupt(database, tmp_path, monkeypatch):
    dao = StatisticsDAO(database, DatabaseType.ROOT)
    plot_certificates(dao, tmp_path / "first", False, workers=2)
    executor = plotter_utils._pool[1]
    processes = list(executor._processes.values())
    assert processes
    used = []

    def interrupt(plotter, *args):
        used.append(plotter._executor)
        raise KeyboardInterrupt

    # Ctrl+C while the next call waits for its first chart
    monkeypatch.setattr(plotter_utils._Plotter, "_collect", interrupt)
    with pytest.raises(KeyboardInterrupt):
        plot_certificates(dao, tmp_path / "second", False, workers=2)
    assert used == [executor]       # the pool of the first call was reused
    assert plotter_utils._pool is None
    assert all(stopped(process) for process in processes)
    shutdown_render_pool()      # after Ctrl+C there is nothing left to stop


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX only")
def test_render_processes_ignore_ctrl_c_from_the_start_and_are_shut_down():
    shutdown_render_pool()      # no pool: nothing to do
    executor = plotter_utils._executor(2)
    blocked, ignored = plotter_utils._spawn_safe_submit(executor, _signal_state).result(timeout=60)
    # Blocked while the process started (a Ctrl+C then never interrupts its imports), ignored after the set-up
    assert blocked and ignored
    processes = list(executor._processes.values())
    shutdown_render_pool()
    shutdown_render_pool()
    assert plotter_utils._pool is None
    assert processes and all(stopped(process) for process in processes)


def test_broken_pool_falls_back_to_the_current_process(database, tmp_path, monkeypatch, caplog, in_process):
    monkeypatch.setattr(plotter_utils, "_query_job", _crash_job)
    monkeypatch.setattr(plotter_utils, "_render_job", _crash_job)
    plot_certificates(StatisticsDAO(database, DatabaseType.ROOT), tmp_path / "broken", False, workers=2)
    assert "Render processes stopped" in caplog.text
    assert plotter_utils._pool is None
    assert generated(tmp_path / "broken") == in_process(DatabaseType.ROOT).charts


def test_render_process_dying_during_the_scans(database, tmp_path, monkeypatch, caplog, in_process):
    monkeypatch.setattr(statistics_facts, "scan", _crash_job)
    plot_certificates(StatisticsDAO(database, DatabaseType.ROOT), tmp_path / "broken", False, workers=2)
    assert "Statistics not materialized" in caplog.text and "Render processes stopped" in caplog.text
    assert plotter_utils._pool is None
    assert generated(tmp_path / "broken") == in_process(DatabaseType.ROOT).charts


# The main process starts the render pool with two busy jobs, prints the pids of the render processes, then waits
_ORPHAN_PARENT = """
import os, time
from utils import plotter_utils, process_utils
process_utils.PARENT_CHECK_INTERVAL = 0.05      # also in the render processes, which import this module


def busy():
    print(os.getpid(), flush=True)
    time.sleep(60)


if __name__ == "__main__":
    executor = plotter_utils._executor(2)
    for _ in range(2):
        plotter_utils._spawn_safe_submit(executor, busy)
    time.sleep(60)
"""


def _read_line(stream, timeout):
    assert select.select([stream], [], [], timeout)[0], "no answer from the process"
    return stream.readline().decode()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_render_processes_exit_when_the_main_process_is_killed(tmp_path):
    script = tmp_path / "plots_main.py"
    script.write_text(_ORPHAN_PARENT)
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    parent = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, env=env, bufsize=0)
    pids = []
    try:
        pids = [int(_read_line(parent.stdout, 60)) for _ in range(2)]
        parent.kill()       # SIGKILL: no clean-up runs in the main process
        parent.wait()
        killed = time.monotonic()
        # The busy render processes are the last writers of the pipe: end of file once both have exited
        assert _read_line(parent.stdout, 10) == ""
        assert time.monotonic() - killed < 5
        pids = []
    finally:
        parent.kill()
        parent.wait()
        parent.stdout.close()
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


# The main process plots a database whose scans hang in the two render processes, which print their pids
_INTERRUPTED_PARENT = """
import os, sqlite3, sys, time
from dao import statistics_facts
from dao.statistics_dao import StatisticsDAO
from db.database import DatabaseType
from utils import plotter_utils


def slow_scan(*args):
    print(os.getpid(), flush=True)
    time.sleep(60)


if __name__ == "__main__":
    statistics_facts.scan = slow_scan
    connection = sqlite3.connect(sys.argv[1])
    try:
        plotter_utils.plot_certificates(StatisticsDAO(connection, DatabaseType.LEAF), sys.argv[2], False, workers=2)
    except KeyboardInterrupt:
        print("interrupted", flush=True)
        sys.exit(130)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_ctrl_c_during_the_scans_stops_the_render_processes(tmp_path):
    create_database(tmp_path / "leaf.db").close()
    script = tmp_path / "plots_main.py"
    script.write_text(_INTERRUPTED_PARENT)
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    parent = subprocess.Popen([sys.executable, str(script), str(tmp_path / "leaf.db"), str(tmp_path / "plots")],
                              stdout=subprocess.PIPE, env=env, bufsize=0,
                              preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
    pids = []
    try:
        pids = [int(_read_line(parent.stdout, 60)) for _ in range(2)]
        parent.send_signal(signal.SIGINT)
        assert parent.wait(timeout=10) == 130
        assert _read_line(parent.stdout, 10) == "interrupted\n"
        # The render processes were the other writers of the pipe: end of file once they have been stopped
        assert _read_line(parent.stdout, 10) == ""
        pids = []
    finally:
        parent.kill()
        parent.wait()
        parent.stdout.close()
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
