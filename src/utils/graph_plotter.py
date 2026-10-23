from __future__ import annotations

import json
import math
import os
import textwrap
import warnings
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable, NamedTuple

import matplotlib
import matplotlib.dates as mdates
import matplotlib.ticker as mticker
from matplotlib.axes import Axes
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from matplotlib.text import Text

from dao.statistics_dao import NEGATIVE_VALIDITY, VALIDITY_DAY_CLASSES
from db.database import DatabaseType
from utils.plotter_utils import TYPE_LABELS, format_number, format_share, latex_label, latex_table, write_csv

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Style A ("classic academic"): serif text, one accent colour, no top/right spines, no title (the caption goes in
# LaTeX). Narrative figures add a data-driven title.
INK, ACCENT, GREY, LIGHT_GREY, NEGATIVE = "#262626", "#1d3f6e", "#b8b8b8", "#dedede", "#7a1f1f"
_COLORS = {"main": ACCENT, "secondary": GREY, "other": LIGHT_GREY, "negative": NEGATIVE}
_STYLE = {
    "font.family": ["STIXGeneral", "DejaVu Sans"], "mathtext.fontset": "stix", "font.size": 9.5,
    "axes.titlesize": 10.5, "axes.titleweight": "bold", "axes.titlelocation": "left", "axes.labelsize": 9.5,
    "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": "#333333", "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
    "xtick.minor.width": 0.4, "ytick.minor.width": 0.4, "text.color": INK, "axes.labelcolor": INK,
    "pdf.fonttype": 42, "figure.dpi": 100, "savefig.dpi": 300,
}
WIDTH = 6.3                     # thesis text width, inches
_LABEL_SIZE = 7.8
_LABEL_OFFSET = 3               # points between a bar and its label
_LOG_SPAN = 1e3                 # log scale when the values span more than ~3 orders of magnitude
_MAX_LABEL = 42                 # longer category labels are shortened in the figure (tables keep them whole)
_UPSET_COMBINATIONS = 10        # combinations shown individually, the rest are aggregated
_CONCENTRATION_ISSUERS = 20     # issuers on the concentration curve
_BR_LIMIT_DAYS = 398            # CA/Browser Forum Baseline Requirements limit for TLS certificates
_MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December")
_DEPRECATED_HASHES = {"SHA1": "SHA-1", "MD5": "MD5", "MD2": "MD2"}
_OTHERS = "Others"

# Category labels: raw value -> readable label, for raw values that are not plain prose (the others, e.g. 'Critical',
# 'Not Found', 'Not Valid', and the technical names stay as they are)
_OCSP_LABELS = {"Impossible Retrieve OCSP Information": "OCSP information not retrievable",
                "Not Ok OCSP Response": "Invalid OCSP response", "No Issuer Url Found": "No issuer URL",
                "No OCSP Url Found": "No OCSP URL", "No Request Done": "No request made"}
_SELF_SIGNED_LABELS = {"True": "Self-signed", "False": "CA-signed"}
_NEGATIVE_DURATION = "Negative duration"
_DAY_LABELS = {NEGATIVE_VALIDITY: _NEGATIVE_DURATION, "<=90": "≤ 90 days", "91-200": "91–200 days",
               "201-398": "201–398 days", "399-825": "399–825 days", "826-1825": "826 days – 5 years",
               ">1825": "> 5 years"}
_LIMIT_TICKS = {NEGATIVE_VALIDITY: "negative", "<=90": "≤ 90", "91-200": "91–200", "201-398": "201–398",
                "399-825": "399–825", "826-1825": "826 – 5 years", ">1825": "> 5 years"}
_OTHERS_LABELS = {"issuers": "Other issuers", "countries": "Other countries"}
# Figure captions: what the red bars stand for, by category label
_NEGATIVE_NOTES = {_NEGATIVE_DURATION: "the negative durations", "Revoked": "the Revoked status",
                   "Not Valid": "the invalid signatures", "Error": "the errors"}
# Nouns of the caption totals ({n} {occurrences}), singular for N = 1
_TOTAL_NOUNS = {"occurrences": ("occurrence", "occurrences"), "domains": ("domain", "domains"), "scts": ("SCT", "SCTs")}
_USAGE_NAMES = {"certificate_sign": "keyCertSign", "crl_sign": "cRLSign", "ocsp_signing": "OCSPSigning",
                "any": "anyExtendedKeyUsage"}


class Item(NamedTuple):
    """One plotted category."""
    label: str
    value: int
    role: str = "secondary"     # 'main', 'secondary', 'other' (aggregated rest) or 'negative'


@dataclass(frozen=True)
class RenderOutcome:
    """Result of one chart: the PNG path (None when there was nothing to plot) and its caption."""
    name: str
    image: str | None
    caption: str = ""


@dataclass
class _Drawing:
    figure: Figure
    rows: list[tuple[str, int]]         # table rows: (category, value)
    fields: dict[str, Any]              # caption fields
    column: tuple[str, list[str]] | None = None     # extra text column of the table: heading, one value per row


# ---------------------------------------------------------------- formatting

def _count_label(value: int, total: int) -> str:
    return f"{format_number(value)} ({format_share(value, total)})"


def _shorten(label: str) -> str:
    return label if len(label) <= _MAX_LABEL else label[:_MAX_LABEL - 1].rstrip() + "…"


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{format_number(count)} {singular if count == 1 else plural}"


def _share_phrase(share: str) -> str:
    """A percentage as read in a sentence: '31.7%', 'less than 0.01%'."""
    return f"less than {share.lstrip('< ')}" if share.startswith("<") else share


def _capitalized(text: str) -> str:
    return text[:1].upper() + text[1:]


def _join(names: list[str], conjunction: str = "or") -> str:
    """'SHA-1', 'SHA-1 or MD5', 'SHA-1, MD5 or MD2'."""
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} {conjunction} {names[-1]}"


def _usage_name(name: str) -> str:
    """zgrab2 snake_case usage name -> RFC 5280 camelCase name (digital_signature -> digitalSignature)."""
    if name in _USAGE_NAMES:
        return _USAGE_NAMES[name]
    head, *tail = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


# ---------------------------------------------------------------- categories

def _deprecated_hashes(algorithms: Any) -> list[str]:
    """Deprecated hashes used by the given algorithms, in _DEPRECATED_HASHES order."""
    found = {_deprecated_hash(algorithm) for algorithm in algorithms}
    return [name for name in _DEPRECATED_HASHES.values() if name in found]


def _deprecated_hash(algorithm: str) -> str | None:
    """'RSA-SHA1' -> 'SHA-1'; None for algorithms with a current hash."""
    for part in str(algorithm).upper().split("-"):
        if part in _DEPRECATED_HASHES:
            return _DEPRECATED_HASHES[part]
    return None


def _basic_constraints_label(raw: Any) -> str:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)
    if not isinstance(value, dict):
        return str(value)
    if not value:
        return "Absent"
    names = {"is_ca": "cA"}
    return ", ".join(f"{names.get(k, k)} = {str(v).upper() if isinstance(v, bool) else v}" for k, v in value.items())


def _years_label(years: int) -> str:
    if years < 0:
        return _NEGATIVE_DURATION
    return "< 1 year" if years == 0 else ("1 year" if years == 1 else f"{years} years")


def _plain_label(raw: Any) -> str:
    if raw is None:
        return "(missing)"
    return str(raw) if str(raw).strip() else "(unspecified)"


_LABELERS: dict[str, Callable[[Any], tuple[str, bool]]] = {
    "plain": lambda raw: (_plain_label(raw), False),
    "flags": lambda raw: (_plain_label(raw), raw == "Error"),
    "version": lambda raw: (f"v{raw}" if isinstance(raw, int) else _plain_label(raw), False),
    "years": lambda raw: (_years_label(raw), raw < 0),
    "days": lambda raw: (_DAY_LABELS.get(raw, _plain_label(raw)), raw == NEGATIVE_VALIDITY),
    "signatures": lambda raw: (_plain_label(raw), _deprecated_hash(raw) is not None),
    "basic_constraints": lambda raw: (_basic_constraints_label(raw), False),
    "ocsp": lambda raw: (_OCSP_LABELS.get(raw, _plain_label(raw)), raw == "Revoked"),
    "signature_validity": lambda raw: (_plain_label(raw), raw in ("Not Valid", "Error")),
    "self_signed": lambda raw: (_SELF_SIGNED_LABELS.get(raw, _plain_label(raw)), False),
    "status": lambda raw: ("Success" if raw == "success" else _plain_label(raw), False),
    "operators": lambda raw: ("Unknown" if raw == "unknown" else _plain_label(raw), False),
}


def _items(chart: Any, data: dict) -> list[Item]:
    """Plotted categories: labelled, zero counts dropped, sorted by value unless the chart is ordinal."""
    if chart.labels == "key_lengths":
        # {algorithm: {length: count}} -> one bar per algorithm and length
        pairs = [(f"{algorithm} {length}", count, False)
                 for algorithm, lengths in data.items() for length, count in lengths.items()]
    else:
        labeler = _LABELERS.get(chart.labels, _LABELERS["plain"])
        pairs = []
        for raw, count in data.items():
            if raw == _OTHERS and chart.labels in _OTHERS_LABELS:
                pairs.append((_OTHERS_LABELS[chart.labels], count, None))
            else:
                label, negative = labeler(raw)
                pairs.append((label, count, negative))
    items = [(label, int(count), negative) for label, count, negative in pairs if count]
    if not chart.ordered:
        # Largest first; the aggregated rest (negative=None) always last
        items.sort(key=lambda item: (item[2] is None, -item[1], item[0]))
    return _assign_roles(items)


def _assign_roles(items: list[tuple[str, int, bool | None]]) -> list[Item]:
    """Accent for the largest categories that together reach half of the total, grey for the rest."""
    total = sum(value for _, value, _ in items)
    main, running = set(), 0
    for index in sorted((i for i, item in enumerate(items) if item[2] is False),
                        key=lambda i: -items[i][1]):
        if running >= total / 2:
            break
        main.add(index)
        running += items[index][1]
    roles = []
    for index, (label, value, negative) in enumerate(items):
        role = "other" if negative is None else "negative" if negative else "main" if index in main else "secondary"
        roles.append(Item(label, value, role))
    return roles


# ---------------------------------------------------------------- figure helpers

def _figure(height: float) -> Figure:
    figure = Figure(figsize=(WIDTH, height))
    FigureCanvasAgg(figure)
    return figure


def _use_log(values: list[int]) -> bool:
    positive = [value for value in values if value > 0]
    return bool(positive) and max(positive) / min(positive) > _LOG_SPAN


def _log_floor(values: list[int]) -> float:
    return 0.7 * 10 ** math.floor(math.log10(min(values)))


def _fit_limit(low: float, values: list[float], sizes: list[float], length: float, log: bool) -> float:
    """Upper axis limit so that every label (sizes, in pixels) fits after its value inside the axis (length px)."""
    usable = length * 0.98
    limit = max(values) * (1.25 if log else 1.04)
    for value, size in zip(values, sizes):
        room = max(usable - size, length * 0.25)
        if log:
            start = math.log10(low)
            limit = max(limit, 10 ** (start + (math.log10(value) - start) * length / room))
        else:
            limit = max(limit, value * length / room)
    return limit


def _label_sizes(figure: Figure, texts: list[Text], vertical: bool) -> list[float]:
    renderer = figure.canvas.get_renderer()
    offset = _LABEL_OFFSET * figure.dpi / 72
    return [(text.get_window_extent(renderer).height if vertical else text.get_window_extent(renderer).width) + offset
            for text in texts]


def _fit_value_axis(figure: Figure, ax: Axes, texts: list[Text], values: list[int], log: bool, vertical: bool) -> None:
    """Make room for the value labels at the end of the bars, then redo the layout."""
    low = _log_floor(values) if log else 0
    figure.tight_layout()
    box = ax.get_window_extent(figure.canvas.get_renderer())
    limit = _fit_limit(low, values, _label_sizes(figure, texts, vertical), box.height if vertical else box.width, log)
    (ax.set_ylim if vertical else ax.set_xlim)(low, limit)
    figure.tight_layout()


def _value_axis(axis: Any, values: list[int], label: str, log: bool, set_label: Callable[[str], None]) -> None:
    """Value axis: log scale, millions or integers with thousands separators."""
    if log:
        axis.set_major_locator(mticker.LogLocator(numticks=12))
        set_label(f"{label} (log scale)")
        return
    if max(values) >= 1e6:
        axis.set_major_formatter(mticker.FuncFormatter(lambda x, _: format_number(x / 1e6, 1 if x % 1e6 else 0)))
        set_label(f"{label} (millions)")
    else:
        axis.set_major_locator(mticker.MaxNLocator(integer=True))
        axis.set_major_formatter(mticker.FuncFormatter(lambda x, _: format_number(x)))
        set_label(label)


def _hbars(figure: Figure, ax: Axes, items: list[Item], total: int, axis_label: str) -> None:
    """Horizontal bars, first item on top, each labelled 'count (percent)'."""
    values = [item.value for item in items]
    positions = list(range(len(items)))[::-1]
    log = _use_log(values)
    if log:
        ax.set_xscale("log")
    ax.barh(positions, values, color=[_COLORS[item.role] for item in items], height=0.66)
    texts = [ax.annotate(_count_label(value, total), (value, y), xytext=(_LABEL_OFFSET, 0), textcoords="offset points",
                         va="center", fontsize=_LABEL_SIZE, color=INK) for value, y in zip(values, positions)]
    ax.set_yticks(positions, [_shorten(item.label) for item in items])
    ax.set_ylim(-0.6, len(items) - 0.4)
    ax.tick_params(axis="y", length=0)
    _value_axis(ax.xaxis, values, axis_label, log, ax.set_xlabel)
    _fit_value_axis(figure, ax, texts, values, log, vertical=False)


def _set_title(figure: Figure, ax: Axes, title: str) -> None:
    """Data-driven title of a narrative figure, wrapped on two balanced lines when wider than the figure."""
    text = ax.set_title(title)
    figure.tight_layout()
    renderer = figure.canvas.get_renderer()
    if text.get_window_extent(renderer).x1 <= figure.bbox.width:
        return
    width = len(title) // 2
    while len(textwrap.wrap(title, width)) > 2:
        width += 1
    text.set_text("\n".join(textwrap.wrap(title, width)))


def _bars_height(count: int) -> float:
    return max(1.7, 0.85 + 0.235 * count)


def _rows(items: list[Item]) -> list[tuple[str, int]]:
    return [(item.label, item.value) for item in items]


# ---------------------------------------------------------------- charts

def _draw_bars(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    items = _items(chart, data)
    if not items:
        return None
    total = sum(item.value for item in items)
    figure = _figure(_bars_height(len(items)))
    ax = figure.add_subplot()
    _hbars(figure, ax, items, total, chart.axis)
    negatives = [item.label for item in items if item.role == "negative"]
    column = None
    if chart.labels == "signatures":
        # The table marks the deprecated algorithms in a column instead of the colour
        column = ("Status", ["deprecated" if item.role == "negative" else "recommended" for item in items])
    if negatives and chart.labels == "signatures":
        text = f"deprecated algorithms ({', '.join(_deprecated_hashes(raw for raw, count in data.items() if count))})"
        ax.text(0.99, 0.03, f"in red: {text}", transform=ax.transAxes, ha="right", fontsize=7.5, color=NEGATIVE,
                style="italic")
        fields["note"] = f" In red, the {text}."
    elif negatives:
        phrases = list(dict.fromkeys(_NEGATIVE_NOTES.get(label, label) for label in negatives))
        fields["note"] = f" In red, {_join(phrases, 'and')}."
    return _Drawing(figure, _rows(items), fields, column)


def _month(key: Any) -> date | None:
    try:
        year, month = str(key).split("-")
        return date(int(year), int(month), 1)
    except (TypeError, ValueError):
        return None


def _month_label(day: date, long: bool = False) -> str:
    """'Jan 2025', or 'January 2025' when long."""
    name = _MONTHS[day.month - 1]
    return f"{name if long else name[:3]} {day.year}"


def _month_axis(ax: Axes, first: date, last: date) -> None:
    """Month labels ('Jan 2025'), or years only for long periods."""
    months = (last.year - first.year) * 12 + last.month - first.month
    if months > 48:
        locator = mdates.YearLocator(max(1, math.ceil(months / 12 / 8)))
        formatter = mticker.FuncFormatter(lambda x, _: str(mdates.num2date(x).year))
    else:
        step = next(step for step in (1, 2, 3, 4, 6, 12) if (months + 1) / step <= 8)
        locator = mdates.MonthLocator(bymonth=range(1, 13, step))
        formatter = mticker.FuncFormatter(lambda x, _: _month_label(mdates.num2date(x).date()))
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(formatter)


def _consecutive_months(points: list[tuple[date, int]]) -> list[list[tuple[date, int]]]:
    """Runs of consecutive months: the queries leave out the months below the threshold."""
    runs: list[list[tuple[date, int]]] = []
    for day, value in points:
        previous = runs[-1][-1][0] if runs else None
        if previous and (day.year - previous.year) * 12 + day.month - previous.month == 1:
            runs[-1].append((day, value))
        else:
            runs.append([(day, value)])
    return runs


def _draw_line(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    points = sorted((day, int(count)) for day, count in ((_month(key), count) for key, count in data.items()) if day)
    if not points:
        return None
    days, values = [day for day, _ in points], [value for _, value in points]
    figure = _figure(2.8)
    ax = figure.add_subplot()
    runs = _consecutive_months(points)
    # One line per run, so the line never bridges the omitted months; isolated months always get a marker
    for run in runs:
        ax.plot([day for day, _ in run], [value for _, value in run], color=ACCENT, linewidth=1.3,
                marker="o" if len(points) <= 60 or len(run) == 1 else None, markersize=2.6)
    ax.set_ylim(0, max(values) * 1.08)
    if len(days) == 1:
        ax.set_xlim(mdates.date2num(days[0]) - 31, mdates.date2num(days[0]) + 31)
    _month_axis(ax, days[0], days[-1])
    _value_axis(ax.yaxis, values, chart.axis, False, ax.set_ylabel)
    ax.set_xlabel("Month")
    figure.tight_layout()
    rows = [(f"{day:%Y-%m}", value) for day, value in points]
    if len(days) == 1:
        fields["period"] = f"in {_month_label(days[0], True)}"
    else:
        fields["period"] = f"per month, from {_month_label(days[0], True)} to {_month_label(days[-1], True)}"
    if len(runs) > 1:
        fields["note"] = " The line is broken at the omitted months."
    return _Drawing(figure, rows, fields)


def _combinations(data: dict) -> list[tuple[tuple[str, ...], int]]:
    """Usage sets from the get_*_key_usage_distribution keys (JSON strings 'name1, name2'), largest first."""
    combos = {}
    for key, count in data.items():
        try:
            text = json.loads(key)
        except (TypeError, ValueError):
            text = key
        names = tuple(_usage_name(name) for name in str(text or "").split(", ") if name)
        combos[names] = combos.get(names, 0) + int(count)
    return sorted(((names, count) for names, count in combos.items() if count), key=lambda item: (-item[1], item[0]))


def _draw_upset(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    """UpSet diagram: bars for the size of each combination, dot matrix for the flags in it."""
    combos = _combinations(data)
    if not combos:
        return None
    shown, rest = combos[:_UPSET_COMBINATIONS], combos[_UPSET_COMBINATIONS:]
    if len(rest) == 1:
        shown, rest = combos, []
    totals = {}
    for names, count in combos:
        for name in names:
            totals[name] = totals.get(name, 0) + count
    flags = sorted({name for names, _ in shown for name in names}, key=lambda name: (-totals[name], name))
    total = sum(count for _, count in combos)
    rows = [(" + ".join(names) or "(empty extension)", count) for names, count in shown]
    if rest:
        rows.append((f"{len(rest)} other combinations", sum(count for _, count in rest)))
        fields["note"] = f" The {len(rest)} least frequent combinations are aggregated in the last column."
        fields["table_note"] = f" The {len(rest)} least frequent combinations are aggregated in the last row."
    if not flags:
        return None if not rows else _upset_as_bars(chart, rows, total, fields)

    figure = _figure(1.9 + 0.2 * len(flags) + 0.35)
    # No local spacing on the grid: tight_layout ignores grids with locally modified parameters
    grid = figure.add_gridspec(2, 1, height_ratios=[2.0, 0.2 * len(flags) + 0.25])
    ax_bar = figure.add_subplot(grid[0])
    ax_matrix = figure.add_subplot(grid[1], sharex=ax_bar)
    values = [count for _, count in rows]
    positions = list(range(len(rows)))
    log = _use_log(values)
    if log:
        ax_bar.set_yscale("log")
    colors = [ACCENT] * len(shown) + [LIGHT_GREY] * (len(rows) - len(shown))
    ax_bar.bar(positions, values, color=colors, width=0.62)
    texts = [ax_bar.annotate(f"{format_number(value)}\n{format_share(value, total)}", (x, value),
                             xytext=(0, _LABEL_OFFSET), textcoords="offset points", ha="center", va="bottom",
                             fontsize=6.6, color=INK, linespacing=1.05) for x, value in zip(positions, values)]
    _value_axis(ax_bar.yaxis, values, chart.axis, log, ax_bar.set_ylabel)
    ax_bar.tick_params(axis="x", bottom=False, labelbottom=False)
    ax_bar.spines["bottom"].set_visible(False)
    _upset_matrix(ax_matrix, flags, [names for names, _ in shown], len(rest))
    _fit_value_axis(figure, ax_bar, texts, values, log, vertical=True)
    return _Drawing(figure, rows, fields)


def _upset_matrix(ax: Axes, flags: list[str], combos: list[tuple[str, ...]], aggregated: int) -> None:
    rows = {name: len(flags) - 1 - index for index, name in enumerate(flags)}
    middle = (len(flags) - 1) / 2
    for x, names in enumerate(combos):
        active = [rows[name] for name in names]
        if active:
            ax.scatter([x] * len(flags), list(rows.values()), s=17, color="#e3e3e3", zorder=1, linewidths=0)
            ax.scatter([x] * len(active), active, s=17, color=INK, zorder=3, linewidths=0)
            ax.plot([x, x], [min(active), max(active)], color=INK, linewidth=1.1, zorder=2)
        else:
            ax.text(x, middle, "no flags", rotation=90, ha="center", va="center", fontsize=6.6, color="#666666")
    if aggregated:
        ax.text(len(combos), middle, f"{aggregated} others", rotation=90, ha="center", va="center", fontsize=6.6,
                color="#666666")
    ax.set_yticks(list(rows.values()), list(rows))
    ax.set_ylim(-0.6, len(flags) - 0.4)
    # A few combinations keep the width of a column instead of filling the figure
    ax.set_xlim(-0.6, max(len(combos) + (1 if aggregated else 0), 6) - 0.4)
    ax.tick_params(axis="both", length=0, labelbottom=False)
    for side in ("left", "bottom"):
        ax.spines[side].set_visible(False)


def _upset_as_bars(chart: Any, rows: list[tuple[str, int]], total: int, fields: dict) -> _Drawing:
    """Without any flag (only empty extensions) the matrix is empty: plain bars instead."""
    items = _assign_roles([(label, value, False) for label, value in rows])
    figure = _figure(_bars_height(len(items)))
    _hbars(figure, figure.add_subplot(), items, total, chart.axis)
    return _Drawing(figure, rows, fields)


def _draw_concentration(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    """Concentration curve of the issuers with the Herfindahl-Hirschman index (over every issuer)."""
    counts = sorted((int(count) for count in data.values() if count), reverse=True)
    total = sum(counts)
    if not total:
        return None
    names = sorted(((int(count), str(name)) for name, count in data.items() if count), key=lambda item: (-item[0], item[1]))
    shown = names[:_CONCENTRATION_ISSUERS]
    cumulative, running = [], 0
    for count, _ in shown:
        running += count
        cumulative.append(100 * running / total)
    hhi = sum((100 * count / total) ** 2 for count in counts)
    half = next(index for index, share in enumerate(cumulative) if share >= 50 or index == len(cumulative) - 1) + 1
    share = format_share(_first_issuers(shown, half), total)
    occurrences = f"of the occurrences of {fields['type']} certificates"
    if len(counts) == 1:
        title = f"A single issuer ({_shorten(shown[0][1])}) for all the occurrences of {fields['type']} certificates"
    elif half == 1:
        title = f"One issuer ({_shorten(shown[0][1])}) covers {_share_phrase(share)} {occurrences}"
    else:
        title = f"The first {half} issuers cover {_share_phrase(share)} {occurrences}"

    figure = _figure(3.0)
    ax = figure.add_subplot()
    ranks = list(range(1, len(shown) + 1))
    ax.fill_between(ranks, cumulative, color=ACCENT, alpha=0.10, linewidth=0)
    ax.plot(ranks, cumulative, color=ACCENT, linewidth=1.5, marker="o", markersize=3.2)
    ax.set_ylim(0, 104)
    ax.set_xlim(0.5, max(len(shown), 2) + 0.5)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: f"{y:.0f}%"))
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.set_xlabel("Number of issuers (sorted by share)")
    ax.set_ylabel("Cumulative share of the occurrences")
    _set_title(figure, ax, title)
    arrow = {"arrowstyle": "->", "color": "#555555", "lw": 0.7}
    first = "only issuer" if len(counts) == 1 else "first issuer"
    ax.annotate(f"{first}: {share}" if half == 1 else f"first {half}: {share}", (half, cumulative[half - 1]),
                xytext=(18, -26), textcoords="offset points", fontsize=7.8, arrowprops=arrow)
    if len(shown) >= 10 and half != 10:
        ax.annotate(f"first 10: {format_share(_first_issuers(shown, 10), total)}", (10, cumulative[9]),
                    xytext=(10, -26), textcoords="offset points", fontsize=7.8, arrowprops=arrow)
    level = "high" if hhi > 1800 else "moderate" if hhi >= 1000 else "low"
    every = "over the only issuer" if len(counts) == 1 else f"over all {format_number(len(counts))} issuers"
    ax.text(0.99, 0.05, f"Herfindahl-Hirschman index: {format_number(hhi)} ({level} concentration)\n"
            f"computed {every}", transform=ax.transAxes, ha="right", va="bottom", fontsize=7.4, color="#444444")
    figure.tight_layout()
    rows = [(name, count) for count, name in shown]
    aggregated = len(names) > len(shown)
    if aggregated:
        rows.append((_OTHERS_LABELS["issuers"], total - sum(count for count, _ in shown)))
    fields.update(hhi=format_number(hhi), level=level, share=share, curve=_curve_phrase(len(shown), len(counts)),
                  computed=f", computed {every}," if aggregated else "",
                  rows=f" (the first {len(shown)} issuers, the others aggregated)" if aggregated else "")
    return _Drawing(figure, rows, fields)


def _curve_phrase(shown: int, issuers: int) -> str:
    """Issuers on the concentration curve: 'of the only issuer', 'of the 6 issuers', 'of the first 20 issuers'."""
    if issuers == 1:
        return "of the only issuer"
    return f"of the {shown} issuers" if shown == issuers else f"of the first {shown} issuers"


def _first_issuers(shown: list[tuple[int, str]], first: int) -> int:
    """Certificates of the first `first` issuers."""
    return sum(count for count, _ in shown[:first])


_OTHER_FAMILIES = "Others"


def _signature_family(algorithm: Any) -> str:
    head = str(algorithm).upper().split("-")[0]
    if head.startswith("RSA"):
        return "RSA"
    if head.startswith("ECDSA"):
        return "ECDSA"
    if head.startswith("ED25519") or head.startswith("ED448"):
        return "EdDSA"
    return "DSA" if head == "DSA" else _OTHER_FAMILIES


def _draw_families(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    """RSA vs ECDSA share of the signature algorithms, with the certificates still signed with SHA-1/MD5."""
    families = {}
    for algorithm, count in data.items():
        family = _signature_family(algorithm)
        families[family] = families.get(family, 0) + int(count)
    families = {family: count for family, count in families.items() if count}
    total = sum(families.values())
    if not total:
        return None
    order = sorted(families, key=lambda family: (family == _OTHER_FAMILIES, -families[family], family))
    roles = {"ECDSA": "main", "RSA": "secondary"}
    items = [Item(family, families[family], roles.get(family, "other")) for family in order]
    deprecated_count = sum(int(count) for algorithm, count in data.items() if _deprecated_hash(algorithm))
    highlighted = "ECDSA" if "ECDSA" in families else order[0]
    share = _share_phrase(format_share(families[highlighted], total))
    title = f"{_capitalized(share)} of the {fields['type']} certificates are signed with {highlighted}"
    hashes = _join(_deprecated_hashes(algorithm for algorithm, count in data.items() if count) or ["SHA-1", "MD5"])
    if deprecated_count:
        verb = "is" if deprecated_count == 1 else "are"
        note = (f"{_plural(deprecated_count, 'certificate', 'certificates')} ({format_share(deprecated_count, total)}) "
                f"{verb} still signed with {hashes}.")
    else:
        note = f"No certificate is signed with {hashes}."

    figure = _figure(max(1.9, 1.25 + 0.3 * len(items)))
    ax = figure.add_subplot()
    _hbars(figure, ax, items, total, chart.axis)
    _set_title(figure, ax, title)
    # The bars carry count and share: the value axis gives way to the note on deprecated hashes
    ax.tick_params(axis="x", which="both", bottom=False, labelbottom=False)
    ax.spines["bottom"].set_visible(False)
    ax.set_xlabel(note, loc="left", fontsize=8, style="italic", color=NEGATIVE if deprecated_count else "#444444")
    figure.tight_layout()
    fields.update(note=f" {note}", table_note=f" {note}", family=highlighted, share=share)
    return _Drawing(figure, _rows(items), fields)


def _draw_validity_limit(chart: Any, data: dict, fields: dict) -> _Drawing | None:
    """Validity classes in days with the share beyond the 398-day limit of the Baseline Requirements."""
    beyond_keys = {key for key, limit in VALIDITY_DAY_CLASSES if limit is None or limit > _BR_LIMIT_DAYS}
    classes = [(key, int(data.get(key, 0))) for key in (NEGATIVE_VALIDITY, *(key for key, _ in VALIDITY_DAY_CLASSES))]
    classes = [(key, count) for key, count in classes if count or key != NEGATIVE_VALIDITY]
    total = sum(count for _, count in classes)
    if not total:
        return None
    beyond = sum(count for key, count in classes if key in beyond_keys)
    share = format_share(beyond, total)
    if beyond:
        title = (f"{_capitalized(_share_phrase(share))} of the {fields['type']} certificates exceed "
                 f"{_BR_LIMIT_DAYS} days")
    else:
        title = f"No {fields['type']} certificate exceeds {_BR_LIMIT_DAYS} days of validity"

    figure = _figure(2.7)
    ax = figure.add_subplot()
    positions = list(range(len(classes)))
    shares = [100 * count / total for _, count in classes]
    colors = [NEGATIVE if key in beyond_keys or key == NEGATIVE_VALIDITY else ACCENT for key, _ in classes]
    bars = ax.bar(positions, shares, color=colors, width=0.62)
    labels = [ax.annotate(format_share(count, total), (x, 100 * count / total), xytext=(0, 2), textcoords="offset points",
                          ha="center", va="bottom", fontsize=_LABEL_SIZE, color=INK)
              for x, (_, count) in zip(positions, classes)]
    ax.set_xticks(positions, [_LIMIT_TICKS[key] for key, _ in classes])
    ax.set_xlabel("Validity duration (days)")
    ax.set_ylim(0, max(shares) * 1.18)
    ax.set_yticks([])
    ax.spines["left"].set_visible(False)
    _set_title(figure, ax, title)
    figure.tight_layout()
    if beyond:
        # On the side whose bars are lower, then above every bar and label
        middle = len(shares) // 2
        left = max(shares[:middle]) < max(shares[len(shares) - middle:])
        note = ax.text(0.01 if left else 0.99, 0.97, f"{_plural(beyond, 'certificate', 'certificates')} beyond the "
                       f"{_BR_LIMIT_DAYS}-day limit\nof the Baseline Requirements (CA/Browser Forum)",
                       transform=ax.transAxes, ha="left" if left else "right", va="top", fontsize=7.6, color=NEGATIVE)
        _clear_note(figure, ax, note, [*bars, *labels])
    fields.update(share=share, beyond=_beyond_phrase(beyond, share))
    if beyond or classes[0][0] == NEGATIVE_VALIDITY:
        reds = [phrase for phrase, shown in (("the classes beyond the limit", beyond),
                                             ("the negative durations", classes[0][0] == NEGATIVE_VALIDITY)) if shown]
        fields["note"] = f" In red, {_join(reds, 'and')}."
    return _Drawing(figure, [(_DAY_LABELS[key], count) for key, count in classes], fields)


def _beyond_phrase(beyond: int, share: str) -> str:
    if not beyond:
        return "no certificate exceeds it"
    return f"{_plural(beyond, 'certificate', 'certificates')} ({share}) {'exceeds' if beyond == 1 else 'exceed'} it"


def _clear_note(figure: Figure, ax: Axes, note: Text, artists: list) -> None:
    """Raise the top of the value axis until the note (anchored to the axes) overlaps no bar and no label."""
    renderer = figure.canvas.get_renderer()
    for _ in range(12):
        box = note.get_window_extent(renderer)
        if not any(box.overlaps(artist.get_window_extent(renderer)) for artist in artists):
            return
        low, high = ax.get_ylim()
        ax.set_ylim(low, high * 1.12)


_DRAWERS: dict[str, Callable[[Any, dict, dict], _Drawing | None]] = {
    "bars": _draw_bars, "line": _draw_line, "upset": _draw_upset, "concentration": _draw_concentration,
    "families": _draw_families, "validity_limit": _draw_validity_limit,
}


# ---------------------------------------------------------------- entry point

def render_chart(chart: Any, data: dict, certificate_type: DatabaseType, directory: str,
                 fields: dict | None = None) -> RenderOutcome:
    """Draw one chart and write <name>.png (300 dpi), .pdf, .csv and .tex into directory.

    `chart` is a plotter_utils.Chart; its caption templates are filled with type, n (the plotted total), note, the
    nouns of n (occurrences, domains, scts: singular when n is 1), the given fields and the fields computed by the
    drawing. The figure caption gets the drawing's 'note' (e.g. what the red bars mean), the table caption its
    'table_note'.
    """
    fields = {"type": TYPE_LABELS[certificate_type], "note": "", "table_note": "", **(fields or {})}
    with matplotlib.rc_context(_STYLE), warnings.catch_warnings():
        # Missing glyphs (e.g. CJK organization names) and similar rendering warnings must not reach the console
        warnings.simplefilter("ignore")
        drawing = _DRAWERS[chart.kind](chart, data, fields)
        if drawing is None:
            return RenderOutcome(chart.name, None)
        base = os.path.join(directory, chart.name)
        drawing.figure.savefig(f"{base}.png", metadata={"Software": None})
        drawing.figure.savefig(f"{base}.pdf", metadata={"Creator": None, "Producer": None, "CreationDate": None})
    total = sum(value for _, value in drawing.rows)
    fields = {**drawing.fields, "n": format_number(total),
              **{noun: forms[0] if total == 1 else forms[1] for noun, forms in _TOTAL_NOUNS.items()}}
    caption = chart.caption.format(**fields)
    table_caption = (chart.table or chart.caption).format(**{**fields, "note": fields["table_note"]})
    write_csv(f"{base}.csv", drawing.rows)
    with open(f"{base}.tex", "w", encoding="utf-8") as file:
        file.write(latex_table(drawing.rows, chart, table_caption, latex_label("tab", certificate_type, chart.name),
                               drawing.column))
    return RenderOutcome(chart.name, os.path.abspath(f"{base}.png"), caption)
