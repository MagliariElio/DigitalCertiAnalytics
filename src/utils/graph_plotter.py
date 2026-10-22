from __future__ import annotations

import logging
import os
import warnings
from typing import Callable

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from matplotlib.axes import Axes
from matplotlib.figure import Figure

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Shared chart style, applied via plt.rc_context so global rcParams stay untouched
_BASE_STYLE = {
    **sns.axes_style("whitegrid"),
    'font.family': 'serif',
    'font.size': 12,
    'axes.titlesize': 16,
    'axes.titleweight': 'bold',
}
_DPI = 300
_BAR_LABEL_OFFSET = 3


def _autopct(pct: float) -> str:
    """Pie wedge label; empty for negligible wedges."""
    return f'{pct:.1f}%' if pct > 0.1 else ''


def _rotate_xticks(ax: Axes) -> None:
    plt.setp(ax.get_xticklabels(), rotation=45, ha='right', fontsize=12)


class GraphPlotter:
    """Renders the certificate analysis charts to image files."""

    def __init__(self, is_verbose: bool = False) -> None:
        """Silence plotting-library logging (seaborn too, unless verbose)."""
        logging.getLogger('PIL.PngImagePlugin').setLevel(logging.ERROR)
        logging.getLogger('matplotlib').setLevel(logging.ERROR)
        warnings.filterwarnings("ignore", category=FutureWarning)
        if not is_verbose:
            logging.getLogger('seaborn').setLevel(logging.ERROR)

    def plot_bar_chart(self, data: pd.DataFrame, y: str, title: str, xlabel: str, ylabel: str, filename: str) -> None:
        """Vertical bar chart of `y` per index category, with value labels."""
        def draw(ax: Axes) -> None:
            # A color list keeps the mapping categorical even for numeric indexes
            # (same colors as palette='viridis' without hue, deprecated since seaborn 0.13)
            palette = sns.color_palette('viridis', n_colors=data.index.nunique())
            sns.barplot(x=data.index, y=y, data=data, hue=data.index, palette=palette, legend=False, ax=ax)
            ax.set_title(title, fontsize=16, fontweight='bold', pad=30)
            ax.set_xlabel(xlabel, fontsize=14)
            ax.set_ylabel(ylabel, fontsize=14)
            _rotate_xticks(ax)
            plt.setp(ax.get_yticklabels(), fontsize=12)
            ax.grid(axis='y', linestyle='--', alpha=0.7)
            for patch in ax.patches:
                height = patch.get_height()
                ax.text(patch.get_x() + patch.get_width() / 2.0, height + _BAR_LABEL_OFFSET, f'{height:.0f}',
                        ha='center', va='bottom', fontsize=10)

        self._render(data, title, filename, draw, figsize=(14, 7), dpi=_DPI, bbox_inches='tight')

    def plot_pie_chart(self, data: pd.DataFrame, column: str, title: str, filename: str) -> None:
        """Pie chart of `column`, with the index categories in the legend."""
        def draw(ax: Axes) -> None:
            wedges, _, autotexts = ax.pie(
                data[column],
                autopct=_autopct,
                startangle=140,
                colors=sns.color_palette('muted', n_colors=len(data)),
                wedgeprops={'edgecolor': 'white', 'linewidth': 1.5},
                pctdistance=1.05,
                explode=[0.06] * len(data)
            )
            plt.setp(autotexts, fontsize=10, fontweight='medium', color='black')
            ax.set_title(title, pad=20)
            ax.axis('equal')
            legend = ax.legend(wedges, data.index, title="Legend", loc='best', bbox_to_anchor=(1.1, 1), fontsize=10,
                               frameon=True, framealpha=0.9, borderpad=1)
            plt.setp(legend.get_title(), fontsize=10, fontweight='bold')

        self._render(data, title, filename, draw, figsize=(9, 9), dpi=_DPI, bbox_inches='tight')

    def plot_line_chart(self, data: pd.DataFrame, y: str, title: str, xlabel: str, ylabel: str, filename: str) -> None:
        """Line chart of `y` over the index."""
        def draw(ax: Axes) -> None:
            sns.lineplot(x=data.index, y=y, data=data, marker='o', linewidth=2, markersize=6, color='blue', ax=ax)
            ax.set_title(title, fontsize=18, fontweight='bold', pad=20)
            ax.set_xlabel(xlabel, fontsize=16, labelpad=10)
            ax.set_ylabel(ylabel, fontsize=16, labelpad=10)
            _rotate_xticks(ax)
            plt.setp(ax.get_yticklabels(), fontsize=12)
            ax.grid(True, linestyle='--', alpha=0.7)

        self._render(data, title, filename, draw, figsize=(14, 7))

    def plot_stacked_bar_chart(self, data: pd.DataFrame, title: str, xlabel: str, ylabel: str, filename: str) -> None:
        """Stacked bar chart: one bar per row, one segment per column."""
        def draw(ax: Axes) -> None:
            data.plot(kind='bar', stacked=True, ax=ax, color=sns.color_palette('Set2', n_colors=len(data.columns)))
            ax.set_title(title, fontsize=16, fontweight='bold')
            ax.set_xlabel(xlabel, fontsize=14)
            ax.set_ylabel(ylabel, fontsize=14)
            _rotate_xticks(ax)
            ax.grid(axis='y', linestyle='--', alpha=0.7)

        self._render(data, title, filename, draw, figsize=(12, 6))

    def plot_horizontal_bar(self, data: pd.DataFrame, x: str, title: str, xlabel: str, ylabel: str, filename: str) -> None:
        """Horizontal bar chart of `x` per index category, with value labels."""
        def draw(ax: Axes) -> None:
            categories = data.index.unique()
            palette = dict(zip(categories, sns.color_palette('viridis', n_colors=len(categories))))
            sns.barplot(x=x, y=data.index, data=data, hue=data.index, dodge=False, palette=palette, errorbar=None, ax=ax)
            ax.set_title(title, pad=20)
            ax.set_xlabel(xlabel, fontsize=16)
            ax.set_ylabel(ylabel, fontsize=16)
            ax.tick_params(labelsize=14)
            ax.grid(axis='x', linestyle='--', alpha=0.7)
            for patch in ax.patches:
                width = patch.get_width()
                ax.text(width + 0.01 * width, patch.get_y() + patch.get_height() / 2, f'{width:.0f}',
                        ha='left', va='center', fontsize=12)

        self._render(data, title, filename, draw, figsize=(20, 14), dpi=_DPI, bbox_inches='tight',
                     style={'axes.titlesize': 20})

    def _render(self, data: pd.DataFrame, title: str, filename: str, draw: Callable[[Axes], None],
                figsize: tuple[float, float], dpi: float | None = None, bbox_inches: str | None = None,
                style: dict | None = None) -> None:
        """Draw with the shared style and save; the figure is always closed."""
        # seaborn and pandas raise on empty data
        if data is None or data.empty:
            logging.warning(f"Nessun dato disponibile per il grafico '{title}': grafico non generato.")
            return

        with plt.rc_context({**_BASE_STYLE, **(style or {})}):
            fig, ax = plt.subplots(figsize=figsize, dpi=dpi)
            try:
                draw(ax)
                fig.tight_layout()
                self._save(fig, title, filename, bbox_inches)
            finally:
                plt.close(fig)

    @staticmethod
    def _save(fig: Figure, title: str, filename: str, bbox_inches: str | None) -> None:
        """Save the figure, creating its directory if needed."""
        directory = os.path.dirname(filename)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fig.savefig(filename, dpi=_DPI, bbox_inches=bbox_inches)
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
