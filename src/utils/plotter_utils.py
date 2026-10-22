from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pandas as pd

from db.database import DatabaseType
from utils.graph_plotter import GraphPlotter

if TYPE_CHECKING:
    from dao.certificate_dao import CertificateDAO

# Admin: Anuar Elio Magliari
# Politecnico di Torino

_ALL_TYPES = frozenset(DatabaseType)
_LEAF = frozenset({DatabaseType.LEAF})
_LEAF_AND_ROOT = frozenset({DatabaseType.LEAF, DatabaseType.ROOT})


@dataclass(frozen=True)
class _Chart:
    """Declarative chart spec: data source, kind, output file and labels."""
    query: str                              # CertificateDAO get_* method returning the data
    kind: str                               # 'bar', 'pie', 'line', 'hbar' (horizontal bars) or 'stacked'
    name: str                               # PNG file name, without extension
    title: str
    index: str = ''                         # category column (DataFrame index)
    value: str = ''                         # value column
    xlabel: str = ''
    ylabel: str = ''
    types: frozenset[DatabaseType] = _ALL_TYPES     # certificate types the chart is generated for

    def frame(self, result: dict) -> pd.DataFrame:
        """Convert the DAO result into the DataFrame to plot."""
        if self.kind == 'stacked':
            # {algorithm: {length: count}} -> rows = lengths, columns = algorithms (missing combinations = 0)
            return pd.DataFrame.from_dict(result, orient='index').fillna(0).astype(int).transpose()
        return pd.DataFrame(list(result.items()), columns=[self.index, self.value]).set_index(self.index)

    def render(self, plotter: GraphPlotter, data: pd.DataFrame, filename: str) -> None:
        """Draw the chart with the GraphPlotter method matching `kind`."""
        if self.kind == 'pie':
            plotter.plot_pie_chart(data, self.value, self.title, filename)
        elif self.kind == 'stacked':
            plotter.plot_stacked_bar_chart(data, self.title, self.xlabel, self.ylabel, filename)
        else:
            plot = {'bar': plotter.plot_bar_chart, 'line': plotter.plot_line_chart,
                    'hbar': plotter.plot_horizontal_bar}[self.kind]
            plot(data, self.value, self.title, self.xlabel, self.ylabel, filename)


_N_CERTS = 'Number of Certificates'

# In generation order: charts for every type, then leaf only, then leaf and root
_CHARTS = (
    _Chart('get_issuer_certificate_count', 'bar', 'issuer_certificates_count', 'Issuance of Certificates by Issuers',
           'Issuer', 'Certificate Count', 'Issuers', _N_CERTS),
    _Chart('get_certificate_version_distribution', 'bar', 'certificate_version_distribution',
           'Distribution of Certificate Versions', 'Version', 'Count', 'Versions', _N_CERTS),
    _Chart('get_count_critical_non_critical_extensions', 'pie', 'count_critical_non_critical_extensions',
           'Critical vs Non-Critical Extensions of the AIA', 'Flag', 'Count'),
    _Chart('get_certificates_per_country', 'pie', 'certificates_per_country',
           'Number of Certificates Issued in Different Countries', 'Country', 'Certificate Count'),
    _Chart('get_certificate_expiration_trend', 'line', 'certificate_expiration_trend',
           'Maturity Trends of the Certificates', 'Month', 'Certificate Count', 'Months', _N_CERTS),
    _Chart('get_validity_duration_distribution', 'bar', 'validity_duration_distribution',
           'Distribution of Validity Duration', 'Validity Length', 'Certificate Count', 'Duration (years)', _N_CERTS),
    _Chart('get_signature_algorithm_distribution', 'bar', 'signature_algorithm_distribution', 'Signature Algorithms Used',
           'Signature Algorithm', 'Count', 'Signature Algorithm', _N_CERTS),
    _Chart('get_key_algorithm_length_distribution', 'stacked', 'key_algorithm_length_distribution',
           'Distribution of Key and Length Algorithms', xlabel='Key Length', ylabel=_N_CERTS),
    _Chart('get_key_usage_distribution', 'hbar', 'key_usage_distribution', 'Key Usage in Extensions',
           'Key Usage', 'Count', _N_CERTS, 'Key Usage Numbers'),
    _Chart('get_critical_vs_non_critical_key_usage', 'bar', 'critical_vs_non_critical_key_usage',
           'Critical vs Non-Critical Key Usage in Extensions', 'Flag', 'Count', 'Flag', _N_CERTS),
    _Chart('get_extended_key_usage_distribution', 'hbar', 'extended_key_usage_distribution',
           'Extended Key Usage in Extensions', 'Extendend Key Usage', 'Count', _N_CERTS, 'Extendend Key Usage Numbers'),
    _Chart('get_critical_vs_non_critical_extended_key_usage', 'bar', 'critical_vs_non_critical_extended_key_usage',
           'Critical vs Non-Critical Extended Key Usage in Extensions', 'Flag', 'Count', 'Flag', _N_CERTS),
    _Chart('get_critical_vs_non_critical_san_extensions', 'bar', 'critical_vs_non_critical_san_extensions',
           'Critical vs Non-Critical Extensions of Subject Alternative Names', 'Flag', 'Count', 'Flag', _N_CERTS),
    _Chart('get_critical_vs_non_critical_cp_policies', 'bar', 'critical_vs_non_critical_cp_policies',
           'Critical vs Non-Critical Extensions of Certificate Policies', 'Flag', 'Count', 'Flag', _N_CERTS),
    _Chart('get_validation_level_distribution', 'bar', 'validation_level_distribution',
           'Distribution of the Validation Level of Certificates', 'Validation', 'Count', 'Validation Levels', _N_CERTS),
    _Chart('get_basic_constraints_distribution', 'bar', 'basic_constraints_distribution',
           'Distribution of Basic Constraints in Extensions', 'Flag', 'Count', 'Flag', _N_CERTS),
    _Chart('get_critical_vs_non_critical_crl_distribution', 'pie', 'critical_vs_non_critical_crl_distribution',
           'Critical vs Non-Critical Extensions of CRL Distribution', 'Flag', 'Count'),
    _Chart('get_ocsp_status_distribution', 'bar', 'ocsp_status_distribution', 'OCSP Status of Certificates',
           'OCSP Status', 'Count', 'OCSP Status', _N_CERTS),
    # Leaf only
    _Chart('get_status_analysis', 'bar', 'status_analysis', 'Analysis Status Certificates',
           'Status', 'Count', 'Status', _N_CERTS, _LEAF),
    _Chart('get_self_signed_vs_ca_signed', 'pie', 'self_signed_vs_ca_signed', 'Self-Signed vs CA-Signed Certificates',
           'Flag', 'Count', types=_LEAF),
    _Chart('get_top_sct_logs', 'bar', 'top_sct_logs', 'Top SCT Logs',
           'Log Name', 'Certificate Count', 'Logs Name', _N_CERTS, _LEAF),
    _Chart('get_top_sct_log_operators', 'pie', 'top_sct_log_operators', 'Top SCT Log Operators',
           'Log Operator', 'Certificate Count', types=_LEAF),
    _Chart('get_signed_certificate_timestamp_trend', 'line', 'sct_trend',
           'Trend of Signed Certificate Timestamps (SCT) by Month and Year', 'Date', 'Certificate Count', 'Date', _N_CERTS,
           _LEAF),
    _Chart('get_sct_count_per_certificate', 'bar', 'sct_count_per_certificate',
           'Number of Signed Certificate Timestamps (SCT) per Certificate', 'SCT Count', 'Certificate Count', 'SCT Count',
           _N_CERTS, _LEAF),
    # Leaf and root
    _Chart('get_signature_validity_distribution', 'bar', 'signature_validity_distribution',
           'Validity of Certificate Signatures', 'Signature Validity', 'Count', 'Signature Validity', _N_CERTS,
           _LEAF_AND_ROOT),
)


def _reset_directory(path: str | os.PathLike) -> None:
    if os.path.exists(path):
        shutil.rmtree(path)
        logging.info(f"La cartella '{path}' è stata rimossa.")
    os.makedirs(path)
    logging.info(f"La cartella '{path}' è stata creata.")


def _generate(chart: _Chart, dao: CertificateDAO, plotter: GraphPlotter, plots_path: str | os.PathLike) -> None:
    """Generate one chart; errors are logged so the remaining charts still run."""
    logging.info(f"Generazione grafico '{chart.title}'")
    try:
        data = chart.frame(getattr(dao, chart.query)())
        chart.render(plotter, data, os.path.abspath(os.path.join(plots_path, f'{chart.name}.png')))
    except Exception as e:
        logging.error(f"Errore nella generazione del grafico '{chart.title}': {e}")


def plot_certificates(dao: CertificateDAO, plots_path: str | os.PathLike, is_verbose: bool) -> None:
    """Regenerate in plots_path every chart applicable to the DAO's certificate type."""
    plotter = GraphPlotter(is_verbose)
    _reset_directory(plots_path)
    for chart in _CHARTS:
        if dao.certificate_type in chart.types:
            _generate(chart, dao, plotter, plots_path)
    certificate_type = dao.certificate_type.value.capitalize()
    logging.info(f"Generazione dei grafici per l'analisi dei certificati {certificate_type} completata.")
