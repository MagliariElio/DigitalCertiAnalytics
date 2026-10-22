from __future__ import annotations

import argparse
import json
import logging
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import pyfiglet
from rich.console import Console

from dao.certificate_dao import CertificateDAO
from db.database import Database, DatabaseType
from utils.chain_utils import find_root_certificate, intermediate_certificates, validate_leaf_certificate_chains
from utils.utils import ArgparseFormatter, progress_bar, setup_logging

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Paths resolved from the package, independent of the working directory
SRC_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = SRC_DIR / "analysis"
SCHEMA_PATH = SRC_DIR / "db" / "schema_db.sql"
CERTIFICATES_FILE = SRC_DIR.parent / "res" / "certs_polito.json"     # zgrab2 output
LOG_LIST_FILE = SRC_DIR.parent / "res" / "log_list.json"             # SCT log list

# Read buffer for the zgrab2 JSON file (~80 GB)
_READ_BUFFER_SIZE = 1 << 20

# Boolean CLI flags: (names, help text)
_CLI_FLAGS = (
    (('--delete_all_db',), 'Se presenti, elimina tutti i database prima di iniziare.'),
    (('--delete_leaf_db',), 'Se presente, elimina il database leaf prima di iniziare.'),
    (('--delete_intermediate_db',), 'Se presente, elimina il database intermediate prima di iniziare.'),
    (('--delete_root_db',), 'Se presente, elimina il database root prima di iniziare.\n\n'),

    (('--leaf_analysis',), 'Rimuove il database esistente e analizza i certificati leaf nel file JSON generato da zgrab2.'),
    (('--leaf_ocsp_analysis',), 'Esegue l\'analisi OCSP per i certificati leaf presenti nel database.'),
    (('--leaf_zlint_check',), 'Esegue l\'analisi Zlint sui certificati leaf per verificare eventuali vulnerabilità e '
                              'configurazioni errate secondo determinati requisiti ufficiali.'),
    (('--leaf_chain_validation',), 'Esegue la validazione della catena dei certificati leaf per verificare la conformità '
                                   'e l\'affidabilità della catena di trust.\n\n'),

    (('--intermediate_analysis',), 'Rimuove il database esistente e analizza ed analizza i certificati intermediate '
                                   'nel file JSON generato da zgrab2.'),
    (('--intermediate_ocsp_analysis',), 'Esegue l\'analisi OCSP per i certificati intermediate presenti nel database.'),
    (('--intermediate_zlint_check',), 'Esegue l\'analisi Zlint sui certificati intermediate per verificare eventuali '
                                      'vulnerabilità e configurazioni errate secondo determinati requisiti ufficiali.\n\n'),

    (('--root_analysis',), 'Rimuove il database esistente e analizza i certificati root nel file JSON generato da zgrab2.'),
    (('--root_ocsp_analysis',), 'Esegue l\'analisi OCSP per i certificati root presenti nel database.\n\n'),

    (('--plot_all_results',), 'Genera e visualizza i grafici per tutti i dati analizzati sui certificati.'),
    (('--plot_leaf_results',), 'Genera e visualizza i grafici per i risultati dell\'analisi dei certificati leaf.'),
    (('--plot_intermediate_results',), 'Genera e visualizza i grafici per i risultati dell\'analisi dei certificati '
                                       'intermedi.'),
    (('--plot_root_results',), 'Genera e visualizza i grafici per i risultati dell\'analisi dei certificati root.\n\n'),
    (('-v', '--verbose'), 'Attiva la modalità verbose per una registrazione dettagliata.'),
)


@dataclass(frozen=True)
class StageConfig:
    """Stages requested on the command line for one certificate type."""
    db_type: DatabaseType
    analysis: bool = False
    ocsp: bool = False
    zlint: bool = False
    chain_validation: bool = False
    plot: bool = False
    delete: bool = False

    @property
    def name(self) -> str:
        """'leaf', 'intermediate' or 'root'."""
        return self.db_type.value

    @property
    def label(self) -> str:
        """Capitalized name used in log messages."""
        return self.name.capitalize()

    @property
    def results_dir(self) -> Path:
        """Holds the database, the OCSP CSV files and the plots."""
        return RESULTS_DIR / self.name

    @property
    def db_path(self) -> Path:
        return self.results_dir / f"{self.name}_certificates.db"

    @property
    def has_stages(self) -> bool:
        """True if any stage working on an already populated database is requested."""
        return self.ocsp or self.zlint or self.chain_validation or self.plot

    @property
    def delete_only(self) -> bool:
        """True if the database is deleted without a new analysis."""
        return self.delete and not self.analysis

    @property
    def needs_database(self) -> bool:
        """True if the database must be opened for the analysis or the other stages."""
        return not self.delete_only and (self.analysis or self.has_stages)


@dataclass(frozen=True)
class _Target:
    """Open database of one certificate type and its DAO."""
    config: StageConfig
    database: Database
    dao: CertificateDAO


_RowInserter = Callable[[CertificateDAO, dict, dict | None, list[dict]], None]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='python -m analysis.main',
        description='Strumento per l\'analisi dei certificati digitali.',
        epilog='Utilizza le opzioni disponibili per eseguire diverse analisi sui certificati e generare report visivi. '
               'Usa -v per attivare la modalità verbose per ulteriori dettagli.',
        add_help=False,
        formatter_class=ArgparseFormatter
    )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Mostra le opzioni disponibili per l\'analisi dei certificati digitali '
                             'e la generazione di grafici.\n\n')
    for names, help_text in _CLI_FLAGS:
        parser.add_argument(*names, action='store_true', help=help_text)
    return parser


def _build_stage_configs(args: argparse.Namespace) -> list[StageConfig]:
    """Build one StageConfig per certificate type; analysis implies deleting the database."""
    configs = []
    for db_type in DatabaseType:
        name = db_type.value
        analysis = getattr(args, f"{name}_analysis")
        configs.append(StageConfig(
            db_type=db_type,
            analysis=analysis,
            ocsp=getattr(args, f"{name}_ocsp_analysis"),
            # Zlint and chain validation flags exist only for some types
            zlint=getattr(args, f"{name}_zlint_check", False),
            chain_validation=getattr(args, f"{name}_chain_validation", False),
            plot=getattr(args, f"plot_{name}_results") or args.plot_all_results,
            delete=getattr(args, f"delete_{name}_db") or analysis or args.delete_all_db,
        ))
    return configs


def _print_banner() -> None:
    """Clear the console and print the application logo."""
    Console().clear()
    print("\n")
    print(pyfiglet.figlet_format("        DigitalCertiAnalytics", font="standard", width=150))
    print("\n")


def _check_input_files(configs: list[StageConfig]) -> bool:
    """Check that the input files exist when at least one analysis is requested."""
    if not any(config.analysis for config in configs):
        return True

    if not CERTIFICATES_FILE.exists():
        logging.error(
            f"Il file '{CERTIFICATES_FILE}' non esiste. Oppure il nome del file output non coincide! "
            "Si prega di consultare il README per istruzioni su come generare questo file utilizzando il programma Zgrab2."
        )
        return False

    if not LOG_LIST_FILE.exists():
        logging.error(
            f"Il file {LOG_LIST_FILE} non esiste. Puoi scaricarlo direttamente da questo link: "
            "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
        )
        return False
    return True


def _delete_database(config: StageConfig) -> None:
    """Delete the database without re-analysing it; the other requested stages are skipped."""
    if config.db_path.exists():
        config.db_path.unlink()
        logging.info("Database '%s' eliminato con successo.", config.db_path)

    if config.has_stages:
        logging.warning(f"Il database {config.name} è stato eliminato senza eseguire --{config.name}_analysis: "
                        f"le altre analisi sui certificati '{config.label}' non vengono eseguite.")


def _prepare_databases(configs: list[StageConfig]) -> bool:
    """Handle delete-only databases and check that the databases needed by the other stages exist."""
    for config in configs:
        if config.delete_only:
            _delete_database(config)
        elif config.has_stages and not config.analysis and not config.db_path.exists():
            logging.error(
                "Il database %s non è stato trovato nel percorso '%s'. "
                "Per eseguire la seguente analisi è necessario eseguire prima l'analisi "
                "dei certificati dal file JSON per creare il database. "
                "In alternativa, assicurati di posizionare il database nel percorso corretto.",
                config.name, config.db_path
            )
            return False
    return True


def _load_log_list() -> dict | None:
    """Read the SCT log list; on error return None and the logs are not inserted."""
    try:
        with open(LOG_LIST_FILE, encoding='utf-8') as log_list_reader:
            return json.load(log_list_reader)
    except json.JSONDecodeError as e:
        logging.error(f"Errore nel parsing del file JSON: {e}")
    except (OSError, ValueError) as e:
        logging.error(f"Errore nell'apertura del file: {e}")
    return None


def _open_database(config: StageConfig, log_list: dict | None, stack: ExitStack) -> _Target:
    """Open the database (recreated if analysed) and insert the SCT operators and logs."""
    database = Database(db_path=config.db_path, schema_path=SCHEMA_PATH, db_type=config.db_type)
    stack.callback(database.close)
    database.connect(delete_database=config.analysis)
    dao = CertificateDAO(database.conn, config.db_type)

    if config.analysis and log_list is not None:
        with database.transaction():
            dao.insert_sct_logs(log_list)
        logging.info("SCT Operators e SCT Logs memorizzati con successo.")
    return _Target(config, database, dao)


def _open_databases(configs: list[StageConfig], stack: ExitStack) -> list[_Target]:
    """Open the needed databases; the stack closes them even on error or interrupt."""
    log_list = _load_log_list() if any(config.analysis for config in configs) else None
    return [_open_database(config, log_list, stack) for config in configs if config.needs_database]


def _server_certificates(row: dict) -> tuple[dict | None, list[dict]]:
    """Server certificate and chain of a zgrab2 row; (None, []) if the scan failed."""
    tls = row.get("data", {}).get("tls", {})
    if tls.get("status", "") != "success":
        return None, []

    certificates = tls.get("result", {}).get("handshake_log", {}).get("server_certificates", {})
    certificate = certificates.get("certificate", {})
    if certificate is None:
        # None means a failed scan to the inserters: a null certificate makes the row invalid instead
        raise ValueError("certificato del server nullo")
    return certificate, certificates.get("chain", [])


def _insert_leaf(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert the server certificate, or an error row if the scan failed."""
    if certificate is None:
        dao.insert_error_row(row)
    else:
        dao.process_insert_certificate(row, certificate, chain, 0)


def _insert_intermediates(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert every intermediate of the chain with its distance from the leaf."""
    if certificate is None:
        return

    for emitted_up_to, (intermediate, remaining_chain) in enumerate(intermediate_certificates(chain, certificate), start=1):
        dao.process_insert_certificate(row, intermediate, remaining_chain, emitted_up_to)


def _insert_root(dao: CertificateDAO, row: dict, certificate: dict | None, chain: list[dict]) -> None:
    """Insert the root certificate of the chain, if any."""
    if certificate is None:
        return

    root, emitted_up_to = find_root_certificate(chain, certificate)
    if root is not None:
        dao.process_insert_certificate(row, root, [], emitted_up_to)


_ROW_INSERTERS: dict[DatabaseType, _RowInserter] = {
    DatabaseType.LEAF: _insert_leaf,
    DatabaseType.INTERMEDIATE: _insert_intermediates,
    DatabaseType.ROOT: _insert_root,
}


def _ingest_line(line_number: int, line: bytes, targets: list[_Target]) -> None:
    """Insert one JSON line into every database, each in its own transaction."""
    try:
        row = json.loads(line)
        certificate, chain = _server_certificates(row)
    except json.JSONDecodeError:
        logging.error(f"Errore nel parsing della riga {line_number}: {line.decode('utf-8', errors='replace').strip()}")
        return
    except Exception as e:
        logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
        return

    for target in targets:
        try:
            with target.database.row_transaction():
                _ROW_INSERTERS[target.config.db_type](target.dao, row, certificate, chain)
        except Exception as e:
            logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")


def _read_certificates_file(targets: list[_Target]) -> None:
    """Read the zgrab2 JSON file once, inserting each line into all target databases."""
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(target.database.bulk_insert_mode())

        reader = stack.enter_context(open(CERTIFICATES_FILE, 'rb', buffering=_READ_BUFFER_SIZE))
        pbar = stack.enter_context(progress_bar(
            total=CERTIFICATES_FILE.stat().st_size, description=" 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]",
            colour="magenta", unit="B", unit_scale=True, unit_divisor=1024
        ))

        for line_number, line in enumerate(reader, start=1):
            pbar.update(len(line))
            _ingest_line(line_number, line, targets)


def _analyse_certificates(targets: list[_Target]) -> None:
    """Populate the databases to analyse in a single pass over the JSON file, then drop unneeded data."""
    analysed = [target for target in targets if target.config.analysis]
    if not analysed:
        return

    for target in analysed:
        logging.info(f"Inizio analisi certificati '{target.config.label}'.")

    _read_certificates_file(analysed)

    for target in analysed:
        logging.info(f"Analisi dei certificati '{target.config.label}' completata con successo.")
        target.database.finalize_analysis()


@contextmanager
def _stage(start_message: str, end_message: str | None = None) -> Iterator[None]:
    """Log the start and end of a stage; an error stops only the current stage, not the following ones."""
    logging.info(start_message)
    try:
        yield
    except Exception as e:
        logging.error(f"Errore durante l'esecuzione della fase: {e}")
        return

    if end_message:
        logging.info(end_message)


async def _run_stages(target: _Target, is_verbose: bool) -> None:
    """Run the requested stages: OCSP, Zlint, chain validation and plots."""
    config, database, dao = target.config, target.database, target.dao

    # Stage modules are imported lazily: pandas/matplotlib/seaborn and pymongo slow down startup
    if config.ocsp:
        from utils.ocsp_utils import run_ocsp_analysis
        with _stage(f"Inizio dell'analisi OCSP per i certificati '{config.label}'."):
            await run_ocsp_analysis(database, config.results_dir)

    if config.zlint:
        from utils.zlint_utils import run_zlint_check
        with _stage(f"Inizio dell'analisi dei certificati '{config.label}' con Zlint.", "Controllo ZLint completato."):
            run_zlint_check(dao)

    if config.chain_validation:
        with _stage(f"Inizio del controllo della validità delle catene dei certificati '{config.label}' con 'sslyze'.",
                    "Controllo Validità completato."):
            validate_leaf_certificate_chains(dao, database)

    if config.plot:
        from dao.statistics_dao import StatisticsDAO
        from utils.plotter_utils import plot_certificates
        with _stage(f"Inizio generazione grafici per certificati '{config.label}'."):
            database.prepare_for_plots()
            plot_certificates(StatisticsDAO(database.conn, config.db_type), config.results_dir / "plots", is_verbose)


async def certificates_analysis_main() -> None:
    """Parse the command line and run the requested analyses on leaf, intermediate and root certificates."""
    _print_banner()
    args = _build_parser().parse_args()

    setup_logging(args.verbose)
    logging.info("Inizio dell'applicazione.")

    configs = _build_stage_configs(args)
    for config in configs:
        config.results_dir.mkdir(parents=True, exist_ok=True)

    if not (_check_input_files(configs) and _prepare_databases(configs)):
        return

    with ExitStack() as stack:
        targets = _open_databases(configs, stack)
        _analyse_certificates(targets)

        for target in targets:
            await _run_stages(target, args.verbose)
            target.database.close()

    logging.info("Applicazione terminata correttamente.\n")
