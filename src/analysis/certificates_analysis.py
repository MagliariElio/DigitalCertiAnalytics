import json, csv
import aiosqlite, asyncio
import logging
import argparse
import pyfiglet
import os, shutil, signal
from tqdm.rich import tqdm
from rich.console import Console
from db.database import Database, DatabaseType
from dao.certificate_dao import CertificateDAO
from utils.utils import find_next_intermediate_certificate, count_certificates_to_root, setup_logging, ArgparseFormatter 
from utils.utils import update_certificates_ocsp_status_db, save_certificates_ocsp_status_file, check_certificate_chain
from utils.plotter_utils import plot_general_certificates_analysis, plot_leaf_certificates_analysis, plot_leaf_and_root_certificates_analysis
from utils.graph_plotter import GraphPlotter
from utils.zlint_utils import run_zlint_check

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

async def close_connections():
    """Funzione per gestire la chiusura delle connessioni ai database."""
    global pbar_ocsp_check, pbar_zlint
    
    logging.info("Inizio chiusura delle connessioni ai database...")
    
    if 'leaf_database' in globals():
        leaf_database.close()
        
    if 'intermediate_database' in globals():
        intermediate_database.close()
        
    if 'root_database' in globals():
        root_database.close()
    
    if 'pbar_leaf' in globals():
        pbar_leaf.close()
    
    if 'pbar_intermediate' in globals():
        pbar_intermediate.close()
    
    if 'pbar_root' in globals():
        pbar_root.close()
    
    if 'pbar_zlint' in globals():
        pbar_zlint.close()
    
    if 'pbar_leaf_chain_check' in globals():
        pbar_leaf_chain_check.close()
    
    if 'pbar_ocsp_check' in globals():
        pbar_ocsp_check.close()
    
    if 'plotter' in globals():
        plotter.close_all_plots()
        
    logging.info("Tutte le connessioni ai database sono state chiuse.")
    return

async def handle_exit_signal(loop, signal=None):
    """Cancella i task e chiude il loop in modo ordinato."""
    if signal:
        logging.info(f"Ricevuto segnale di interruzione ({signal.name}). Inizio della procedura di chiusura...")

    tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task(loop)]
    for task in tasks:
        task.cancel()

    # Attende la cancellazione di tutti i task
    await asyncio.gather(*tasks, return_exceptions=True)
    
    await close_connections()
    logging.info("Uscita dell'applicazione in corso...\n")

    loop.stop()
    return

def setup_signal_handlers(loop):
    """Configura i gestori dei segnali per gestire SIGINT."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(handle_exit_signal(loop, signal=s)))
    return

def leaf_certificates_analysis(certificates_file, dao: CertificateDAO, database: Database, total_lines:int=0):
    """Analizza e inserisce i certificati leaf dal file JSON nel database."""
    global pbar_leaf
    
    with open(certificates_file, 'r') as certificates_reader:
        # Inizializza la barra di caricamento
        tqdm.write("")
        pbar_leaf = tqdm(total=total_lines, desc=" 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]", unit="cert.", 
                    colour="magenta", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")
        try:
            for line_number, row in enumerate(certificates_reader, start=1):
                try:
                    json_row = json.loads(row)
                    status = json_row.get("data", {}).get("tls", {}).get("status", "")

                    # Aggiorna la barra di caricamento
                    pbar_leaf.update(1)

                    with database.transaction():
                        if status == "success":
                            dao.process_insert_certificate(json_row, database.db_type, 0)
                        else:
                            dao.insert_error_row(json_row)
                            
                except json.JSONDecodeError:
                    logging.error(f"Errore nel parsing della riga {line_number}: {row.strip()}")
                except Exception as e:
                    logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
        except KeyboardInterrupt:
            logging.info(f"Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
        finally:
            pbar_leaf.close()   # Chiusura barra di progresso
    return

def intermediate_certificates_analysis(certificates_file, dao: CertificateDAO, database: Database, total_lines:int=0):
    """Analizza e inserisce i certificati intermediate dal file JSON nel database."""
    global pbar_intermediate
    
    with open(certificates_file, 'r') as certificates_reader:
        # Inizializza la barra di caricamento
        tqdm.write("")
        pbar_intermediate = tqdm(total=total_lines, desc=" 📜  [green bold]Righe elaborate[/green bold]", unit="rows", 
                    colour="green", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")

        try:
            for line_number, row in enumerate(certificates_reader, start=1):
                try:
                    json_row = json.loads(row)
                    status = json_row.get("data", {}).get("tls", {}).get("status", "")

                    # Aggiorna la barra di caricamento
                    pbar_intermediate.update(1)
                    
                    with database.transaction():
                        if status == "success":
                            handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                            server_certificates = handshake_log.get("server_certificates", {})
                            chain: list = server_certificates.get("chain", [])
                            current_cert = server_certificates.get("certificate", {})
                            certificates_emitted_up_to = 0          # Numero di certificati presenti tra il certificato leaf fino all'intermediate
                            
                            while True:
                                # Estrae il certificato intermedio dalla catena. 
                                # Restituisce None se l'issuer del certificato corrente non è presente o se è un certificato root.
                                intermediate_cert = find_next_intermediate_certificate(chain, current_cert)
                                            
                                # Se non è stato trovato alcun certificato intermedio, interrompe il ciclo.
                                if(intermediate_cert is None):
                                    break
                                
                                # Aggiorna il certificato corrente per la prossima iterazione
                                current_cert = intermediate_cert
                                
                                raw_intermediate = intermediate_cert.get("raw", {})
                                parsed_intermediate = intermediate_cert.get("parsed", {})
                            
                                try:
                                    # Rimuove il certificato intermedio estratto dalla catena
                                    serial_number_intermediate = intermediate_cert.get("parsed", {}).get("serial_number", "")
                                    chain = list(filter(lambda cert: cert.get("parsed", {}).get("serial_number", "") != serial_number_intermediate, chain))
                                except ValueError:
                                    pass  # Ignora l'errore se il certificato non è presente nella catena
                            
                                # Aggiorna i dati del certificato nel server_certificates
                                server_certificates["certificate"]["raw"] = raw_intermediate
                                server_certificates["certificate"]["parsed"] = parsed_intermediate
                                server_certificates["chain"] = chain
                                certificates_emitted_up_to += 1
                                
                                # Inizia l'analisi del certificato intermediate
                                dao.process_insert_certificate(json_row, database.db_type, certificates_emitted_up_to)

                except json.JSONDecodeError:
                    logging.error(f"Errore nel parsing della riga {line_number}: {row.strip()}")
                except Exception as e:
                    logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
        except KeyboardInterrupt:
            logging.info(f"Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
        finally:
            pbar_intermediate.close()   # Chiusura barra di progresso
    return

def root_certificates_analysis(certificates_file, dao: CertificateDAO, database: Database, total_lines: int=0):
    """Analizza e inserisce i certificati root dal file JSON nel database."""
    global pbar_root
    
    with open(certificates_file, 'r') as certificates_reader:
        # Inizializza la barra di caricamento
        tqdm.write("")
        pbar_root = tqdm(total=total_lines, desc=" 🛠️  [blue bold]Elaborazione Certificati[/blue bold]", unit="cert.", 
                    colour="blue", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")

        # TODO: da rimuovere
        # for _ in range(800000): # 800000
        #   next(certificates_reader)
        
        try:
            for line_number, row in enumerate(certificates_reader, start=1):
                try:
                    json_row = json.loads(row)
                    status = json_row.get("data", {}).get("tls", {}).get("status", "")

                    # Aggiorna la barra di caricamento
                    pbar_root.update(1)
                    
                    with database.transaction():
                        if status == "success":
                            handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                            server_certificates = handshake_log.get("server_certificates", {})
                            chain:list = server_certificates.get("chain", [])
                            current_cert = server_certificates.get("certificate", {})
                                                    
                            # Estrae il certificato intermedio dalla catena. 
                            # Restituisce None se l'issuer del certificato corrente non è presente o se è un certificato root.
                            root_cert, certificates_emitted_up_to = count_certificates_to_root(chain, current_cert)
                                                    
                            # Se non è stato trovato alcun certificato root, passa alla prossima riga nel file JSON.
                            if(root_cert is None):
                                continue
                            
                            raw_root = root_cert.get("raw", {})
                            parsed_root = root_cert.get("parsed", {})
                        
                            # Imposta la catena ad una lista vuota essendo il certificato root
                            chain = []
                        
                            # Aggiorna i dati del certificato nel server_certificates
                            server_certificates["certificate"]["raw"] = raw_root
                            server_certificates["certificate"]["parsed"] = parsed_root
                            server_certificates["chain"] = chain

                            # Inizia l'analisi del certificato root
                            dao.process_insert_certificate(json_row, database.db_type, certificates_emitted_up_to)

                except json.JSONDecodeError:
                    logging.error(f"Errore nel parsing della riga {line_number}: {row.strip()}")
                except Exception as e:
                    logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
        
        except KeyboardInterrupt:
            logging.info(f"Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
        finally:
            pbar_root.close()   # Chiusura barra di progresso
    return

async def process_ocsp_check_status_request(dao: CertificateDAO, database: Database, main_path):
    """Elabora la richiesta per controllare lo stato OCSP di tutti i certificati nel DAO."""
    try:
        ocsp_temp_file = os.path.abspath(f'{main_path}/ocsp_check_results_temp.csv')
        ocsp_backup_file = os.path.abspath(f'{main_path}/ocsp_certificates_backup.csv')
        
        # Rimuove gli indici non necessari che rallentano le operazioni di aggiornamento del database
        database.drop_indexes_for_table()
        
        async with aiosqlite.connect(database.db_path) as db:
            # Se il file esiste e ha delle righe, salva questi dati nel db e lo cancella
            if os.path.exists(ocsp_temp_file) and os.path.getsize(ocsp_temp_file) > 0:
                await update_certificates_ocsp_status_db(db, ocsp_temp_file)
            
            if(os.path.exists(ocsp_backup_file)):
                await update_certificates_ocsp_status_db(db, ocsp_backup_file, True)
             
            # Esegue l'ocsp check prendendo i dati dal db e scrive nel file temporaneo
            with open(ocsp_temp_file, mode="a", newline="") as ocsp_temp_file_csv:
                ocsp_temp_file_writer = csv.writer(ocsp_temp_file_csv)
                await dao.check_ocsp_status_for_certificates(database.db_type, db, ocsp_temp_file_writer)
            
            # Esegue il salvataggio dei dati presenti nel file al db
            await update_certificates_ocsp_status_db(db, ocsp_temp_file)
            
            tqdm.write("")
            logging.info(f"Salvataggio dei dati dello stato OCSP come backup eseguito con successo: 'file://{ocsp_backup_file}'")
            
            # Scrive su un file CSV i lo status OCSP relativi ai certificati come backup
            await save_certificates_ocsp_status_file(db, ocsp_backup_file)
            
            logging.info("Analisi OCSP per i certificati completata.")
    except asyncio.CancelledError:
        logging.info("Elaborazione della richiesta di controllo OCSP cancellata.")
    except Exception as e:
        logging.error(f"Errore nell'elaborazione della richiesta di controllo OCSP: {e}")
        
def process_insert_sct_logs(log_list_path, dao: CertificateDAO, database: Database):
    """Elabora e inserisce i log SCT nel database a partire da un file JSON."""
    
    with open(log_list_path, 'r') as log_list_reader:
        try:
            data = json.load(log_list_reader)
            operators = data.get("operators", [])
        except json.JSONDecodeError as e:
            logging.error(f"Errore nel parsing del file JSON: {e}")
            return
        except Exception as e:
            logging.error(f"Errore nell'apertura del file: {e}")
            return
        
        for operator in operators:
            with database.transaction():
                operator_id = dao.insert_sct_log_operator(operator)
                logs = operator.get("logs", [])
                for json_log in logs:
                    dao.insert_sct_log(operator_id, json_log)
        
        # Inserimento di un operatore fantasma in caso non un log id non appartenesse all'elenco
        operator = {
            "name": "unknown",
            "email": ""
        }
        dao.insert_sct_log_operator(operator)
        logging.info("SCT Operators e SCT Logs memorizzati con successo.")

    return

def plot_leaf_certificates(dao: CertificateDAO, is_verbose: bool):
    """Genera e salva vari grafici relativi all'analisi dei certificati."""
    global plotter
    
    plots_path = 'analysis/leaf/plots'
    
    plotter = GraphPlotter()
    plotter.disable_logging(is_verbose)
    
    # Rimuovi la cartella se esiste
    if os.path.exists(plots_path):
        shutil.rmtree(plots_path)
        logging.info(f"La cartella '{plots_path}' è stata rimossa.")

    # Crea la cartella per il plot leaf
    os.makedirs(plots_path)
    logging.info(f"La cartella '{plots_path}' è stata creata.")
    
    # Generazione grafici
    plot_general_certificates_analysis(dao, plotter, plots_path)
    plot_leaf_certificates_analysis(dao, plotter, plots_path)
    plot_leaf_and_root_certificates_analysis(dao, plotter, plots_path)
    
    logging.info("Generazione dei grafici per l'analisi dei certificati Leaf completata.")
    return

def plot_intermediate_certificates(dao: CertificateDAO, is_verbose: bool):
    """Genera e salva vari grafici relativi all'analisi dei certificati."""
    global plotter
    
    plots_path = 'analysis/intermediate/plots'
    
    plotter = GraphPlotter()
    plotter.disable_logging(is_verbose)
    
    # Rimuovi la cartella se esiste
    if os.path.exists(plots_path):
        shutil.rmtree(plots_path)
        logging.info(f"La cartella '{plots_path}' è stata rimossa.")

    # Crea la cartella per il plot intermediate
    os.makedirs(plots_path)
    logging.info(f"La cartella '{plots_path}' è stata creata.")
    
    # Generazione grafici
    plot_general_certificates_analysis(dao, plotter, plots_path)
    
    logging.info("Generazione dei grafici per l'analisi dei certificati Intermediate completata.")
    return

def plot_root_certificates(dao: CertificateDAO, is_verbose: bool):
    """Genera e salva vari grafici relativi all'analisi dei certificati."""
    global plotter

    plots_path = 'analysis/root/plots'
    
    plotter = GraphPlotter()
    plotter.disable_logging(is_verbose)
    
    # Rimuovi la cartella se esiste
    if os.path.exists(plots_path):
        shutil.rmtree(plots_path)
        logging.info(f"La cartella '{plots_path}' è stata rimossa.")

    # Crea la cartella per il plot root
    os.makedirs(plots_path)
    logging.info(f"La cartella '{plots_path}' è stata creata.")
    
    # Generazione grafici
    plot_general_certificates_analysis(dao, plotter, plots_path)
    plot_leaf_and_root_certificates_analysis(dao, plotter, plots_path)
        
    logging.info("Generazione dei grafici per l'analisi dei certificati Root completata.")
    return

def start_leaf_certificate_chain_check(dao: CertificateDAO, database: Database):
    global pbar_leaf_chain_check
    
    try:
        logging.info("Inizio controllo della validità della catena sui certificati...")
        
        total_lines = dao.get_certificates_count()
        
        tqdm.write("")
        pbar_leaf_chain_check = tqdm(total=total_lines, desc=" 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]", unit="cert.", 
                    colour="magenta", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")
        
        batch_size = 5000
        offset = 0
            
        while(True):
            certificates = dao.get_leaf_domain_certificates(batch_size, offset)
            
            offset += batch_size
                
            if not certificates or len(certificates) == 0:
                break
        
            for certificate in certificates:
                # Aggiorna la barra di caricamento
                pbar_leaf_chain_check.update(1)
            
                certificate_id, leaf_domain = certificate
                signature_valid = check_certificate_chain(leaf_domain)
                with database.transaction():
                    dao.update_leaf_certificate_validity(signature_valid, certificate_id)

    except Exception as e:
        logging.error(f"Errore durante l'esecuzione della funzione start_leaf_certificate_chain_check: {str(e)}")
    except KeyboardInterrupt:
        logging.info(f"Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
    finally:
        pbar_leaf_chain_check.close()
    return
    
async def certificates_analysis_main():
    global leaf_database, intermediate_database, root_database
    
    # Pulisce la console
    console = Console()
    console.clear()
    
    # Stampa il logo dell'applicazione
    tqdm.write("\n")
    tqdm.write(pyfiglet.figlet_format("        DigitalCertiAnalytics", font="standard", width=150))
    tqdm.write("\n")

    # Configura argparse per gestire gli argomenti della riga di comando
    parser = argparse.ArgumentParser(
        prog='python -m analysis.main',
        description='Strumento per l\'analisi dei certificati digitali.',
        epilog='Utilizza le opzioni disponibili per eseguire diverse analisi sui certificati e generare report visivi. Usa -v per attivare la modalità verbose per ulteriori dettagli.',
        add_help=False,
        formatter_class=ArgparseFormatter
    )
    
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Mostra le opzioni disponibili per l\'analisi dei certificati digitali e la generazione di grafici.\n\n')

    parser.add_argument('--delete_all_db', action='store_true', help='Se presenti, elimina tutti i database prima di iniziare.')
    parser.add_argument('--delete_leaf_db', action='store_true', help='Se presente, elimina il database leaf prima di iniziare.')
    parser.add_argument('--delete_intermediate_db', action='store_true', help='Se presente, elimina il database intermediate prima di iniziare.')
    parser.add_argument('--delete_root_db', action='store_true', help='Se presente, elimina il database root prima di iniziare.\n\n')
    
    parser.add_argument('--leaf_analysis', action='store_true', help='Rimuove il database esistente e analizza i certificati leaf nel file JSON generato da zgrab2.')
    parser.add_argument('--leaf_ocsp_analysis', action='store_true', help='Esegue l\'analisi OCSP per i certificati leaf presenti nel database.')
    parser.add_argument('--leaf_zlint_check', action='store_true', help='Esegue l\'analisi Zlint sui certificati leaf per verificare eventuali vulnerabilità e configurazioni errate secondo determinati requisiti ufficiali.')
    parser.add_argument('--leaf_chain_validation', action='store_true', help='Esegue la validazione della catena dei certificati leaf per verificare la conformità e l\'affidabilità della catena di trust.\n\n')

    parser.add_argument('--intermediate_analysis', action='store_true', help='Rimuove il database esistente e analizza ed analizza i certificati intermediate nel file JSON generato da zgrab2.')
    parser.add_argument('--intermediate_ocsp_analysis', action='store_true', help='Esegue l\'analisi OCSP per i certificati intermediate presenti nel database.')
    parser.add_argument('--intermediate_zlint_check', action='store_true', help='Esegue l\'analisi Zlint sui certificati intermediate per verificare eventuali vulnerabilità e configurazioni errate secondo determinati requisiti ufficiali.\n\n')
    
    parser.add_argument('--root_analysis', action='store_true', help='Rimuove il database esistente e analizza i certificati root nel file JSON generato da zgrab2.')
    parser.add_argument('--root_ocsp_analysis', action='store_true', help='Esegue l\'analisi OCSP per i certificati root presenti nel database.\n\n')
    
    parser.add_argument('--plot_all_results', action='store_true', 
                    help='Genera e visualizza i grafici per tutti i dati analizzati sui certificati.')
    parser.add_argument('--plot_leaf_results', action='store_true', 
                    help='Genera e visualizza i grafici per i risultati dell\'analisi dei certificati leaf.')
    parser.add_argument('--plot_intermediate_results', action='store_true', 
                    help='Genera e visualizza i grafici per i risultati dell\'analisi dei certificati intermedi.')
    parser.add_argument('--plot_root_results', action='store_true', 
                    help='Genera e visualizza i grafici per i risultati dell\'analisi dei certificati root.\n\n')
    parser.add_argument('-v', '--verbose', action='store_true', 
                    help='Attiva la modalità verbose per una registrazione dettagliata.')

    # Estrai gli argomenti dalla riga di comando
    args = parser.parse_args()
    
    # Setup del logger
    setup_logging(args.verbose)
    logging.info("Inizio dell'applicazione.")

    # Imposta le cancellazioni dei database
    args.delete_leaf_db =         args.delete_leaf_db         or args.leaf_analysis         or args.delete_all_db
    args.delete_intermediate_db = args.delete_intermediate_db or args.intermediate_analysis or args.delete_all_db
    args.delete_root_db =         args.delete_root_db         or args.root_analysis         or args.delete_all_db
    
    # Imposta il plot dei risutalti    
    args.plot_leaf_results =         args.plot_leaf_results           or args.plot_all_results
    args.plot_intermediate_results = args.plot_intermediate_results   or args.plot_all_results
    args.plot_root_results =         args.plot_root_results           or args.plot_all_results
    
    # Funzione lambda per creare una cartella se non esiste
    create_directory = lambda path: os.makedirs(path) if not os.path.exists(path) else None
    
    # Definizione delle cartelle per il risultato delle analisi
    leaf_path = 'analysis/leaf'
    intermediate_path = 'analysis/intermediate'
    root_path = 'analysis/root'
    create_directory(leaf_path)
    create_directory(intermediate_path)
    create_directory(root_path)
    
    # File di output di Zgrab2 pronto per l'analisi
    result_json_file = os.path.abspath('../res/certs_polito.json')
    if not os.path.exists(result_json_file) and (args.leaf_analysis or args.intermediate_analysis or args.root_analysis):
        logging.error(
            f"Il file '{result_json_file}' non esiste. Oppure il nome del file output non coincide! "
            "Si prega di consultare il README per istruzioni su come generare questo file utilizzando il programma Zgrab2."
        )
        return
    
    # File contenente la lista dei log SCT più utilizzati
    log_list_file = os.path.abspath('../res/log_list.json')
    if not os.path.exists(log_list_file) and (args.leaf_analysis or args.intermediate_analysis or args.root_analysis):
        logging.error(
            f"Il file {log_list_file} non esiste. Puoi scaricarlo direttamente da questo link: "
            "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
        )
        return
    
    if(args.leaf_analysis or args.intermediate_analysis or args.root_analysis):
        logging.info("Inizio il conteggio delle righe del file JSON contenente i certificati.")

        """
        total_lines = 0

        tqdm.write(" ")
        with open(result_json_file, 'r') as certificates_reader:
            with Progress(
                TextColumn(19*" "),
                SpinnerColumn("dots", style="cyan"),
                TextColumn("⚙️  Conteggio dei Certificati in Corso... {task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(description=f"[bold]{total_lines:,.0f}[/bold] certificati letti", total=None)
                for _ in certificates_reader:
                    total_lines += 1
                    progress.update(task, description=f"[bold]{total_lines:,.0f}[/bold] certificati letti")

        """
        # TODO: rimuovere i commenti precedenti se non si conoscono il numero delle righe del file output JSON di Zgrab2, 
        # TODO: altrimenti scrivere qui sotto il numero esatto per risparmiare tempo
        total_lines = 10000000
        
        logging.info(f"Conteggio completato: {total_lines:,.0f} certificati trovati.")

    # Analisi Certificati Leaf
    db_leaf_path = os.path.abspath(f'{leaf_path}/leaf_certificates.db')
    if(args.delete_leaf_db and not (args.leaf_analysis or args.leaf_ocsp_analysis or args.plot_leaf_results or args.leaf_zlint_check or args.leaf_chain_validation)):
        if os.path.exists(db_leaf_path):
            os.remove(db_leaf_path)
            logging.info("Database '%s' eliminato con successo.", db_leaf_path)
            
    elif(args.delete_leaf_db or args.leaf_analysis or args.leaf_ocsp_analysis or args.plot_leaf_results or args.leaf_zlint_check or args.leaf_chain_validation):
        if((args.leaf_ocsp_analysis or args.plot_leaf_results or args.leaf_zlint_check or args.leaf_chain_validation) and (not os.path.exists(db_leaf_path))):
            logging.error(
                "Il database leaf non è stato trovato nel percorso '%s'. "
                "Per eseguire la seguente analisi è necessario eseguire prima l'analisi "
                "dei certificati dal file JSON per creare il database. "
                "In alternativa, assicurati di posizionare il database nel percorso corretto.",
                db_leaf_path
            )
            return
        
        # Inizializza la connessione al database leaf
        schema_leaf_db_path = os.path.abspath('db/schema_db.sql')
        leaf_database = Database(db_path=db_leaf_path, schema_path=schema_leaf_db_path, db_type=DatabaseType.LEAF)
        leaf_database.connect(delete_database=args.delete_leaf_db)

        # Crea un'istanza del DAO
        leaf_dao = CertificateDAO(leaf_database.conn, DatabaseType.LEAF)

        # Inserisce gli SCT Operators e SCT Logs 
        if(args.delete_leaf_db):
            process_insert_sct_logs(log_list_file, leaf_dao, leaf_database)

        # Esegui l'analisi dei certificati
        if(args.leaf_analysis):
            logging.info("Inizio analisi certificati 'Leaf'.")
            leaf_certificates_analysis(result_json_file, leaf_dao, leaf_database, total_lines)
            logging.info("Analisi dei certificati 'Leaf' completata con successo.")
            
            # Rimuove i dati non necessari
            leaf_database.cleanup_unused_tables()
            leaf_database.remove_columns()
        
        # Esegui l'analisi OCSP dei certificati
        if(args.leaf_ocsp_analysis):
            logging.info("Inizio dell'analisi OCSP per i certificati 'Leaf'.")  
            await process_ocsp_check_status_request(leaf_dao, leaf_database, leaf_path)
        
        if(args.leaf_zlint_check):
            logging.info("Inizio dell'analisi dei certificati 'Leaf' con Zlint.")
            run_zlint_check(leaf_dao)
            logging.info("Controllo ZLint completato.")
        
        if(args.leaf_chain_validation):
            logging.info("Inizio del controllo della validità delle catene dei certificati 'Leaf' con 'sslyze'.")
            start_leaf_certificate_chain_check(leaf_dao, leaf_database)
            logging.info("Controllo Validità completato.")
        
        # Esegui la generazione dei grafici per i certificati leaf
        if(args.plot_leaf_results):
            # Crea gli indici e applica delle correzioni ai dati
            leaf_database.create_indexes()
            leaf_database.apply_database_corrections()
            logging.info("Inizio generazione grafici per certificati 'Leaf'.")        
            plot_leaf_certificates(leaf_dao, args.verbose)

        # Chiude la connessione al database
        leaf_database.close()
    
    # Analisi Certificati Intermediate
    db_intermediate_path = os.path.abspath(f'{intermediate_path}/intermediate_certificates.db')
    if(args.delete_intermediate_db and not (args.intermediate_analysis or args.intermediate_ocsp_analysis or args.plot_intermediate_results or args.intermediate_zlint_check)):
        if os.path.exists(db_intermediate_path):
            os.remove(db_intermediate_path)
            logging.info("Database '%s' eliminato con successo.", db_intermediate_path)

    elif(args.delete_intermediate_db or args.intermediate_analysis or args.intermediate_ocsp_analysis or args.plot_intermediate_results or args.intermediate_zlint_check):
        if((args.intermediate_ocsp_analysis or args.plot_intermediate_results or args.intermediate_zlint_check) and (not os.path.exists(db_intermediate_path))):
            logging.error(
                "Il database intermedio non è stato trovato nel percorso '%s'. "
                "Per eseguire l'analisi OCSP o visualizzare i risultati, "
                "è necessario eseguire prima l'analisi dei certificati dal file JSON per creare il database. "
                "In alternativa, assicurati di posizionare il database nel percorso corretto.",
                db_intermediate_path
            )
            return
        
        # Inizializza la connessione al database intermediate
        schema_intermediate_db_path = os.path.abspath('db/schema_db.sql')
        intermediate_database = Database(db_path=db_intermediate_path, schema_path=schema_intermediate_db_path, db_type=DatabaseType.INTERMEDIATE)
        intermediate_database.connect(delete_database=args.delete_intermediate_db)

        # Crea un'istanza del DAO
        intermediate_dao = CertificateDAO(intermediate_database.conn, DatabaseType.INTERMEDIATE)

        # Inserisce gli SCT Operators e SCT Logs 
        if(args.delete_intermediate_db):
            process_insert_sct_logs(log_list_file, intermediate_dao, intermediate_database)

        # Esegui l'analisi dei certificati
        if(args.intermediate_analysis):
            logging.info("Inizio analisi certificati 'Intermediate'.")      
            intermediate_certificates_analysis(result_json_file, intermediate_dao, intermediate_database, total_lines)
            logging.info("Analisi dei certificati 'Intermediate' completata con successo.")
            
            # Rimuove i dati non necessari, crea gli indici e applica delle correzioni ai dati
            intermediate_database.cleanup_unused_tables()
            intermediate_database.remove_columns()

        # Esegui l'analisi OCSP dei certificati
        if(args.intermediate_ocsp_analysis):
            logging.info("Inizio dell'analisi OCSP per i certificati 'Intermediate'.")  
            await process_ocsp_check_status_request(intermediate_dao, intermediate_database, intermediate_path)
        
        if(args.intermediate_zlint_check):
            logging.info("Inizio dell'analisi dei certificati 'Intermediate' con Zlint.")
            run_zlint_check(intermediate_dao)
            logging.info("Controllo ZLint completato.")
            
        # Esegui la generazione dei grafici per i certificati Intermediate
        if(args.plot_intermediate_results):
            # Crea gli indici e applica delle correzioni ai dati
            intermediate_database.create_indexes()
            intermediate_database.apply_database_corrections()
            logging.info("Inizio generazione grafici per certificati 'Intermediate'.")        
            plot_intermediate_certificates(intermediate_dao, args.verbose)

        # Chiude la connessione al database
        intermediate_database.close()
    
    # Analisi Certificati Root
    db_root_path = os.path.abspath(f'{root_path}/root_certificates.db')
    if(args.delete_root_db and not (args.root_analysis or args.root_ocsp_analysis or args.plot_root_results)):
        if os.path.exists(db_root_path):
            os.remove(db_root_path)
            logging.info("Database '%s' eliminato con successo.", db_root_path)

    elif(args.delete_root_db or args.root_analysis or args.root_ocsp_analysis or args.plot_root_results):
        if((args.root_ocsp_analysis or args.plot_root_results) and (not os.path.exists(db_root_path))):
            logging.error(
                "Il database root non è stato trovato nel percorso '%s'. "
                "Per eseguire l'analisi OCSP o visualizzare i risultati, "
                "è necessario eseguire prima l'analisi dei certificati dal file JSON per creare il database. "
                "In alternativa, assicurati di posizionare il database nel percorso corretto.",
                db_root_path
            )
            return
        
        # Inizializza la connessione al database root
        schema_root_db_path = os.path.abspath('db/schema_db.sql')
        root_database = Database(db_path=db_root_path, schema_path=schema_root_db_path, db_type=DatabaseType.ROOT)
        root_database.connect(delete_database=args.delete_root_db)

        # Crea un'istanza del DAO
        root_dao = CertificateDAO(root_database.conn, DatabaseType.ROOT)

        # Inserisce gli SCT Operators e SCT Logs 
        if(args.delete_root_db):
            process_insert_sct_logs(log_list_file, root_dao, root_database)

        # Esegui l'analisi dei certificati
        if(args.root_analysis):
            logging.info("Inizio analisi certificati 'Root'.")      
            root_certificates_analysis(result_json_file, root_dao, root_database, total_lines)
            logging.info("Analisi dei certificati 'Root' completata con successo.")
            
            # Rimuove i dati non necessari, crea gli indici e applica delle correzioni ai dati
            root_database.cleanup_unused_tables()
            root_database.remove_columns()

        # Esegui l'analisi OCSP dei certificati
        if(args.root_ocsp_analysis):
            logging.info("Inizio dell'analisi OCSP per i certificati 'Root'.")  
            await process_ocsp_check_status_request(root_dao, root_database, root_path)
        
        # Esegui la generazione dei grafici per i certificati Root
        if(args.plot_root_results):
            # Crea gli indici e applica delle correzioni ai dati
            root_database.create_indexes()
            root_database.apply_database_corrections()
            logging.info("Inizio generazione grafici per certificati 'Root'.")
            plot_root_certificates(root_dao, args.verbose)

        # Chiude la connessione al database
        root_database.close()
    
    logging.info("Applicazione terminata correttamente.\n")

