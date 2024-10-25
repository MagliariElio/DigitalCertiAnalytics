import json
import logging
import os, shutil
import argparse
from db.database import Database, DatabaseType
from dao.certificate_dao import CertificateDAO
from utils.graph_plotter import GraphPlotter
import pandas as pd

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

def setup_logging():
    """Configura il logging dell'applicazione."""
    logging.basicConfig(
        level=logging.INFO,  # Cambia in DEBUG per più dettagli
        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s',
        handlers=[
            logging.FileHandler("app.log"),
            logging.StreamHandler()
        ]
    )

def leaf_certificates_analysis(certificates_file, dao: CertificateDAO, database: Database):
    """Analizza e inserisce i certificati leaf dal file JSON nel database."""
    print("\n")
    with open(certificates_file, 'r') as certificates_reader:
        for line_number, row in enumerate(certificates_reader, start=1):
            try:
                json_row = json.loads(row)
                status = json_row.get("data", {}).get("tls", {}).get("status", "")

                # TODO: da rimuovere
                # if(line_number < 1567400):
                #    continue

                if(line_number % 100 == 0):
                    print(f"\rNumero di Certificati processati: {line_number}", end="")

                with database.transaction():
                    if status == "success":
                        dao.process_insert_certificate(json_row)
                    else:
                        dao.insert_error_row(json_row)

            except json.JSONDecodeError:
                logging.error(f"Errore nel parsing della riga {line_number}: {row.strip()}")
            except Exception as e:
                logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
    return

def intermediate_certificates_analysis(certificates_file, dao: CertificateDAO, database: Database):
    """Analizza e inserisce i certificati intermediate dal file JSON nel database."""
    print("\n")
    with open(certificates_file, 'r') as certificates_reader:
        for line_number, row in enumerate(certificates_reader, start=1):
            try:
                json_row = json.loads(row)
                status = json_row.get("data", {}).get("tls", {}).get("status", "")

                """
                    Se la riga ha uno stato di "success", il primo certificato intermedio della 
                    catena viene inserito impostato come se fosse un certificato leaf. 
                    Dopo l'inserimento, il certificato intermedio viene rimosso dalla catena, 
                    riducendo progressivamente la catena mentre viene elaborata. Inoltre,
                    dall'analisi viene escluso il certificato root.               
                """
                with database.transaction():
                    if status == "success":
                        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                        server_certificates = handshake_log.get("server_certificates", {})
                        chain = server_certificates.get("chain", [])
                        
                        for cert_number, cert in enumerate(chain, start=1):
                            if((line_number+cert_number) % 100 == 0):
                                print(f"\rNumero di Certificati processati: {line_number+cert_number}", end="")
                            
                            raw_intermediate = cert.get("raw", {})
                            parsed_intermediate = cert.get("parsed", {})
                        
                            json_row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["raw"] = raw_intermediate
                            json_row["data"]["tls"]["result"]["handshake_log"]["server_certificates"]["certificate"]["parsed"] = parsed_intermediate

                            server_certificates["chain"] = chain[cert_number:]
 
                            # Impostazione dei certificati eseguita, inizio analisi del certificato intermedio
                            dao.process_insert_certificate(json_row)

            except json.JSONDecodeError:
                logging.error(f"Errore nel parsing della riga {line_number}: {row.strip()}")
            except Exception as e:
                logging.error(f"Errore nell'elaborazione della riga {line_number}: {e}")
    return

def process_ocsp_check_status_request(dao: CertificateDAO, database: Database):
    """Elabora la richiesta per controllare lo stato OCSP di tutti i certificati nel DAO."""
    try:
        with database.transaction():
            dao.check_ocsp_status_for_certificates()
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

def plot_leaf_certificates_analysis(dao: CertificateDAO):
    """Genera e salva vari grafici relativi all'analisi dei certificati."""
    
    plotter = GraphPlotter()
    plots_path = 'analysis/leaf/plots'
    
    # Rimuovi la cartella se esiste
    if os.path.exists(plots_path):
        shutil.rmtree(plots_path)

    # Crea la cartella per il plot leaf
    os.makedirs(plots_path)
    
    # Emissione dei Certificati da Parte degli Issuer
    result = dao.get_issuer_certificate_count()
    filename = os.path.abspath(f'{plots_path}/issuer_certificates_count.png')
    data = pd.DataFrame(list(result.items()), columns=['Issuer', 'Certificate Count'])
    data.set_index('Issuer', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Certificate Count', 
        title='Emissione dei Certificati da Parte degli Issuer', 
        xlabel='Issuers', 
        ylabel='Numero di Certificati', 
        filename=filename
    )

    # Certificates per Country
    result = dao.get_certificates_per_country()
    filename = os.path.abspath(f'{plots_path}/certificates_per_country.png')
    data = pd.DataFrame(list(result.items()), columns=['Country', 'Certificate Count'])
    data.set_index('Country', inplace=True)
    plotter.plot_pie_chart(data, column='Certificate Count', title='Numero di Certificati Emessi in Diversi Paesi', filename=filename)
    

    # Distribuzione della Durata di Validità
    result = dao.get_validity_duration_distribution()
    data = pd.DataFrame(list(result.items()), columns=['Validity Length', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/validity_duration_distribution.png')
    data.set_index('Validity Length', inplace=True)
    plotter.plot_bar_chart(
        data=data,
        x=data.index,
        y='Certificate Count',
        title='Distribuzione della Durata di Validità', 
        xlabel='Durata (anni)',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Trend di Scadenza dei Certificati
    result = dao.get_certificate_expiration_trend()
    data = pd.DataFrame(list(result.items()), columns=['Month', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/certificate_expiration_trend.png')
    data.set_index('Month', inplace=True)
    plotter.plot_line_chart(
        data=data, 
        x=data.index,
        y='Certificate Count',
        title='Trend di Scadenza dei Certificati', 
        xlabel='Mese',
        ylabel='Numero di Certificati', 
        filename=filename
    )

    # Algoritmi di Firma Utilizzati    
    result = dao.get_signature_algorithm_distribution()
    filename = os.path.abspath(f'{plots_path}/signature_algorithm_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Signature Algorithm', 'Count'])
    data.set_index('Signature Algorithm', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Algoritmi di Firma Utilizzati', 
        xlabel='Numero di Certificati', 
        ylabel='Signature Algorithm', 
        filename=filename
    )
    
    # Distribuzione degli Algoritmi di Chiave e Lunghezza    
    result = dao.get_key_algorithm_length_distribution()
    filename = os.path.abspath(f'{plots_path}/key_algorithm_length_distribution.png')
    data = pd.DataFrame.from_dict(
        {alg: dict(lengths) for alg, lengths in result.items()},
        orient='index'
    ).fillna(0)  # Sostituisce i NaN con 0
    data = data.astype(int)  
    data = data.transpose()

    plotter.plot_stacked_bar_chart(
        data=data, 
        title='Distribuzione degli Algoritmi di Chiave e Lunghezza', 
        xlabel='Key Length',
        ylabel='Numero di Certificati',
        filename=filename
    )
    
    # Stato OCSP dei Certificati
    result = dao.get_ocsp_status_distribution()
    filename = os.path.abspath(f'{plots_path}/ocsp_status_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['OCSP Status', 'Count'])
    data.set_index('OCSP Status', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Stato OCSP dei Certificati', filename=filename)
    
    # Estensioni Critiche vs Non Critiche dell'AIA
    result = dao.get_count_critical_non_critical_extensions()
    filename = os.path.abspath(f'{plots_path}/count_critical_non_critical_extensions.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche dell\'AIA', filename=filename)
    
    # Certificati Auto-Firmati vs CA-Firmati
    result = dao.get_self_signed_vs_ca_signed()
    filename = os.path.abspath(f'{plots_path}/self_signed_vs_ca_signed.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Certificati Auto-Firmati vs CA-Firmati', filename=filename)
    
    # Livelli di Validazione dei Certificati    
    result = dao.get_validation_level_distribution()
    filename = os.path.abspath(f'{plots_path}/validation_level_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Validation', 'Count'])
    data.set_index('Validation', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Distribuzione del Validation Level dei Certificati', 
        xlabel='Validation Levels', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Distribuzione delle Versioni dei Certificati    
    result = dao.get_certificate_version_distribution()
    filename = os.path.abspath(f'{plots_path}/certificate_version_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Version', 'Count'])
    data.set_index('Version', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Distribuzione delle Versioni dei Certificati', 
        xlabel='Versions', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Validità delle Firme dei Certificati
    result = dao.get_signature_validity_distribution()
    filename = os.path.abspath(f'{plots_path}/signature_validity_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Signature Validity', 'Count'])
    data.set_index('Signature Validity', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Validità delle Firme dei Certificati', filename=filename)
    
    # Analisi Status Certificati
    result = dao.get_status_analysis()
    filename = os.path.abspath(f'{plots_path}/status_analysis.png')
    data = pd.DataFrame(list(result.items()), columns=['Status', 'Count'])
    data.set_index('Status', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Analisi Status Certificati', 
        xlabel='Status', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Utilizzo del Key Usage nelle Estensioni
    result = dao.get_key_usage_distribution()
    filename = os.path.abspath(f'{plots_path}/key_usage_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Key Usage', 'Count'])
    data.set_index('Key Usage', inplace=True)    
    plotter.plot_dot_plot(
        data=data, 
        x='Count',
        y='Key Usage',
        title='Utilizzo del Key Usage nelle Estensioni', 
        xlabel='Numero di Certificati',
        ylabel='Key Usage Numbers',
        filename=filename
    )
    
    # Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
    result = dao.get_critical_vs_non_critical_key_usage()
    filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_key_usage.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni', 
        xlabel='Flag', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Utilizzo dell'Extended Key Usage nelle Estensioni
    result = dao.get_extended_key_usage_distribution()
    filename = os.path.abspath(f'{plots_path}/extended_key_usage_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Extendend Key Usage', 'Count'])
    data.set_index('Extendend Key Usage', inplace=True)
    plotter.plot_dot_plot(
        data=data, 
        x='Count',
        y=data.index,
        title='Utilizzo dell\'Extended Key Usage nelle Estensioni', 
        xlabel='Numero di Certificati',
        ylabel='Extendend Key Usage Numbers',
        filename=filename
    )
    
    # Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
    result = dao.get_critical_vs_non_critical_extended_key_usage()
    filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_extended_key_usage.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Estensioni Critiche vs Non Critiche dell\'Extended Key Usage nelle Estensioni', 
        xlabel='Flag', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Distribuzione del Basic Constraints nelle Estensioni
    result = dao.get_basic_constraints_distribution()
    filename = os.path.abspath(f'{plots_path}/basic_constraints_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index, 
        y='Count', 
        title='Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni', 
        xlabel='Flag', 
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Estensioni Critiche vs Non Critiche del CRL Distribution
    result = dao.get_critical_vs_non_critical_crl_distribution()
    filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_crl_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche del CRL Distribution', filename=filename)
    
    # Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno
    result = dao.get_signed_certificate_timestamp_trend()
    data = pd.DataFrame(list(result.items()), columns=['Date', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/certificate_expiration_trend.png')
    data.set_index('Date', inplace=True)
    plotter.plot_line_chart(
        data=data, 
        x=data.index,
        y='Certificate Count',
        title='Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno', 
        xlabel='Date',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Numero dei Signed Certificate Timestamps (SCT) per Certificato
    result = dao.get_sct_count_per_certificate()
    data = pd.DataFrame(list(result.items()), columns=['SCT Count', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/sct_count_per_certificate.png')
    data.set_index('SCT Count', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index,
        y='Certificate Count',
        title='Numero dei Signed Certificate Timestamps (SCT) per Certificato', 
        xlabel='SCT Count',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Top SCT Logs
    result = dao.get_top_sct_logs()
    data = pd.DataFrame(list(result.items()), columns=['Log Name', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/top_sct_logs.png')
    data.set_index('Log Name', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index,
        y='Certificate Count',
        title='Top SCT Logs', 
        xlabel='Logs Name',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Top SCT Log Operators
    result = dao.get_top_sct_log_operators()
    data = pd.DataFrame(list(result.items()), columns=['Log Operator', 'Certificate Count'])
    filename = os.path.abspath(f'{plots_path}/top_sct_log_operators.png')
    data.set_index('Log Operator', inplace=True)
    plotter.plot_pie_chart(data, column='Certificate Count', title='Top SCT Log Operators', filename=filename)
    
    # Estensioni Critiche vs Non Critiche delle Subject Alternative Name
    result = dao.get_critical_vs_non_critical_san_extensions()
    filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_san_extensions.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index,
        y='Count',
        title='Estensioni Critiche vs Non Critiche delle Subject Alternative Name', 
        xlabel='Flag',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Estensioni Critiche vs Non Critiche del Certificate Policies
    result = dao.get_critical_vs_non_critical_cp_policies()
    filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_cp_policies.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index,
        y='Count',
        title='Estensioni Critiche vs Non Critiche del Certificate Policies', 
        xlabel='Flag',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    return


def certificates_analysis_main():
    # Configura argparse per gestire gli argomenti della riga di comando
    parser = argparse.ArgumentParser(description='Analisi dei certificati.')
    parser.add_argument('--delete_all_db', action='store_true', help='Se presenti, elimina tutti i database prima di iniziare.')
    parser.add_argument('--delete_leaf_db', action='store_true', help='Se presente, elimina il database leaf prima di iniziare.')
    parser.add_argument('--delete_intermediate_db', action='store_true', help='Se presente, elimina il database intermediate prima di iniziare.')
    parser.add_argument('--leaf_analysis', action='store_true', help='Analizza i certificati leaf.')
    parser.add_argument('--leaf_ocsp_analysis', action='store_true', help='Esegue l\'analisi OCSP per i certificati leaf.')
    parser.add_argument('--intermediate_analysis', action='store_true', help='Analizza i certificati intermediate.')
    parser.add_argument('--plot_all_results', action='store_true', 
                    help='Genera e visualizza i grafici se sono presenti dati analizzati. Utilizza questo flag per attivare la visualizzazione dei risultati grafici dell\'analisi dei certificati.')
    parser.add_argument('--plot_leaf_results', action='store_true', 
                    help='Genera e visualizza i grafici se sono presenti dati analizzati. Utilizza questo flag per attivare la visualizzazione dei risultati grafici dell\'analisi dei certificati.')
    parser.add_argument('--plot_intermediate_results', action='store_true', 
                    help='Genera e visualizza i grafici se sono presenti dati analizzati. Utilizza questo flag per attivare la visualizzazione dei risultati grafici dell\'analisi dei certificati.')

    # Estrai gli argomenti dalla riga di comando
    args = parser.parse_args()
    
    # Setup del logger
    setup_logging()
    logging.info("Inizio dell'applicazione.")

    # Imposta le cancellazioni dei database    
    args.delete_leaf_db = args.delete_leaf_db or args.delete_all_db
    args.delete_intermediate_db = args.delete_intermediate_db or args.delete_all_db
    
    # Imposta il plot dei risutalti    
    args.plot_leaf_results = args.plot_leaf_results or args.plot_all_results
    args.plot_intermediate_results = args.plot_intermediate_results or args.plot_all_results
    
    # Funzione lambda per creare una cartella se non esiste
    create_directory = lambda path: os.makedirs(path) if not os.path.exists(path) else None
    
    # Definizione delle cartelle per il risultato delle analisi
    leaf_path = 'analysis/leaf'
    intermediate_path = 'analysis/intermediate'
    create_directory(leaf_path)
    create_directory(intermediate_path)
    
    # File di output di Zgrab2 pronto per l'analisi
    result_json_file = os.path.abspath('../res/certs_polito.json')

    # Analisi Certificati Leaf
    if(args.delete_leaf_db or args.leaf_analysis or args.leaf_ocsp_analysis or args.plot_leaf_results):
        # Inizializza la connessione al database leaf
        db_leaf_path = os.path.abspath(f'{leaf_path}/leaf_certificates.db')
        schema_leaf_db_path = os.path.abspath('db/schema_db.sql')
        leaf_database = Database(db_path=db_leaf_path, schema_path=schema_leaf_db_path, db_type=DatabaseType.LEAF)
        leaf_database.connect(delete_database=args.delete_leaf_db)

        # Crea un'istanza del DAO
        leaf_dao = CertificateDAO(leaf_database.conn)

        # Inserisce gli SCT Operators e SCT Logs 
        if(args.delete_leaf_db):
            log_list_file = os.path.abspath('../res/log_list.json')
            if not os.path.exists(log_list_file):
                raise FileNotFoundError(f"Il file {log_list_file} non esiste. Scaricare il file.")
            process_insert_sct_logs(log_list_file, leaf_dao, leaf_database)

        # Esegui l'analisi dei certificati
        if(args.leaf_analysis):
            logging.info("Inizio analisi certificati Leaf.")      
            leaf_certificates_analysis(result_json_file, leaf_dao, leaf_database)
            logging.info("Analisi dei certificati Leaf completata con successo.")        

        # Esegui l'analisi OCSP dei certificati
        if(args.leaf_ocsp_analysis):
            logging.info("Inizio dell'analisi OCSP per i certificati.")  
            process_ocsp_check_status_request(leaf_dao, leaf_database)
            logging.info("Analisi OCSP per i certificati completata.")
        
        # Esegui la generazione dei grafici per i certificati leaf
        if(args.plot_leaf_results):
            logging.info("Inizio generazione grafici per certificati Leaf.")        
            plot_leaf_certificates_analysis(leaf_dao)
            logging.info("Generazione dei grafici per l'analisi dei certificati Leaf completata.")

        # Chiudi la connessione al database
        leaf_database.close()
    
    # Analisi Certificati Intermediate
    if(args.delete_intermediate_db or args.intermediate_analysis or args.plot_leaf_results):
        # Inizializza la connessione al database intermediate
        db_intermediate_path = os.path.abspath(f'{intermediate_path}/intermediate_certificates.db')
        schema_intermediate_db_path = os.path.abspath('db/schema_db.sql')
        intermediate_database = Database(db_path=db_intermediate_path, schema_path=schema_intermediate_db_path, db_type=DatabaseType.INTERMEDIATE)
        intermediate_database.connect(delete_database=args.delete_intermediate_db)

        # Crea un'istanza del DAO
        intermediate_dao = CertificateDAO(intermediate_database.conn)

        # Inserisce gli SCT Operators e SCT Logs 
        if(args.delete_intermediate_db):
            log_list_file = os.path.abspath('../res/log_list.json')
            if not os.path.exists(log_list_file):
                raise FileNotFoundError(f"Il file {log_list_file} non esiste. Scaricare il file.")
            process_insert_sct_logs(log_list_file, intermediate_dao, intermediate_database)

        # Esegui l'analisi dei certificati
        if(args.intermediate_analysis):
            logging.info("Inizio analisi certificati Intermediate.")      
            intermediate_certificates_analysis(result_json_file, intermediate_dao, intermediate_database)
            logging.info("Analisi dei certificati Intermediate completata con successo.")

        # Chiudi la connessione al database
        intermediate_database.close()
        
    logging.info("Applicazione terminata correttamente.")

