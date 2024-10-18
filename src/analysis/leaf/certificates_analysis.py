import json
import logging
import os
import argparse
from db.database import Database
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
    """Analizza e inserisce i certificati dal file JSON nel database."""
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

def plot_leaf_certificates_analysis(dao: CertificateDAO):
    plotter = GraphPlotter()
    
    # Emissione dei Certificati da Parte degli Issuer
    result = dao.get_issuer_certificate_count()
    filename = os.path.abspath('analysis/leaf/plots/issuer_certificates_count.png')
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
    filename = os.path.abspath('analysis/leaf/plots/certificates_per_country.png')
    data = pd.DataFrame(list(result.items()), columns=['Country', 'Certificate Count'])
    data.set_index('Country', inplace=True)
    plotter.plot_pie_chart(data, column='Certificate Count', title='Numero di Certificati Emessi in Diversi Paesi', filename=filename)
    

    # Distribuzione della Durata di Validità
    result = dao.get_validity_duration_distribution()
    data = pd.DataFrame(list(result.items()), columns=['Validity Length', 'Certificate Count'])
    filename = os.path.abspath('analysis/leaf/plots/validity_duration_distribution.png')
    data.set_index('Certificate Count', inplace=True)
    plotter.plot_histogram(
        data=data, 
        y='Validity Length',
        title='Distribuzione della Durata di Validità', 
        xlabel='Durata (anni)',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Trend di Scadenza dei Certificati
    result = dao.get_certificate_expiration_trend()
    data = pd.DataFrame(list(result.items()), columns=['Month', 'Certificate Count'])
    filename = os.path.abspath('analysis/leaf/plots/certificate_expiration_trend.png')
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
    filename = os.path.abspath('analysis/leaf/plots/signature_algorithm_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/key_algorithm_length_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/ocsp_status_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['OCSP Status', 'Count'])
    data.set_index('OCSP Status', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Stato OCSP dei Certificati', filename=filename)
    
    # Estensioni Critiche vs Non Critiche dell'AIA
    result = dao.get_count_critical_non_critical_extensions()
    filename = os.path.abspath('analysis/leaf/plots/count_critical_non_critical_extensions.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche dell\'AIA', filename=filename)
    
    # Certificati Auto-Firmati vs CA-Firmati
    result = dao.get_self_signed_vs_ca_signed()
    filename = os.path.abspath('analysis/leaf/plots/self_signed_vs_ca_signed.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Certificati Auto-Firmati vs CA-Firmati', filename=filename)
    
    # Livelli di Validazione dei Certificati    
    result = dao.get_validation_level_distribution()
    filename = os.path.abspath('analysis/leaf/plots/validation_level_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/certificate_version_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/signature_validity_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Signature Validity', 'Count'])
    data.set_index('Signature Validity', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Validità delle Firme dei Certificati', filename=filename)
    
    # Analisi Status Certificati
    result = dao.get_status_analysis()
    filename = os.path.abspath('analysis/leaf/plots/status_analysis.png')
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
    filename = os.path.abspath('analysis/leaf/plots/key_usage_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/critical_vs_non_critical_key_usage.png')
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
    filename = os.path.abspath('analysis/leaf/plots/extended_key_usage_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/critical_vs_non_critical_extended_key_usage.png')
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
    filename = os.path.abspath('analysis/leaf/plots/basic_constraints_distribution.png')
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
    filename = os.path.abspath('analysis/leaf/plots/critical_vs_non_critical_crl_distribution.png')
    data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
    data.set_index('Flag', inplace=True)
    plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche del CRL Distribution', filename=filename)
    
    # Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno
    result = dao.get_signed_certificate_timestamp_trend()
    data = pd.DataFrame(list(result.items()), columns=['Date', 'Certificate Count'])
    filename = os.path.abspath('analysis/leaf/plots/certificate_expiration_trend.png')
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
    filename = os.path.abspath('analysis/leaf/plots/sct_count_per_certificate.png')
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
    
    # Top SCT Issuers
    result = dao.get_top_sct_issuers()
    data = pd.DataFrame(list(result.items()), columns=['Log ID', 'Certificate Count'])
    filename = os.path.abspath('analysis/leaf/plots/top_sct_issuers.png')
    data.set_index('Log ID', inplace=True)
    plotter.plot_bar_chart(
        data=data, 
        x=data.index,
        y='Certificate Count',
        title='Top SCT Issuers', 
        xlabel='Log ID',
        ylabel='Numero di Certificati', 
        filename=filename
    )
    
    # Estensioni Critiche vs Non Critiche delle Subject Alternative Name
    result = dao.get_critical_vs_non_critical_san_extensions()
    filename = os.path.abspath('analysis/leaf/plots/critical_vs_non_critical_san_extensions.png')
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
    
    return


def leaf_certificates_analysis_main():
    # Configura argparse per gestire gli argomenti della riga di comando
    parser = argparse.ArgumentParser(description='Analisi dei certificati.')
    parser.add_argument('--delete_db', action='store_true', help='Se presente, elimina il database prima di iniziare.')
    parser.add_argument('--leaf_analysis', action='store_true', help='Analizza i certificati leaf.')
    parser.add_argument('--plot_results', action='store_true', 
                    help='Genera e visualizza i grafici se sono presenti dati analizzati. Utilizza questo flag per attivare la visualizzazione dei risultati grafici dell\'analisi dei certificati.')

    # Estrai gli argomenti dalla riga di comando
    args = parser.parse_args()
    
    # Setup del logger
    setup_logging()
    logging.info("Inizio dell'applicazione.")
    
    result_json_file = os.path.abspath('../res/certs_polito_windows_2.json')

    # Inizializza la connessione al database
    # db_path = os.path.abspath('analysis/leaf/leaf_certificates.db')
    db_path = os.path.abspath('../leaf_certificates_light.db')
    schema_path = os.path.abspath('db/schema_leaf_db.sql')
    database = Database(db_path=db_path, schema_path=schema_path)
    database.connect(delete_database=args.delete_db)

    # Crea un'istanza del DAO
    dao = CertificateDAO(database.conn)

    # Esegui l'analisi dei certificati
    if(args.leaf_analysis):
        leaf_certificates_analysis(result_json_file, dao, database)

    if(args.plot_results):
        plot_leaf_certificates_analysis(dao)

    # Chiudi la connessione al database
    database.close()
    logging.info("Applicazione terminata correttamente.")

