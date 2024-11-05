import logging
import os
import pandas as pd
from dao.certificate_dao import CertificateDAO
from utils.graph_plotter import GraphPlotter

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

def plot_general_certificates_analysis(dao: CertificateDAO, plotter:GraphPlotter, plots_path: str):
    """Genera e salva vari grafici comuni alle analisi di tutte le tipologie di certificati."""

    try:
        # Emissione dei Certificati da Parte degli Issuer
        logging.info("Generazione grafico 'Emissione dei Certificati da Parte degli Issuer'")
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
        
        # Distribuzione delle Versioni dei Certificati    
        logging.info("Generazione grafico 'Distribuzione delle Versioni dei Certificati'")
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
        
        # Estensioni Critiche vs Non Critiche dell'AIA
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche dell'AIA'")
        result = dao.get_count_critical_non_critical_extensions()
        filename = os.path.abspath(f'{plots_path}/count_critical_non_critical_extensions.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche dell\'AIA', filename=filename)
        
        # Numero di Certificati Emessi in Diversi Paesi
        logging.info("Generazione grafico 'Numero di Certificati Emessi in Diversi Paesi'")
        result = dao.get_certificates_per_country()
        filename = os.path.abspath(f'{plots_path}/certificates_per_country.png')
        data = pd.DataFrame(list(result.items()), columns=['Country', 'Certificate Count'])
        data.set_index('Country', inplace=True)
        plotter.plot_pie_chart(data, column='Certificate Count', title='Numero di Certificati Emessi in Diversi Paesi', filename=filename)
        
        # Distribuzione della Durata di Validità
        logging.info("Generazione grafico 'Distribuzione della Durata di Validità'")
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
        logging.info("Generazione grafico 'Trend di Scadenza dei Certificati'")
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
        logging.info("Generazione grafico 'Algoritmi di Firma Utilizzati'")
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
        
        # Validità delle Firme dei Certificati
        logging.info("Generazione grafico 'Validità delle Firme dei Certificati'")
        result = dao.get_signature_validity_distribution()
        filename = os.path.abspath(f'{plots_path}/signature_validity_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Signature Validity', 'Count'])
        data.set_index('Signature Validity', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Validità delle Firme dei Certificati', 
            xlabel='Numero di Certificati', 
            ylabel='Signature Validity', 
            filename=filename
        )
        # plotter.plot_pie_chart(data, column='Count', title='Validità delle Firme dei Certificati', filename=filename)
        
        # Utilizzo del Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Utilizzo del Key Usage nelle Estensioni'")
        result = dao.get_key_usage_distribution()
        filename = os.path.abspath(f'{plots_path}/key_usage_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Key Usage', 'Count'])
        data.set_index('Key Usage', inplace=True)    
        plotter.plot_horizontal_bar(
            data=data, 
            x='Count',
            y='Key Usage',
            title='Utilizzo del Key Usage nelle Estensioni', 
            xlabel='Numero di Certificati',
            ylabel='Key Usage Numbers',
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni'")
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
        logging.info("Generazione grafico 'Utilizzo dell\'Extended Key Usage nelle Estensioni'")
        result = dao.get_extended_key_usage_distribution()
        filename = os.path.abspath(f'{plots_path}/extended_key_usage_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Extendend Key Usage', 'Count'])
        data.set_index('Extendend Key Usage', inplace=True)
        plotter.plot_horizontal_bar(
            data=data, 
            x='Count',
            y=data.index,
            title='Utilizzo dell\'Extended Key Usage nelle Estensioni', 
            xlabel='Numero di Certificati',
            ylabel='Extendend Key Usage Numbers',
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche dell\'Extended Key Usage nelle Estensioni'")
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
        
        # Estensioni Critiche vs Non Critiche delle Subject Alternative Name
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche delle Subject Alternative Name'")
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
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche del Certificate Policies'")
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
        
        # Distribuzione del Validation Level dei Certificati    
        logging.info("Generazione grafico 'Distribuzione del Validation Level dei Certificati'")
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
        
        # Distribuzione del Basic Constraints nelle Estensioni
        logging.info("Generazione grafico 'Distribuzione del Basic Constraints nelle Estensioni'")
        result = dao.get_basic_constraints_distribution()
        filename = os.path.abspath(f'{plots_path}/basic_constraints_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Distribuzione del Basic Constraints nelle Estensioni', 
            xlabel='Flag', 
            ylabel='Numero di Certificati', 
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche del CRL Distribution
        logging.info("Generazione grafico 'Estensioni Critiche vs Non Critiche del CRL Distribution'")
        result = dao.get_critical_vs_non_critical_crl_distribution()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_crl_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Estensioni Critiche vs Non Critiche del CRL Distribution', filename=filename)
        
        # Stato OCSP dei Certificati
        logging.info("Generazione grafico 'Stato OCSP dei Certificati'")
        result = dao.get_ocsp_status_distribution()
        filename = os.path.abspath(f'{plots_path}/ocsp_status_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['OCSP Status', 'Count'])
        data.set_index('OCSP Status', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Stato OCSP dei Certificati', filename=filename)
    except Exception as e:
        logging.error(f"Errore nella generazione di un grafico: {e}")
    
    return

def plot_leaf_certificates_analysis(dao: CertificateDAO, plotter:GraphPlotter, plots_path: str):
    """Genera e salva grafici specifici per l'analisi dei certificati leaf."""    
    
    try:
        # Analisi Status Certificati
        logging.info("Generazione grafico 'Analisi Status Certificati'")
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
        
        # Certificati Auto-Firmati vs CA-Firmati
        logging.info("Generazione grafico 'Certificati Auto-Firmati vs CA-Firmati'")
        result = dao.get_self_signed_vs_ca_signed()
        filename = os.path.abspath(f'{plots_path}/self_signed_vs_ca_signed.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Certificati Auto-Firmati vs CA-Firmati', filename=filename)
        
        # Distribuzione degli Algoritmi di Chiave e Lunghezza
        logging.info("Generazione grafico 'Distribuzione degli Algoritmi di Chiave e Lunghezza'")
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
        
        # Top SCT Logs
        logging.info("Generazione grafico 'Top SCT Logs'")
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
        logging.info("Generazione grafico 'Top SCT Log Operators'")
        result = dao.get_top_sct_log_operators()
        data = pd.DataFrame(list(result.items()), columns=['Log Operator', 'Certificate Count'])
        filename = os.path.abspath(f'{plots_path}/top_sct_log_operators.png')
        data.set_index('Log Operator', inplace=True)
        plotter.plot_pie_chart(data, column='Certificate Count', title='Top SCT Log Operators', filename=filename)   
    
        # Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno
        logging.info("Generazione grafico 'Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno'")
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
        logging.info("Generazione grafico 'Numero dei Signed Certificate Timestamps (SCT) per Certificato'")
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
        
    except Exception as e:
        logging.error(f"Errore nella generazione di un grafico: {e}")
    
    return