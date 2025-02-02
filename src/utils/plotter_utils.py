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
        logging.info("Generazione grafico 'Issuance of Certificates by Issuers'")
        result = dao.get_issuer_certificate_count()
        filename = os.path.abspath(f'{plots_path}/issuer_certificates_count.png')
        data = pd.DataFrame(list(result.items()), columns=['Issuer', 'Certificate Count'])
        data.set_index('Issuer', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Certificate Count', 
            title='Issuance of Certificates by Issuers', 
            xlabel='Issuers', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Distribuzione delle Versioni dei Certificati    
        logging.info("Generazione grafico 'Distribution of Certificate Versions'")
        result = dao.get_certificate_version_distribution()
        filename = os.path.abspath(f'{plots_path}/certificate_version_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Version', 'Count'])
        data.set_index('Version', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Distribution of Certificate Versions', 
            xlabel='Versions', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche dell'AIA
        logging.info("Generazione grafico 'Critical vs Non-Critical Extensions of the AIA'")
        result = dao.get_count_critical_non_critical_extensions()
        filename = os.path.abspath(f'{plots_path}/count_critical_non_critical_extensions.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Critical vs Non-Critical Extensions of the AIA', filename=filename)
        
        # Numero di Certificati Emessi in Diversi Paesi
        logging.info("Generazione grafico 'Number of Certificates Issued in Different Countries'")
        result = dao.get_certificates_per_country()
        filename = os.path.abspath(f'{plots_path}/certificates_per_country.png')
        data = pd.DataFrame(list(result.items()), columns=['Country', 'Certificate Count'])
        data.set_index('Country', inplace=True)
        plotter.plot_pie_chart(data, column='Certificate Count', title='Number of Certificates Issued in Different Countries', filename=filename)
        
        # Distribuzione della Durata di Validità
        logging.info("Generazione grafico 'Distribution of Validity Duration'")
        result = dao.get_validity_duration_distribution()
        data = pd.DataFrame(list(result.items()), columns=['Validity Length', 'Certificate Count'])
        filename = os.path.abspath(f'{plots_path}/validity_duration_distribution.png')
        data.set_index('Validity Length', inplace=True)
        plotter.plot_bar_chart(
            data=data,
            x=data.index,
            y='Certificate Count',
            title='Distribution of Validity Duration', 
            xlabel='Duration (years)',
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Trend di Scadenza dei Certificati
        logging.info("Generazione grafico 'Maturity Trends of the Certificates'")
        result = dao.get_certificate_expiration_trend()
        data = pd.DataFrame(list(result.items()), columns=['Month', 'Certificate Count'])
        filename = os.path.abspath(f'{plots_path}/certificate_expiration_trend.png')
        data.set_index('Month', inplace=True)
        plotter.plot_line_chart(
            data=data, 
            x=data.index,
            y='Certificate Count',
            title='Maturity Trends of the Certificates', 
            xlabel='Month',
            ylabel='Number of Certificates', 
            filename=filename
        )

        # Algoritmi di Firma Utilizzati    
        logging.info("Generazione grafico 'Signature Algorithms Used'")
        result = dao.get_signature_algorithm_distribution()
        filename = os.path.abspath(f'{plots_path}/signature_algorithm_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Signature Algorithm', 'Count'])
        data.set_index('Signature Algorithm', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Signature Algorithms Used', 
            xlabel='Number of Certificates', 
            ylabel='Signature Algorithm', 
            filename=filename
        )
        
        # Utilizzo del Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Key Usage in Extensions'")
        result = dao.get_key_usage_distribution()
        filename = os.path.abspath(f'{plots_path}/key_usage_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Key Usage', 'Count'])
        data.set_index('Key Usage', inplace=True)    
        plotter.plot_horizontal_bar(
            data=data, 
            x='Count',
            y='Key Usage',
            title='Key Usage in Extensions', 
            xlabel='Number of Certificates',
            ylabel='Key Usage Numbers',
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Critical vs Non-Critical Key Usage in Extensions'")
        result = dao.get_critical_vs_non_critical_key_usage()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_key_usage.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Critical vs Non-Critical Key Usage in Extensions', 
            xlabel='Flag', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Utilizzo dell'Extended Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Extended Key Usage in Extensions'")
        result = dao.get_extended_key_usage_distribution()
        filename = os.path.abspath(f'{plots_path}/extended_key_usage_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Extendend Key Usage', 'Count'])
        data.set_index('Extendend Key Usage', inplace=True)
        plotter.plot_horizontal_bar(
            data=data, 
            x='Count',
            y=data.index,
            title='Extended Key Usage in Extensions', 
            xlabel='Number of Certificates',
            ylabel='Extendend Key Usage Numbers',
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
        logging.info("Generazione grafico 'Critical vs Non-Critical Extended Key Usage in Extensions'")
        result = dao.get_critical_vs_non_critical_extended_key_usage()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_extended_key_usage.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Critical vs Non-Critical Extended Key Usage in Extensions', 
            xlabel='Flag', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche delle Subject Alternative Name
        logging.info("Generazione grafico 'Critical vs Non-Critical Extensions of Subject Alternative Names'")
        result = dao.get_critical_vs_non_critical_san_extensions()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_san_extensions.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index,
            y='Count',
            title='Critical vs Non-Critical Extensions of Subject Alternative Names', 
            xlabel='Flag',
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche del Certificate Policies
        logging.info("Generazione grafico 'Critical vs Non-Critical Extensions of Certificate Policies'")
        result = dao.get_critical_vs_non_critical_cp_policies()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_cp_policies.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index,
            y='Count',
            title='Critical vs Non-Critical Extensions of Certificate Policies', 
            xlabel='Flag',
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Distribuzione del Validation Level dei Certificati    
        logging.info("Generazione grafico 'Distribution of the Validation Level of Certificates'")
        result = dao.get_validation_level_distribution()
        filename = os.path.abspath(f'{plots_path}/validation_level_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Validation', 'Count'])
        data.set_index('Validation', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Distribution of the Validation Level of Certificates', 
            xlabel='Validation Levels', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Distribuzione del Basic Constraints nelle Estensioni
        logging.info("Generazione grafico 'Distribution of Basic Constraints in Extensions'")
        result = dao.get_basic_constraints_distribution()
        filename = os.path.abspath(f'{plots_path}/basic_constraints_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Distribution of Basic Constraints in Extensions', 
            xlabel='Flag', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Estensioni Critiche vs Non Critiche del CRL Distribution
        logging.info("Generazione grafico 'Critical vs Non-Critical Extensions of CRL Distribution'")
        result = dao.get_critical_vs_non_critical_crl_distribution()
        filename = os.path.abspath(f'{plots_path}/critical_vs_non_critical_crl_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Critical vs Non-Critical Extensions of CRL Distribution', filename=filename)
        
        # Stato OCSP dei Certificati
        logging.info("Generazione grafico 'OCSP Status of Certificates'")
        result = dao.get_ocsp_status_distribution()
        filename = os.path.abspath(f'{plots_path}/ocsp_status_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['OCSP Status', 'Count'])
        data.set_index('OCSP Status', inplace=True)
        # plotter.plot_pie_chart(data, column='Count', title='OCSP Status of Certificates', filename=filename)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='OCSP Status of Certificates', 
            xlabel='OCSP Status',
            ylabel='Number of Certificates', 
            filename=filename
        )
    except Exception as e:
        logging.error(f"Errore nella generazione di un grafico: {e}")
    
    return

def plot_leaf_certificates_analysis(dao: CertificateDAO, plotter:GraphPlotter, plots_path: str):
    """Genera e salva grafici specifici per l'analisi dei certificati leaf."""
    
    try:
        # Analisi Status Certificati
        logging.info("Generazione grafico 'Analysis Status Certificates'")
        result = dao.get_status_analysis()
        filename = os.path.abspath(f'{plots_path}/status_analysis.png')
        data = pd.DataFrame(list(result.items()), columns=['Status', 'Count'])
        data.set_index('Status', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Analysis Status Certificates', 
            xlabel='Status', 
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Certificati Auto-Firmati vs CA-Firmati
        logging.info("Generazione grafico 'Self-Signed vs CA-Signed Certificates'")
        result = dao.get_self_signed_vs_ca_signed()
        filename = os.path.abspath(f'{plots_path}/self_signed_vs_ca_signed.png')
        data = pd.DataFrame(list(result.items()), columns=['Flag', 'Count'])
        data.set_index('Flag', inplace=True)
        plotter.plot_pie_chart(data, column='Count', title='Self-Signed vs CA-Signed Certificates', filename=filename)
        
        # Distribuzione degli Algoritmi di Chiave e Lunghezza
        logging.info("Generazione grafico 'Distribution of Key and Length Algorithms'")
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
            title='Distribution of Key and Length Algorithms', 
            xlabel='Key Length',
            ylabel='Number of Certificates',
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
            ylabel='Number of Certificates', 
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
        logging.info("Generazione grafico 'Trend of Signed Certificate Timestamps (SCT) by Month and Year'")
        result = dao.get_signed_certificate_timestamp_trend()
        data = pd.DataFrame(list(result.items()), columns=['Date', 'Certificate Count'])
        filename = os.path.abspath(f'{plots_path}/certificate_expiration_trend.png')
        data.set_index('Date', inplace=True)
        plotter.plot_line_chart(
            data=data, 
            x=data.index,
            y='Certificate Count',
            title='Trend of Signed Certificate Timestamps (SCT) by Month and Year', 
            xlabel='Date',
            ylabel='Number of Certificates', 
            filename=filename
        )
        
        # Numero dei Signed Certificate Timestamps (SCT) per Certificato
        logging.info("Generazione grafico 'Number of Signed Certificate Timestamps (SCT) per Certificate'")
        result = dao.get_sct_count_per_certificate()
        data = pd.DataFrame(list(result.items()), columns=['SCT Count', 'Certificate Count'])
        filename = os.path.abspath(f'{plots_path}/sct_count_per_certificate.png')
        data.set_index('SCT Count', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index,
            y='Certificate Count',
            title='Number of Signed Certificate Timestamps (SCT) per Certificate', 
            xlabel='SCT Count',
            ylabel='Number of Certificates', 
            filename=filename
        )
        
    except Exception as e:
        logging.error(f"Errore nella generazione di un grafico: {e}")
    
    return


def plot_leaf_and_root_certificates_analysis(dao: CertificateDAO, plotter:GraphPlotter, plots_path: str):
    """Genera e salva grafici specifici per l'analisi dei certificati leaf e root."""
    
    try:
        # Validità delle Firme dei Certificati
        logging.info("Generazione grafico 'Validity of Certificate Signatures'")
        result = dao.get_signature_validity_distribution()
        filename = os.path.abspath(f'{plots_path}/signature_validity_distribution.png')
        data = pd.DataFrame(list(result.items()), columns=['Signature Validity', 'Count'])
        data.set_index('Signature Validity', inplace=True)
        plotter.plot_bar_chart(
            data=data, 
            x=data.index, 
            y='Count', 
            title='Validity of Certificate Signatures', 
            xlabel='Number of Certificates', 
            ylabel='Signature Validity', 
            filename=filename
        )
        # plotter.plot_pie_chart(data, column='Count', title='Validity of Certificate Signatures', filename=filename)
        
    except Exception as e:
        logging.error(f"Errore nella generazione di un grafico: {e}")
    
    return
