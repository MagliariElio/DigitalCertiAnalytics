import os
import logging
import json
import subprocess
import tempfile
from tqdm.rich import tqdm
from dao.certificate_dao import CertificateDAO
from bean.certificate import Certificate
from db.MongoDbDatabase import MongoDbDatabase
from db.database import DatabaseType

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

def count_zlint_results(zlint_result):
    """Contare il numero di occorrenze per ciascun tipo di risultato (pass, NA, NE, info)."""
    result_counts = {}
    
    # Scansiona il risultato JSON di ZLint
    if isinstance(zlint_result, dict):
        for key, value in zlint_result.items():
            if isinstance(value, dict) and 'result' in value:
                result_value = value['result']
                if result_value in result_counts:
                    result_counts[result_value] += 1
                else:
                    result_counts[result_value] = 1

    return result_counts


def save_to_mongodb(zlint_result, certificate_id, leaf_domain, common_name, organization, issuer_dn, db, error=False, error_message=None):
    try:
        if error:
            collection = db.get_collection('zlint_errors')
            error_document = {
                'certificate_id': certificate_id,
                'leaf_domain': leaf_domain,
                'error_message': error_message,
                'timestamp': logging.Formatter('%(asctime)s').format(logging.LogRecord('', '', '', '', '', '', ''))
            }
            collection.insert_one(error_document)
            logging.error(f"Errore durante l'elaborazione del certificato ID {certificate_id}: {error_message}")
        else:
            # Salva il risultato di ZLint
            collection = db.get_collection('zlint_results')
            
            results = {}
            results['count_results'] = count_zlint_results(zlint_result)
            results['certificate_id'] = certificate_id
            results['leaf_domain'] = leaf_domain
            results['issuer_common_name'] = common_name
            results['issuer_organization'] = organization
            results['issuer_dn'] = issuer_dn
            results['zlint_results'] = zlint_result
            
            collection.insert_one(results)
    except Exception as e:
        logging.error(f"Errore durante il salvataggio dei risultati in MongoDB: {e}")

def run_zlint_check(dao: CertificateDAO):
    """Funzione che esegue il controllo ZLint sui certificati e salva i risultati in MongoDB."""
    global pbar_zlint
    
    try:
        db = MongoDbDatabase(dao.get_certificate_type())
        
        total_lines = dao.get_certificates_count()
        
        remaining = total_lines - 8895002 # TODO: da rimuovere e rimettere total_lines in total        
        
        tqdm.write("")
        pbar_zlint = tqdm(total=remaining, desc=" 🔍  [magenta bold]Elaborazione Certificati[/magenta bold]", unit="cert.", 
                    colour="magenta", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")
        
        batch_size = 5000
        offset = 8895002 # TODO: da rimettere a 0
        
        # Percorso di zlint relativo alla directory del file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        zlint_path = os.path.join(base_dir, "../../zlint/v3/zlint")
        
        while(True):
            certificates = dao.get_raw_certificates(batch_size, offset)
            
            offset += batch_size
                
            if not certificates or len(certificates) == 0:
                break
        
            for certificate in certificates:
                certificate_id, leaf_domain, raw, common_name, organization, issuer_dn = certificate

                try:
                    # Crea un file temporaneo per il certificato raw
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        certificate_raw = Certificate(cert_string=raw).load_cert_from_string(raw)
                        temp_file.write(certificate_raw.encode())
                        temp_file_path = temp_file.name

                    command = [zlint_path, temp_file_path]
                    result = subprocess.run(command, capture_output=True, text=True)
                    
                    # Elimina il file temporaneo dopo l'uso
                    os.remove(temp_file_path)
                    
                    if result.returncode != 0:
                        error_message = f"Errore durante l'esecuzione di ZLint: {result.stderr}"
                        save_to_mongodb(None, certificate_id, leaf_domain, None, None, None, db, error=True, error_message=error_message)
                        continue
                    
                    # Analizza l'output JSON di ZLint
                    try:
                        zlint_result = json.loads(result.stdout)
                        save_to_mongodb(zlint_result, certificate_id, leaf_domain, common_name, organization, issuer_dn, db)
                        continue
                    except json.JSONDecodeError:
                        error_message = f"Errore nel decodificare l'output JSON di ZLint."
                        save_to_mongodb(None, certificate_id, leaf_domain, None, None, None, db, error=True, error_message=error_message)
                        continue
                except Exception as e:
                    error_message = f"Errore generale durante l'elaborazione: {str(e)}"
                    save_to_mongodb(None, certificate_id, leaf_domain, None, None, None, db, error=True, error_message=error_message)
                    continue
            
            # Aggiorna la barra di caricamento
            pbar_zlint.update(len(certificates))
    except Exception as e:
        logging.error(f"Errore durante l'esecuzione della funzione run_zlint_check: {str(e)}")
    except KeyboardInterrupt:
        logging.info(f"Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
    finally:
        pbar_zlint.close()
    return