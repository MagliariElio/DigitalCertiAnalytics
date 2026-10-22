import json
import logging
import base64
import warnings
import argparse
import csv
import os
import subprocess
from datetime import datetime, timezone
import aiohttp, asyncio, requests
from db.database import DatabaseType
from typing import Optional, Tuple
from bean.certificate import Certificate
from rich.logging import RichHandler
from urllib.parse import urljoin, quote
from tqdm.std import TqdmExperimentalWarning
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, ed25519, ed448
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.ocsp import OCSPCertStatus
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA224, SHA384, SHA512

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

# Numero massimo di richieste OCSP contemporanee: senza limite ogni batch aprirebbe decine di migliaia 
# di connessioni insieme, esaurendo i file descriptor e producendo falsi "Impossible Retrieve OCSP Information"
OCSP_MAX_CONCURRENT_REQUESTS = 200

# Timeout delle singole richieste HTTP verso i server OCSP e gli issuer
HTTP_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=20)

# Esito interno di make_ocsp_query per errori di rete o timeout: il server non risponde, quindi è inutile 
# riprovare con un altro algoritmo di hash sullo stesso URL (non viene mai salvato nel database)
OCSP_NETWORK_ERROR = "OCSP Network Error"

class ArgparseFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, *args, padding=1, **kwargs):
        super().__init__(*args, max_help_position=40, **kwargs)
        self.padding = padding

    def _format_action(self, action):
        result = super()._format_action(action)
        return ' ' * self.padding + result

    def format_help(self):
        help_text = super().format_help()
        return ' ' * self.padding + help_text.replace('\n', '\n' + ' ' * self.padding)

class CustomFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def format(self, record):
        original = super().format(record)
        return original

def setup_logging(is_verbose: bool):
    """Configura il logging dell'applicazione."""
    warnings.simplefilter("ignore", TqdmExperimentalWarning)
    
    formatter_file = CustomFormatter(
        fmt='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s',
    )
    
    formatter_stream = CustomFormatter(
        fmt='%(message)s',
    )
    
    file_handler = logging.FileHandler("app.log")
    file_handler.setFormatter(formatter_file)
    
    stream_handler = RichHandler(rich_tracebacks=True)
    stream_handler.setFormatter(formatter_stream)

    level = logging.INFO
    if(is_verbose):
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        datefmt="[%X]",
        handlers=[file_handler, stream_handler]
    )
    return

def verify_signature(cert: Optional[x509.Certificate], ca_cert: Optional[x509.Certificate]):
    """Verifica la firma di un certificato utilizzando il certificato issuer."""
    try:
        if(cert is None):
            logging.error("Impossibile verificare la firma: il certificato non è presente")
            return "Error"
        
        if(ca_cert is None):
            logging.error("Impossibile verificare la firma: il certificato Issuer non è presente")
            return "Error"
        
        # Estrae la firma e i dati TBSCertificate
        signature = cert.signature
        tbs_cert_bytes = cert.tbs_certificate_bytes
        
        # Estrae la chiave pubblica della CA
        ca_public_key = ca_cert.public_key()
        
        # Verifica se la chiave è RSA, ECDSA o EdDSA
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            # Per chiavi ECDSA
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(ca_public_key, rsa.RSAPublicKey):
            # Per chiavi RSA il padding dipende dall'algoritmo di firma del certificato (PKCS1v15 oppure RSASSA-PSS);
            # per alcuni algoritmi (es. md5WithRSAEncryption) cryptography non restituisce parametri e si usa PKCS1v15
            rsa_padding = cert.signature_algorithm_parameters
            if not isinstance(rsa_padding, (padding.PKCS1v15, padding.PSS)):
                rsa_padding = padding.PKCS1v15()
            
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                rsa_padding,
                cert.signature_hash_algorithm
            )
        elif isinstance(ca_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # Per chiavi EdDSA non è previsto un algoritmo di hash separato
            ca_public_key.verify(
                signature,
                tbs_cert_bytes
            )
        else:
            return "Unsupported Key Type"

        return "Valid"
    except InvalidSignature:
        return "Not Valid"
    except Exception as e:
        logging.error(f"Errore nella verifica del certificato: {e}")
        return "Error"
    
def find_raw_cert_issuer(chain, issuer_dn) -> Optional[str]:
    """Trova il certificato raw dell'emittente corrispondente in una catena di certificati."""
    if not isinstance(chain, list):
        logging.error("La catena deve essere una lista.")
        return None
    
    if not isinstance(issuer_dn, str):
        logging.error("L'issuer_dn deve essere una stringa.")
        return None

    for issuer in chain:
        parsed = issuer.get("parsed", {})
        subject_dn = parsed.get("subject_dn", "")
        if(subject_dn == issuer_dn):
            raw = issuer.get("raw", "")
            return raw
    return None

def check_certificate_chain(hostname: str) -> dict:
    """
        Esegue una scansione SSL utilizzando sslyze per ottenere le informazioni sul certificato e la catena,
        restituendo i risultati come dizionario Python senza scrivere su file.    
    """
    try:
        # Comando per eseguire sslyze con l'opzione --certinfo
        command = ['sslyze', '--certinfo', '--json_out', '-', hostname]

        # Esegui il comando con subprocess (con timeout per evitare che un host bloccato fermi l'intera analisi)
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)

        # Carica il risultato JSON direttamente dal stdout
        scan_results = json.loads(result.stdout)
        server_scan_results = scan_results.get("server_scan_results", [])
        
        if(len(server_scan_results) == 0):
            return 'Error'
        
        certificate_deployments = server_scan_results[0].get("scan_result", {}).get("certificate_info", {}).get("result", {}).get("certificate_deployments", [])

        if(len(certificate_deployments) == 0):
            return 'Error'
        
        path_validation_results = certificate_deployments[0].get("path_validation_results", [])
        
        for result in path_validation_results:
            if(result.get("was_validation_successful", False) == True):
                return 'Valid'

        return 'Not Valid'
    except subprocess.CalledProcessError as e:
        logging.error(f"Errore durante l'esecuzione di sslyze: {e.stderr}")
        return 'Error'
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout durante l'esecuzione di sslyze per l'hostname {hostname}")
        return 'Error'
    except json.JSONDecodeError as e:
        logging.error(f"Errore nel decodificare l'output JSON: {e}")
        return 'Error'
    except Exception as e:
        logging.error(f"Si è verificato un errore durante la verifica del certificate chain per l'hostname {hostname} : {e}")
        return 'Error'


def check_is_revoked_from_crl(cert: x509.Certificate, crl_distribution_points_urls):
    """Dalla lista di URL in input, invia una o più richieste per verificare lo stato di revoca."""

    try:
        if(len(crl_distribution_points_urls) == 0):
            return 'No CRL Distribution Points'
        
        for crl_url in crl_distribution_points_urls:
            response = requests.get(crl_url, timeout=10)
            response.raise_for_status()
            crl = x509.load_der_x509_crl(response.content, default_backend())
            
            # Controllo della scadenza della CRL (next_update è opzionale)
            next_update = crl.next_update_utc
            if next_update is not None and next_update < datetime.now(timezone.utc):
                return 'CRL expired'
            
            # Il certificato è revocato se compare in almeno una delle CRL
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                return 'Revoked'
        return 'Good'
    except Exception as e:
        logging.error(f"Errore durante la verifica nel CRL list: {e}")
        return 'Error'

async def make_ocsp_query(raw, issuer_certificate, alg, ocsp_link, session: aiohttp.ClientSession):
    """Costruisce e invia una richiesta OCSP per verificare lo stato di un certificato."""
    current_certificate = Certificate(raw).get_cert()
    
    if(current_certificate is None):
        logging.error("Impossibile eseguire la richiesta OCSP: il certificato non è presente")
        return "Impossible Retrieve OCSP Information"
    
    if(issuer_certificate is None):
        logging.error("Impossibile eseguire la richiesta OCSP: il certificato Issuer non è presente")
        return "Impossible Retrieve OCSP Information"
    
    final_url = ocsp_link
    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(current_certificate, issuer_certificate, alg)
        req = builder.build()
        
        # La richiesta codificata in base64 deve essere anche codificata per l'URL ('+', '/' e '=') come da RFC 6960, Appendice A.1
        req_path = quote(base64.b64encode(req.public_bytes(serialization.Encoding.DER)).decode('ascii'), safe='')
        final_url = urljoin(ocsp_link + '/', req_path)
        
        async with session.get(final_url, timeout=HTTP_REQUEST_TIMEOUT) as response:
            if response.status != 200:
                return "Not Ok OCSP Response"
            
            ocsp_resp = await response.read()
        
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            if ocsp_decoded.certificate_status == OCSPCertStatus.GOOD:
                return "Good"
            elif ocsp_decoded.certificate_status == OCSPCertStatus.REVOKED:
                return "Revoked"
            elif ocsp_decoded.certificate_status == OCSPCertStatus.UNKNOWN:
                return "Unknown"
        
        return "Impossible Retrieve OCSP Information"
    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
        # Errori di rete o timeout: si potrà riprovare con un altro URL OCSP
        logging.debug(f"Errore di rete durante la richiesta OCSP per {final_url}: {e}")
        return OCSP_NETWORK_ERROR
    except ValueError as e:
        # Risposta OCSP non valida: si potrà riprovare con un altro algoritmo di hash o un altro URL
        logging.debug(f"Risposta OCSP non valida per {final_url}: {e}")
        return "Impossible Retrieve OCSP Information"
    except Exception as e:
        logging.error(f"Errore durante la richiesta OCSP per {final_url}: {e}")
        return "Impossible Retrieve OCSP Information"

async def get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name, session: aiohttp.ClientSession):
    """Recupera e restituisce il certificato dell'emittente dal link fornito."""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'
    }
    
    try:
        async with session.get(issuer_link, headers=headers, allow_redirects=True, timeout=HTTP_REQUEST_TIMEOUT) as response:
            if response.status == 200:
                content_type = response.headers.get('Content-Type', '')
    
                if (
                    "application/x-x509-ca-cert" in content_type or
                    "application/octet-stream" in content_type or
                    "binary/octet-stream" in content_type or
                    "application/pkix-cert" in content_type or
                    content_type == ""
                ):
                    try:
                        content = await response.read()
                        
                        # Verifica se il contenuto è in formato DER o PEM
                        if content.startswith(b"-----BEGIN CERTIFICATE-----"):
                            # È un certificato PEM
                            pem_data = content.decode('utf-8')
                            issuer_cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), backend=default_backend())
                        else:
                            # Tentativo di caricare come certificato DER
                            issuer_cert = x509.load_der_x509_certificate(content, backend=default_backend())

                        return issuer_cert
                    except Exception as e:
                        logging.error(f"Errore nel parsing del certificato DER ({issuer_link}): {e}")
                        return "Impossible Retrieve OCSP Information"
                elif (
                    "application/x-pem-file" in content_type or
                    "text/plain" in content_type      
                ):
                    try:
                        pem_data = await response.text()
                        issuer_cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), backend=default_backend())
                        return issuer_cert
                    except Exception as e:
                        logging.error(f"Errore nel parsing del certificato PEM ({issuer_link}): {e}")
                        return "Impossible Retrieve OCSP Information"
                elif (
                    "application/pkcs7-mime" in content_type or 
                    "application/x-pkcs7-certificates" in content_type
                ):
                    try:
                        pkcs7_data = await response.read()
                        issuer_certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                        
                        issuer_cert = None
                        for cert in issuer_certs:
                            # Alcuni certificati del bundle potrebbero non avere un Common Name
                            common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                            if (len(common_names) > 0 and common_names[0].value == issuer_common_name):
                                issuer_cert = cert

                        if(issuer_cert is None):
                            logging.error(f"Errore certificato non trovato durante il parsing del PKCS #7 ({issuer_link})")
                            return "Impossible Retrieve OCSP Information"    
                        return issuer_cert
                    except Exception as e:
                        logging.error(f"Errore nel parsing del PKCS #7 ({issuer_link}): {e}")
                        return "Impossible Retrieve OCSP Information"
                else:
                    logging.error(f"Formato del certificato sconosciuto ({issuer_link}): {content_type}")
                    return "Impossible Retrieve OCSP Information"
            else:
                logging.error(f"Errore nel recupero del certificato ({issuer_link}). Stato: {response.status}")
                return "Impossible Retrieve OCSP Information"
    
    except asyncio.TimeoutError:
        return "Impossible Retrieve OCSP Information"
    except aiohttp.ClientError as http_err:
        logging.error(f"Errore HTTP nel recupero del certificato ({issuer_link}): {http_err}")
        return "Impossible Retrieve OCSP Information"
    except Exception as e:
        logging.error(f"Errore nel recupero del certificato ({issuer_link}): {e}")
        return "Impossible Retrieve OCSP Information"

async def check_ocsp_status(raw, hash_alg, issuer_link, issuer_common_name, ocsp_link, issuer_cert, session: aiohttp.ClientSession) -> str:
    """Controlla l'OCSP, se il certificato dell'issuer è stato trovato nella catena si usa quello, altrimenti si richiede tramite issuer link."""
    
    # Se sia l'issuer certificate che l'issuer link non sono disponibili allora non è possibile fare richiesta
    if issuer_link is None and issuer_cert is None:
        return "No Issuer Url Found"
    
    # Prende l'issuer certificate dal link, ma potrebbe ritornare una stringa in caso di errore
    if(issuer_cert is None and issuer_link is not None):
        issuer_cert = await get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name, session)
    
        # Verifica se issuer_cert è una stringa di errore
        if(isinstance(issuer_cert, str)):
            return issuer_cert
    
    ocsp_resp = await make_ocsp_query(raw, issuer_cert, hash_alg, ocsp_link, session)
    return ocsp_resp
    
async def check_ocsp_status_row(row, certificate_type, session: aiohttp.ClientSession):
    """Controlla lo stato OCSP per un certificato specificato in una riga del database."""
    
    certificate_id = None
    leaf_domain = None
                        
    try:
        certificate_id = row['certificate_id']
        leaf_domain = row['leaf_domain']
        
        aia = row['authority_info_access']
        aia = json.loads(aia)
        
        issuer_urls = aia.get("issuer_urls", [])
        issuer_url = next(iter(issuer_urls), None)

        ocsp_urls = aia.get("ocsp_urls", [])

        hash_algorithms = [SHA256(), SHA1(), SHA384(), SHA512(), SHA224()]
        
        # Prende il certificato del leaf per controllare l'OCSP
        digital_certificate = Certificate(None)
        leaf_cert_raw = row['leaf_cert_raw']
        
        # Prende il certificato dell'issuer per controllare l'OCSP
        if(certificate_type == DatabaseType.ROOT):
            issuer_cert = digital_certificate.get_certificate_from_raw(leaf_cert_raw)
        else:
            issuer_cert_raw = row['issuer_cert_raw']
            issuer_cert = digital_certificate.get_certificate_from_raw(issuer_cert_raw)
        
        issuer_common_name = row['common_name']
        
        if(issuer_url is None and issuer_cert is None):
            return ("No Issuer Url Found", certificate_id, leaf_domain)
        
        if(len(ocsp_urls) == 0):
            return ("No OCSP Url Found", certificate_id, leaf_domain)
        
        # Scarica una sola volta il certificato dell'issuer se non è presente nel database, 
        # invece di ripetere il download per ogni URL OCSP e per ogni algoritmo di hash
        if(issuer_cert is None):
            issuer_cert = await get_issuer_certificate_from_issuer_link(issuer_url, issuer_common_name, session)
            
            # In caso di errore viene restituita una stringa
            if(isinstance(issuer_cert, str)):
                return (issuer_cert, certificate_id, leaf_domain)
        
        ocsp_check = "Impossible Retrieve OCSP Information"
        for ocsp_url in ocsp_urls:
            for hash_algorithm in hash_algorithms:
                ocsp_check = await check_ocsp_status(leaf_cert_raw, hash_algorithm, issuer_url, issuer_common_name, ocsp_url, issuer_cert, session)
                
                # Server OCSP non raggiungibile: passa direttamente al prossimo URL
                if(ocsp_check == OCSP_NETWORK_ERROR):
                    ocsp_check = "Impossible Retrieve OCSP Information"
                    break
                
                if(ocsp_check != "Impossible Retrieve OCSP Information"):
                    break
            
            if(ocsp_check != "Impossible Retrieve OCSP Information"):
                break
                
        return (ocsp_check, certificate_id, leaf_domain)
    except Exception as e:
        # logging.error(f"Errore durante il controllo dello stato OCSP per il certificato ID {certificate_id}: {e}")
        # traceback.print_exc()
        return ("Impossible Retrieve OCSP Information", certificate_id, leaf_domain)
    
def reorder_signature_algorithm(signature_algorithm):
    """Riorganizza l'algoritmo di firma nel formato 'signing-hash' se è un algoritmo RSA."""
    if 'RSA' in signature_algorithm and '-' in signature_algorithm:
        hash_algorithm, signing_algorithm = signature_algorithm.split('-', 1)
        
        return f"{signing_algorithm}-{hash_algorithm}"
    return signature_algorithm

def find_next_intermediate_certificate(chain, current_cert) -> Optional[str]:
    """
        Trova il prossimo certificato intermedio nella catena partendo dal certificato corrente.
        Restituisce None se il certificato corrente è un certificato root
        o se non ci sono certificati intermedi nella catena.
    """
    if len(chain) == 0:
        return None
    
    # Prende i dati del certificato corrente
    subject_dn = current_cert.get("parsed", {}).get("subject_dn", "")
    issuer_dn = current_cert.get("parsed", {}).get("issuer_dn", "")
    is_self_signed = current_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
    
    # Controlla se è il certificato corrente sia root
    if is_self_signed and subject_dn == issuer_dn:
        return None
    
    # Cerca il certificato successivo nella catena
    next_cert = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
    
    if(next_cert is None):
        return None
    
    subject_dn = next_cert.get("parsed", {}).get("subject_dn", "")
    issuer_dn = next_cert.get("parsed", {}).get("issuer_dn", "")
    is_self_signed = next_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
    
    # Controlla se è un certificato root
    if is_self_signed and subject_dn == issuer_dn:
        return None
    
    return next_cert

def count_certificates_to_root(chain_list: list, current_cert) -> Tuple[Optional[str], int]:
    """
        Trova il certificato radice nella catena partendo dal certificato corrente e conta quanti certificati ci sono 
        dalla foglia fino al certificato radice.
        Restituisce il certificato radice se trovato, altrimenti None.
    """
    chain = chain_list.copy()
    
    if len(chain) == 0:
        return (None, 0)
    
    certificates_emitted_up_to = 0  # Conta il numero di certificati intermedi trovati nella catena fino al root + certificato leaf
    while True:
        # Prende i dati del certificato corrente
        subject_dn = current_cert.get("parsed", {}).get("subject_dn", "")
        issuer_dn = current_cert.get("parsed", {}).get("issuer_dn", "")
        is_self_signed = current_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
        
        # Cerca il certificato successivo nella catena
        next_cert = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
        
        if next_cert:
            subject_dn = next_cert.get("parsed", {}).get("subject_dn", "")
            issuer_dn = next_cert.get("parsed", {}).get("issuer_dn", "")
            is_self_signed = next_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
        
            # Controlla se è un certificato root
            if is_self_signed and subject_dn == issuer_dn:
                return (next_cert, certificates_emitted_up_to)
            else:
                # Rimuove dalla catena il certificato appena visitato (per identità e non per numero di serie)
                chain = [cert for cert in chain if cert is not next_cert]
                # Continua con la ricerca del root
                current_cert = next_cert
                certificates_emitted_up_to += 1     # Altro certificato intermediate trovato
        else:
            return (None, 0)

def count_intermediate_up_to_root_and_root_certificates(chain_list:list, current_cert: dict) -> Tuple[int, int]:
    """
    Conta nella catena, il numero di certificati intermedi rimanenti fino al certificato root e indica se è presente il certificato radice.
    
    Args:
        chain_list (List[Dict]): Lista di certificati nella catena.
        current_cert (Dict): Il certificato corrente da analizzare.

    Returns:
        Tuple[int, int] 
            - Il numero di certificati intermedi trovati.
            - True se è presente il certificato root nella catena, altrimenti False.
    """
    
    count_intermediate = 0
    chain = chain_list.copy()

    # Se la lista è vuota allora non è presente nessun intermediate e root
    if(len(chain) == 0):
        return (0, False)
    
    while True:
        # Prende i dati del certificato corrente
        subject_dn = current_cert.get("parsed", {}).get("subject_dn", "")
        issuer_dn = current_cert.get("parsed", {}).get("issuer_dn", "")
        is_self_signed = current_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
        
        # Cerca il certificato successivo nella catena
        next_cert = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
        
        if next_cert:
            subject_dn = next_cert.get("parsed", {}).get("subject_dn", "")
            issuer_dn = next_cert.get("parsed", {}).get("issuer_dn", "")
            is_self_signed = next_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
        
            # Controlla se è un certificato root
            if is_self_signed and subject_dn == issuer_dn:
                return (count_intermediate, True)
            else:
                # Certificato Intermediate trovato 
                count_intermediate += 1
                # Rimuove dalla catena il certificato appena visitato (per identità e non per numero di serie)
                chain = [cert for cert in chain if cert is not next_cert]
                # Continua con la ricerca del root
                current_cert = next_cert
        else:
            return (count_intermediate, False)

async def update_certificates_ocsp_status_db(db, ocsp_temp_file, is_backup_file: bool = False):
    """Aggiorna lo stato OCSP dei certificati nel database."""

    with open(ocsp_temp_file, mode="r", newline="") as ocsp_temp_file_csv:
        ocsp_temp_file_reader = csv.reader(ocsp_temp_file_csv)
        
        # Salta l'intestazione (il file di backup potrebbe anche essere vuoto)
        if(is_backup_file):
            logging.info("Inizio aggiornamento dei dati dal file di backup al database.")
            next(ocsp_temp_file_reader, None)
        else:
            logging.info("Inizio aggiornamento dei dati dal file temporaneo al database.")
        
        try:
            # Con journal_mode = OFF il ROLLBACK eseguito in caso di errore non è supportato e può corrompere il database:
            # il journal in memoria mantiene prestazioni simili garantendo il rollback
            await db.execute("PRAGMA journal_mode = MEMORY")
            await db.execute("PRAGMA synchronous = OFF")
            await db.execute("PRAGMA temp_store = MEMORY")
                
            async with db.cursor() as cursor:
                await cursor.execute("BEGIN TRANSACTION")

                logging.info("Creazione Indice per l'aggiornamento massiccio!")
                await cursor.executescript("""
                    CREATE INDEX IF NOT EXISTS idx_certificate_id_leaf_domain ON Certificates(certificate_id, leaf_domain);
                """)
                
                logging.info("Creazione Tabella temporanea")
                await cursor.execute("""
                    CREATE TEMPORARY TABLE IF NOT EXISTS TempOCSP (
                        certificate_id INT,
                        ocsp_check VARCHAR(36),
                        leaf_domain VARCHAR
                    );
                """)
                
                logging.info("Inizio inserimento nel database!")
                insert_query = """
                    INSERT INTO TempOCSP (certificate_id, ocsp_check, leaf_domain)
                    VALUES (?, ?, ?)
                """
                batch_size = 50000
                batch = []
                for row in ocsp_temp_file_reader:
                    # Ignora le righe incomplete (es. ultima riga troncata se il programma è stato interrotto durante la scrittura)
                    if(len(row) < 3 or not row[1].isdigit()):
                        logging.warning(f"Riga non valida ignorata nel file '{ocsp_temp_file}': {row}")
                        continue
                    
                    batch.append((int(row[1]), row[0], row[2]))
                    
                    # Inserimento a blocchi per evitare un round-trip verso il database per ogni riga
                    if(len(batch) >= batch_size):
                        await cursor.executemany(insert_query, batch)
                        batch = []
                
                if(len(batch) > 0):
                    await cursor.executemany(insert_query, batch)
                
                # Senza indice ogni certificato richiederebbe la scansione dell'intera tabella temporanea (costo quadratico)
                await cursor.execute("CREATE INDEX IF NOT EXISTS idx_temp_ocsp ON TempOCSP(certificate_id, leaf_domain);")
            
                logging.info("Inizio aggiornamento dei dati nella tabella!")
                await cursor.execute("""
                    UPDATE Certificates
                    SET ocsp_check = (
                        SELECT ocsp_check
                        FROM TempOCSP
                        WHERE Certificates.certificate_id = TempOCSP.certificate_id
                        AND Certificates.leaf_domain = TempOCSP.leaf_domain
                    )
                    WHERE EXISTS (
                        SELECT 1
                        FROM TempOCSP
                        WHERE Certificates.certificate_id = TempOCSP.certificate_id
                        AND Certificates.leaf_domain = TempOCSP.leaf_domain
                    )
                """)
                
                logging.info("Eliminazione della tabella temporanea!")
                await cursor.execute("DROP TABLE IF EXISTS TempOCSP")
                
                await db.commit()
                
                await db.execute("PRAGMA journal_mode = DELETE")
                await db.execute("PRAGMA synchronous = FULL")
                await db.execute("PRAGMA temp_store = FILE")
        except Exception as e:
            await db.rollback()
            raise e
            
    # Cancella il file temporaneo (il file di backup viene invece mantenuto finché non ne viene scritto uno nuovo)
    if(not is_backup_file):
        os.remove(ocsp_temp_file)
    return
    
async def save_certificates_ocsp_status_file(db, ocsp_file, batch_size=10000):
    """Salva lo stato OCSP dei certificati in un file CSV."""

    # Il nuovo backup viene scritto in un file temporaneo e sostituito a quello precedente solo a scrittura completata
    ocsp_file_temp = f"{ocsp_file}.tmp"
    
    with open(ocsp_file_temp, mode="w", newline="") as ocsp_file_csv:
        ocsp_file_writer = csv.writer(ocsp_file_csv)
        ocsp_file_writer.writerow(['OCSP Check', 'Certificate Id', 'Leaf Domain'])
    
        # Un'unica query letta a blocchi: con LIMIT/OFFSET ogni batch dovrebbe riscandire tutte le righe precedenti
        async with db.execute("""
            SELECT ocsp_check, certificate_id, leaf_domain
            FROM Certificates
            WHERE ocsp_check <> 'No Request Done'
            """) as cursor:
            
            while True:
                rows = await cursor.fetchmany(batch_size)

                # Se non ci sono più record, interrompe il ciclo
                if not rows:
                    break

                # Scrivi le righe nel file CSV
                ocsp_file_writer.writerows(rows)
    
    os.replace(ocsp_file_temp, ocsp_file)
    return
    
