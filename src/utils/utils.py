import json
import logging
import base64
import warnings
import argparse
import csv
import os
import aiohttp, asyncio
from db.database import DatabaseType
from typing import Optional, Tuple
from bean.certificate import Certificate
from rich.logging import RichHandler
from urllib.parse import urljoin
from tqdm.std import TqdmExperimentalWarning
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
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
        
        # Verifica se la chiave è RSA o ECDSA
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            # Per chiavi ECDSA
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(ca_public_key, rsa.RSAPublicKey):
            # Per chiavi RSA, determinare il padding corretto
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
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

async def make_ocsp_query(raw, issuer_certificate, alg, ocsp_link):
    """Costruisce e invia una richiesta OCSP per verificare lo stato di un certificato."""
    current_certificate = Certificate(raw).get_cert()
    
    if(current_certificate is None):
        logging.error("Impossibile eseguire la richiesta OCSP: il certificato non è presente")
        return None
    
    if(issuer_certificate is None):
        logging.error("Impossibile eseguire la richiesta OCSP: il certificato Issuer non è presente")
        return None
    
    async with aiohttp.ClientSession() as session:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(current_certificate, issuer_certificate, alg)
        req = builder.build()
        req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        final_url = urljoin(ocsp_link + '/', req_path.decode('ascii'))
        async with session.get(final_url, timeout=20) as response:
            try:
                result = "Impossible Retrieve OCSP Information"
                
                if response.status == 200:
                    ocsp_resp = await response.read()
                    ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp)
                    if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                        if ocsp_decoded.certificate_status == OCSPCertStatus.GOOD:
                            result = "Good"
                        elif ocsp_decoded.certificate_status == OCSPCertStatus.REVOKED:
                            result = "Revoked"
                        elif ocsp_decoded.certificate_status == OCSPCertStatus.UNKNOWN:
                            result = "Unknown"
                    else:
                        result = "Impossible Retrieve OCSP Information"
                else:
                    result = "Not Ok OCSP Response"

                return result
            except asyncio.TimeoutError:
                return "Impossible Retrieve OCSP Information"
            except aiohttp.ClientTimeout:
                return "Impossible Retrieve OCSP Information"
            except aiohttp.ClientResponseError as e:
                logging.error(f"Errore durante la richiesta OCSP per {final_url}: {e}")
                return "Impossible Retrieve OCSP Information"
            except Exception:
                logging.error(f"Errore durante la richiesta OCSP per {final_url}: {e}")
                return "Impossible Retrieve OCSP Information"

async def get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name):
    """Recupera e restituisce il certificato dell'emittente dal link fornito."""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(issuer_link, headers=headers, allow_redirects=True, timeout=20) as response:
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
                                if (cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == issuer_common_name):
                                    issuer_cert = cert

                            if(issuer_cert is None):
                                logging.error(f"Errore certificato non trovato durante il parsing del PKCS #7 ({issuer_link}): {e}")
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
        except aiohttp.ClientTimeout:
            return "Impossible Retrieve OCSP Information"
        except aiohttp.ClientResponseError as http_err:
            logging.error(f"Errore HTTP nel recupero del certificato ({issuer_link}): {http_err}")
            return "Impossible Retrieve OCSP Information"
        except Exception as e:
            logging.error(f"Errore nel recupero del certificato ({issuer_link}): {e}")
            return "Impossible Retrieve OCSP Information"
    
async def check_ocsp_status(raw, hash_alg, issuer_link, issuer_common_name, ocsp_link, issuer_cert) -> str:
    """Controlla l'OCSP, se il certificato dell'issuer è stato trovato nella catena si usa quello, altrimenti si richiede tramite issuer link."""
    
    # Se sia l'issuer certificate che l'issuer link non sono disponibili allora non è possibile fare richiesta
    if issuer_link is None and issuer_cert is None:
        return "No Issuer Url Found"
    
    # Prende l'issuer certificate dal link, ma potrebbe ritornare una stringa in caso di errore
    if(issuer_cert is None and issuer_link is not None):
        issuer_cert = await get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name)
    
        # Verifica se issuer_cert è una stringa di errore
        if(isinstance(issuer_cert, str)):
            return issuer_cert
    
    ocsp_resp = await make_ocsp_query(raw, issuer_cert, hash_alg, ocsp_link)
    return ocsp_resp
    
async def check_ocsp_status_row(row, certificate_type):
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
        
        ocsp_check = "No Issuer Url Found"
        if(issuer_url is not None or issuer_cert is not None):
            for ocsp_url in ocsp_urls:
                for hash_algorithm in hash_algorithms:
                    ocsp_check = await check_ocsp_status(leaf_cert_raw, hash_algorithm, issuer_url, issuer_common_name, ocsp_url, issuer_cert)
                    
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
        hash_algorithm, signing_algorithm = signature_algorithm.split('-')
        
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
                try:
                    serial_number_next = next_cert.get("parsed", {}).get("serial_number", "")
                    chain = list(filter(lambda cert: cert.get("parsed", {}).get("serial_number", "") != serial_number_next, chain))
                except ValueError:
                    pass
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
                try:
                    serial_number_next = next_cert.get("parsed", {}).get("serial_number", "")
                    chain = list(filter(lambda cert: cert.get("parsed", {}).get("serial_number", "") != serial_number_next, chain))
                except ValueError:
                    pass
                # Continua con la ricerca del root
                current_cert = next_cert
        else:
            return (count_intermediate, False)

async def update_certificates_ocsp_status_db(db, ocsp_temp_file, is_backup_file: bool = False, batch_size=1000):
    """Aggiorna lo stato OCSP dei certificati nel database."""
    update_values = []

    with open(ocsp_temp_file, mode="r", newline="") as ocsp_temp_file_csv:
        ocsp_temp_file_reader = csv.reader(ocsp_temp_file_csv)
        
        # Salta l'intestazione
        if(is_backup_file):
            logging.info("Inizio aggiornamento dei dati dal file di backup al database.")
            next(ocsp_temp_file_reader)
        else:
            logging.info("Inizio aggiornamento dei dati dal file temporaneo al database.")
        
        async with db.cursor() as cursor:
            for row in ocsp_temp_file_reader:
                update_values.append((row[0], int(row[1]), row[2]))
                
                if len(update_values) >= batch_size:
                    await cursor.executemany("""
                        UPDATE Certificates
                        SET ocsp_check = ?
                        WHERE certificate_id = ? AND leaf_domain = ?
                    """, update_values)
                    update_values.clear()
            
            # Inserisce eventuali righe rimanenti
            if update_values:
                await cursor.executemany("""
                    UPDATE Certificates
                    SET ocsp_check = ?
                    WHERE certificate_id = ? AND leaf_domain = ?
                """, update_values)
        
        await db.commit()
    
    # Cancella il file temporaneo
    os.remove(ocsp_temp_file)
    return
    
async def save_certificates_ocsp_status_file(db, ocsp_file, batch_size=10000, offset=0):
    """Salva lo stato OCSP dei certificati in un file CSV."""

    # Verifica se il file esiste e scrivi intestazioni solo se il file è vuoto
    write_header = not os.path.exists(ocsp_file)
    
    with open(ocsp_file, mode="a", newline="") as ocsp_file_csv:
        ocsp_file_writer = csv.writer(ocsp_file_csv)
        
        if write_header:
            ocsp_file_writer.writerow(['OCSP Check', 'Certificate Id', 'Leaf Domain'])
    
        while True:
            async with db.execute("""
                SELECT ocsp_check, certificate_id, leaf_domain
                FROM Certificates
                WHERE ocsp_check <> 'No Request Done'
                LIMIT ? OFFSET ?
                """, (batch_size, offset)) as cursor:
            
                # Prende tutti i record
                rows = await cursor.fetchall()

                # Se non ci sono più record, interrompe il ciclo
                if not rows:
                    break

                # Scrivi le righe nel file CSV
                ocsp_file_writer.writerows(rows)
                
                # Incrementa l'offset per il prossimo batch
                offset += batch_size
    
    return
    
