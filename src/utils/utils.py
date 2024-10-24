import logging
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature
from bean.certificate import Certificate
import base64
from urllib.parse import urljoin
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.ocsp import OCSPCertStatus
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

def verify_signature(leaf_cert: x509.Certificate, ca_cert: x509.Certificate):
    """Verifica la firma di un certificato leaf utilizzando il certificato della CA."""
    try:
        # Estrae la firma e i dati TBSCertificate
        signature = leaf_cert.signature
        tbs_cert_bytes = leaf_cert.tbs_certificate_bytes
        
        ca_public_key = ca_cert.public_key() # Estrae la chiave pubblica della CA
        
        # Verifica se la chiave è RSA o ECDSA
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            # Per chiavi ECDSA
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                ec.ECDSA(leaf_cert.signature_hash_algorithm)
            )
        elif isinstance(ca_public_key, rsa.RSAPublicKey):
            # Per chiavi RSA, determinare il padding corretto
            ca_public_key.verify(
                signature,
                tbs_cert_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm
            )
        else:
            return "Unsupported key type"

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

# TODO: forse è da eliminare perchè non è usato più
def get_issuer_cert_from_chain(chain, issuer_dn):
    """Cerca e restituisce il certificato raw dell'emittente corrispondente a un Distinguished Name (DN) nella catena di certificati."""
    for cert in chain:
        subject_dn = cert.get("parsed", {}).get("subject_dn", "")
        if(subject_dn == issuer_dn):
            return cert.get("raw", None)
    return None

def make_ocsp_query(raw, issuer_certificate, alg, ocsp_link):
    """Costruisce e invia una richiesta OCSP per verificare lo stato di un certificato."""
    digital_certificate = Certificate(raw).get_cert()
    
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(digital_certificate, issuer_certificate, alg)
    req = builder.build()
    req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
    final_url = urljoin(ocsp_link + '/', req_path.decode('ascii'))
    try:
        ocsp_resp = requests.get(final_url, timeout=15)
        return ocsp_resp
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Errore durante la richiesta OCSP per {final_url}: {e}")
        return None

def get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name):
    """Recupera e restituisce il certificato dell'emittente dal link fornito."""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'
    }
    
    try:
        req = requests.get(issuer_link, headers=headers, allow_redirects=True, timeout=15)
    except requests.exceptions.Timeout:
        return "Impossible Retrieve OCSP Information"
    except Exception as e:
        logging.error(f"Errore nel recupero del certificato ({issuer_link}): {e}")
        return "Impossible Retrieve OCSP Information"
    
    if req.status_code == 200:
        content_type = req.headers.get('Content-Type', '')

        if (
            "application/x-x509-ca-cert" in content_type or 
            "application/octet-stream" in content_type or 
            "application/pkix-cert" in content_type or
            content_type == ""
        ):
            try:
                issuer_cert = x509.load_der_x509_certificate(req.content, backend=default_backend())
                return issuer_cert
            except Exception as e:
                logging.error(f"Errore nel parsing del certificato DER ({issuer_link}): {e}")
                return "Impossible Retrieve OCSP Information"
        elif (
            "application/x-pem-file" in content_type or
            "text/plain" in content_type      
        ):
            try:
                pem_data = req.content.decode('utf-8')
                issuer_cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), backend=default_backend())
                return issuer_cert
            except Exception as e:
                logging.error(f"Errore nel parsing del certificato PEM ({issuer_link}): {e}")
                return "Impossible Retrieve OCSP Information"
        elif "application/pkcs7-mime" in content_type:
            try:
                pkcs7_data = req.content
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
        logging.error(f"Errore nel recupero del certificato ({issuer_link}). Stato: {req.status_code}")
        return "Impossible Retrieve OCSP Information"

def check_ocsp_status(raw, hash_alg, issuer_link, issuer_common_name, ocsp_link, issuer_cert) -> str:
    """Controlla l'OCSP, se il certificato dell'issuer è stato trovato nella catena si usa quello, altrimenti si richiede tramite issuer link."""
    
    # Prende l'issuer certificate dal link, ma potrebbe ritornare una stringa in caso di errore
    if(issuer_cert is None):
        issuer_cert = get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name)
    
    if(issuer_cert is str):
        return issuer_cert
    
    ocsp_resp = make_ocsp_query(raw, issuer_cert, hash_alg, ocsp_link)
    
    if(ocsp_resp is None):
        return "Impossible Retrieve OCSP Information"
    
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            if ocsp_decoded.certificate_status == OCSPCertStatus.GOOD:
                return "Good"
            elif ocsp_decoded.certificate_status == OCSPCertStatus.REVOKED:
                return "Revoked"
            elif ocsp_decoded.certificate_status == OCSPCertStatus.UNKNOWN:
                return "Unknown"
        else:
            return "Impossible Retrieve OCSP Information"
    else:
        return "Not Ok OCSP Response"
    
def reorder_signature_algorithm(signature_algorithm):
    if 'RSA' in signature_algorithm and '-' in signature_algorithm:
        hash_algorithm, signing_algorithm = signature_algorithm.split('-')
        
        return f"{signing_algorithm}-{hash_algorithm}"
    
    return signature_algorithm  