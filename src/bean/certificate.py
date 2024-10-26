import base64
import logging
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from typing import Optional

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class Certificate:
    def __init__(self, cert_string):
        self.cert_string = cert_string
        self.cert = self.get_certificate_from_raw(cert_string)

    def get_cert(self):
        return self.cert

    def load_cert_from_string(self, raw):
        """Crea una stringa PEM da un certificato raw."""
        if(raw is None):
            return None
        
        # Aggiungi le intestazioni PEM
        pem = f"-----BEGIN CERTIFICATE-----\n{raw}\n-----END CERTIFICATE-----"
        return pem

    def get_certificate_from_raw(self, raw):
        """Carica il certificato da una stringa."""
        if(raw is None):
            return None
        
        try:
            # Aggiungi le intestazioni PEM
            pem = self.load_cert_from_string(raw)
            
            # Decodifica la stringa PEM e carica il certificato
            cert_bytes = pem.encode('utf-8')
            return x509.load_pem_x509_certificate(cert_bytes, default_backend())
        except Exception as e:
            logging.error(f"Certificato non valido, errore nel parsing: {e}")
            return None

    def is_aia_critical(self, issuer):
        """Controlla se l'AIA è critico, non critico o non trovato."""
        try:
            aia_ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if aia_ext is None:
                return "Not Found"
            
            return "Critical" if aia_ext.critical else "Not Critical"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo AIA ({issuer}): {e}")
            return "Error"
    
    def get_cp(self) -> Optional[list[dict]]:
        """Restituisce il certificate policies relativo al certificato"""
        try:
            cp_ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            policies = []

            for policy_info in cp_ext.value:
                policy = {
                    'policy_identifier': policy_info.policy_identifier.dotted_string,
                    'cps': policy_info.policy_qualifiers,  
                    'policy_qualifiers': policy_info.policy_qualifiers,  
                    'is_cp_critical': "Critical" if cp_ext.critical else "Not Critical"  
                }
                policies.append(policy)

            return policies
        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            logging.error(f"Errore imprevisto nel recupero delle CERTIFICATE_POLICIES: {e}")
            return None
        
    def is_crl_distr_point_critical(self):
        """Controlla se il crl distribution point sia critico, non critico o non trovato."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            if ext is None:
                return "Not Found"
            
            return "Critical" if ext.critical else "Not Critical"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo Crl Distr Point: {e}")
            return "Error"
    
    def is_key_usage_critical(self):
        """Controlla se il key usage sia critico, non critico o non trovato."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            if ext is None:
                return "Not Found"
            
            return "Critical" if ext.critical else "Not Critical"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo Key Usage: {e}")
            return "Error"
        
    def is_extended_key_usage_critical(self):
        """Controlla se l'extended key usage sia critico, non critico o non trovato."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            if ext is None:
                return "Not Found"
            
            return "Critical" if ext.critical else "Not Critical"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo Extended Key Usage: {e}")
            return "Error"
    
    def is_sub_alt_name_critical(self):
        """Controlla se il subject alternative name sia critico, non critico o non trovato."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if ext is None:
                return "Not Found"
            
            return "Critical" if ext.critical else "Not Critical"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo Sub Alt Name: {e}")
            return "Error"
    
    def is_ocsp_must_staple(self):
        """Controlla se l'OCSP must staple sia abilitato o meno."""
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            if ext is None:
                return "Not Found"
            
            return "Enabled"
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo OCSP must stapling: {e}")
            return "Error"