import json
import logging
from typing import Optional
from datetime import datetime
from bean.certificate import Certificate
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.ocsp import OCSPCertStatus
from base64 import b64decode, b64encode
import base64
from urllib.parse import urljoin
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA224, SHA384, SHA512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.extensions import UserNotice

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class CertificateDAO:
    def __init__(self, connection):
        self.conn = connection
        self.cursor = self.conn.cursor()

    def insert_error_row(self, json_row):
        """Inserisce un errore nel database."""
        domain = json_row.get("domain", "")
        tls = json_row.get("data", {}).get("tls", {})
        
        status = tls.get("status", "")
        protocol = tls.get("protocol", "")
        timestamp = tls.get("timestamp", "")
        error_message = tls.get("error", "")
        download_date = tls.get("timestamp", "")

        self.cursor.execute('''
            INSERT INTO Errors (domain, status, protocol, timestamp, error_message, download_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (domain, status, protocol, timestamp, error_message, download_date))
        logging.debug(f"Errore inserito per dominio: {domain}")

    def _get_issuer_cert_from_chain(self, chain, issuer_dn):
        for cert in chain:
            subject_dn = cert.get("parsed", {}).get("subject_dn", "")
            if(subject_dn == issuer_dn):
                return cert.get("raw", None)
        return None

    def insert_issuer(self, parsed, digital_certificate: Certificate, chain) -> int:
        """Inserisce un issuer nel database e restituisce l'issuer_id."""
        issuer = parsed.get("issuer", {})
        
        issuer_dn = parsed.get("issuer_dn", "")
        issuer_common_name = ', '.join(issuer.get("common_name", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_organization = ', '.join(issuer.get("organization", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_country = ', '.join(issuer.get("country", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_locality = ', '.join(issuer.get("locality", []))
        issuer_province = ', '.join(issuer.get("province", []))
        issuer_organizational_unit = ', '.join(issuer.get("organizational_unit", []))

        extensions = parsed.get("extensions", {})        

        authority_key_id = extensions.get("authority_key_id", "")
        aia = extensions.get("authority_info_access", {})
        authority_info_access = aia

        authority_info_access_is_critical = digital_certificate.is_aia_critical(issuer_common_name)

        issuer_urls = aia.get("issuer_urls", [])
        issuer_url = next(iter(issuer_urls), None)
        ocsp_urls = aia.get("ocsp_urls", [])

        hash_algorithms = [SHA256(), SHA1(), SHA224(), SHA384(), SHA512()]
        
        # Prende il certificato dell'issuer per controllare l'OCSP
        issuer_cert_raw = self._get_issuer_cert_from_chain(chain, issuer_dn)
        issuer_cert = digital_certificate.get_certificate_from_raw(issuer_cert_raw)
        
        ocsp_check = "No Request Done"
        
        # TODO: rimuovere il commento quando si deve analizzare questa parte
        """
        ocsp_check = "No Issuer Url Found"
        if(issuer_url is not None and issuer_cert is not None):
            for ocsp_url in ocsp_urls:
                for hash_algorithm in hash_algorithms:
                    ocsp_check = self._ocsp_check(raw, hash_algorithm, issuer_url, issuer_common_name, ocsp_url, issuer_cert)
                    
                    if(ocsp_check != "Impossible Retrieve OCSP Information"):
                        break
                
                if(ocsp_check != "Impossible Retrieve OCSP Information"):
                        break
        """

        self.cursor.execute("""
            INSERT INTO Issuers (common_name, organization, country, issuer_dn, locality, province, organizational_unit,
            authority_key_id, authority_info_access_is_critical, authority_info_access, ocsp_check)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(issuer_dn) DO UPDATE SET
            common_name=excluded.common_name,
            organization=excluded.organization,
            country=excluded.country,
            locality=excluded.locality,
            province=excluded.province,
            organizational_unit=excluded.organizational_unit,
            authority_key_id=excluded.authority_key_id,
            authority_info_access_is_critical=excluded.authority_info_access_is_critical,
            authority_info_access=excluded.authority_info_access,
            ocsp_check=excluded.ocsp_check
        """, (
            issuer_common_name, issuer_organization, issuer_country, issuer_dn, issuer_locality, issuer_province, issuer_organizational_unit, 
              authority_key_id, authority_info_access_is_critical, json.dumps(authority_info_access), ocsp_check
        ))

        logging.debug(f"Issuer inserito/aggiornato: {issuer_dn}")
        return self.cursor.lastrowid

    def _make_ocsp_query(self, raw, issuer_certificate, alg, ocsp_link):
        digital_certificate = Certificate(raw).get_cert()
        
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(digital_certificate, issuer_certificate, alg)
        req = builder.build()
        req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        final_url = urljoin(ocsp_link + '/', req_path.decode('ascii'))
        ocsp_resp = requests.get(final_url)
        return ocsp_resp
    
    def _get_issuer_certificate_from_issuer_link(self, issuer_link, issuer_common_name):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'
        }
        
        try:
            req = requests.get(issuer_link, headers=headers, allow_redirects=True)
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
    
    def _ocsp_check(self, raw, hash_alg, issuer_link, issuer_common_name, ocsp_link, issuer_cert) -> str:
        # Controlla l'OCSP, se il certificato dell'issuer è stato trovato nella catena si usa quello, altrimenti si richiede tramite issuer link
        
        # Prende l'issuer certificate dal link, ma potrebbe ritornare una stringa in caso di errore
        if(issuer_cert is None):
            issuer_cert = self._get_issuer_certificate_from_issuer_link(issuer_link, issuer_common_name)
        
        if(issuer_cert is str):
            return issuer_cert
        
        ocsp_resp = self._make_ocsp_query(raw, issuer_cert, hash_alg, ocsp_link)
        
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

    def insert_subject(self, parsed, digital_certificate: Certificate) -> int:
        """Inserisce un subject nel database e restituisce il subject_id."""
        subject = parsed.get("subject", {})
        
        subject_common_name = ', '.join(subject.get("common_name", []))
        subject_dn = parsed.get("subject_dn", "")
        subject_key_id = parsed.get("extensions", {}).get("subject_key_id", "")
        subject_alt_name = json.dumps(parsed.get("extensions", {}).get("subject_alt_name", {}))
        subject_alt_name_is_critical = digital_certificate.is_sub_alt_name_critical()

        self.cursor.execute("""
            INSERT INTO Subjects (common_name, subject_dn, subject_key_id, subject_alt_name, subject_alt_name_is_critical)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(subject_dn) DO UPDATE SET
            common_name=excluded.common_name,
            subject_key_id=excluded.subject_key_id,
            subject_alt_name=excluded.subject_alt_name,
            subject_alt_name_is_critical=excluded.subject_alt_name_is_critical
        """, (subject_common_name, subject_dn, subject_key_id, subject_alt_name, subject_alt_name_is_critical))

        logging.debug(f"Subject inserito/aggiornato: {subject_dn}")
        return self.cursor.lastrowid

    def _reorder_signature_algorithm(self, signature_algorithm):
        if 'RSA' in signature_algorithm and '-' in signature_algorithm:
            hash_algorithm, signing_algorithm = signature_algorithm.split('-')
            
            return f"{signing_algorithm}-{hash_algorithm}"
        
        return signature_algorithm  

    def insert_certificate(self, json_row, parsed, issuer_id, subject_id) -> Optional[int]:
        """Inserisce un certificato nel database e restituisce il certificate_id."""
        download_date = json_row.get("data", {}).get("tls", {}).get("timestamp", datetime.now().isoformat())
        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        ocsp_stapling = handshake_log.get("server_hello", {}).get("ocsp_stapling", False)

        serial_number = parsed.get("serial_number", "")
        domain = json_row.get("domain", "")
        version = parsed.get("version", 0)
        signature_algorithm = parsed.get("signature_algorithm", {}).get("name", "")
        signature_algorithm = self._reorder_signature_algorithm(signature_algorithm)
        key_algorithm = parsed.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "")
        
        key_length = parsed.get("subject_key_info", {}).get("rsa_public_key", {}).get("length", 0)
        if(key_length == 0):
            key_length = parsed.get("subject_key_info", {}).get("ecdsa_public_key", {}).get("length", 0)

        validity_start = parsed.get("validity", {}).get("start", "")
        validity_end = parsed.get("validity", {}).get("end", "")
        validity_length = parsed.get("validity", {}).get("length", "")
        validation_level = parsed.get("validation_level", "")
        redacted = parsed.get("redacted", False)
        signature_valid = parsed.get("signature", {}).get("valid", False)
        self_signed = parsed.get("signature", {}).get("self_signed", False)
        raw = handshake_log.get("server_certificates", {}).get("certificate", {}).get("raw", {})
        
        digital_certificate = Certificate(raw)
        ocsp_must_stapling = digital_certificate.is_ocsp_must_staple()
        
        self.cursor.execute("""
            INSERT INTO Certificates (
                serial_number, domain, version, signature_algorithm, key_algorithm, key_length, 
                validity_start, validity_end, validity_length, issuer_id, 
                subject_id, validation_level, redacted, signature_valid, self_signed, download_date, 
                ocsp_stapling, ocsp_must_stapling, raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(serial_number) DO NOTHING
        """, (
            serial_number, domain, version, signature_algorithm, key_algorithm, key_length,
            validity_start, validity_end, validity_length, issuer_id,
            subject_id, validation_level, redacted, signature_valid, self_signed, download_date, 
            ocsp_stapling, ocsp_must_stapling, raw
        ))

        logging.debug(f"Certificato inserito: {serial_number}")
        return self.cursor.lastrowid

    def insert_extensions(self, certificate_id, json_row, extensions) -> int:
        """Inserisce le estensioni di un certificato nel database."""
        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        raw = handshake_log.get("server_certificates", {}).get("certificate", {}).get("raw", {})
        
        key_usage = json.dumps(extensions.get("key_usage", {}))
        extended_key_usage = json.dumps(extensions.get("extended_key_usage", {}))
        basic_constraints = json.dumps(extensions.get("basic_constraints", {}))
        crl_distribution_points = json.dumps(extensions.get("crl_distribution_points", []))
        
        digital_certificate = Certificate(raw)
        crl_distr_point_is_critical = digital_certificate.is_crl_distr_point_critical()

        key_usage_is_critical = digital_certificate.is_key_usage_critical()
        extended_key_usage_is_critical = digital_certificate.is_extended_key_usage_critical()

        self.cursor.execute("""
            INSERT INTO Extensions (
                certificate_id, key_usage, key_usage_is_critical, extended_key_usage, extended_key_usage_is_critical, 
                basic_constraints, crl_distribution_points, crl_distr_point_is_critical
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            certificate_id, key_usage, key_usage_is_critical, extended_key_usage, extended_key_usage_is_critical, basic_constraints,
            crl_distribution_points, crl_distr_point_is_critical
        ))

        logging.debug(f"Estensioni inserite per certificato ID: {certificate_id}")
        return self.cursor.lastrowid

    def insert_certificate_policies(self, extension_id, certificate_policies):
        """Inserisce le estensioni di un certificato nel database."""

        for policy in certificate_policies:
            policy_identifier = policy['policy_identifier']
            
            def filter_user_notice(items): 
                if items is None:
                    items = []
                return list(filter(lambda item: not isinstance(item, UserNotice), items))
            
            cps = filter_user_notice(policy.get('cps', []))
            policy_qualifiers = filter_user_notice(policy.get('policy_qualifiers', []))
            
            is_critical = policy.get('is_critical', False)
            
            self.cursor.execute("""
                INSERT INTO CertificatePolicies (
                    extension_id, policy_identifier, cps, policy_qualifiers, is_critical
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                extension_id, policy_identifier, json.dumps(cps), json.dumps(policy_qualifiers), is_critical
            ))

            logging.debug(f"Policy inserita per l'extension ID: {extension_id}, policy_identifier: {policy_identifier}")

    def insert_signed_certificate_timestamps(self, certificate_id, extensions):
        """Inserisce gli SCT di un certificato nel database."""
        signed_certificate_timestamps = extensions.get("signed_certificate_timestamps", [])
        
        if(len(signed_certificate_timestamps) == 0):
            logging.debug(f"Nessun SCT trovato per il certificate ID: {certificate_id}")
            return
        
        for sct in signed_certificate_timestamps:
            log_id = sct.get("log_id", "")
            signature = sct.get("signature", "")
            timestamp = sct.get("timestamp", "")
            version = sct.get("version", "")

            self.cursor.execute("""
                INSERT INTO SignedCertificateTimestamps (
                    certificate_id, log_id, timestamp, version, signature
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                certificate_id, log_id, timestamp, version, signature
            ))

            logging.debug(f"SCT inserito per il certificate ID: {certificate_id}")
        return

    def insert_certificate_full(self, json_row, parsed, digital_certificate: Certificate, issuer_id, subject_id):
        """Processa e inserisce un certificato nel database, comprese le estensioni."""
        certificate_id = self.insert_certificate(json_row, parsed, issuer_id, subject_id)
        
        if certificate_id:
            # Inserisce le Extensions
            extensions = parsed.get("extensions", {})
            extension_id = self.insert_extensions(certificate_id, json_row, extensions)
            
            # Inserisce gli SCT
            self.insert_signed_certificate_timestamps(certificate_id, extensions)

            certificate_policies = digital_certificate.get_cp()

            # Inserisce i Certificate Policies
            if (certificate_policies is not None):
                self.insert_certificate_policies(extension_id, certificate_policies)

    def process_insert_certificate(self, json_row):
        """Processa e inserisce un certificato nel database."""
        parsed = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})

        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        server_certificates = handshake_log.get("server_certificates", {})
        raw = server_certificates.get("certificate", {}).get("raw", {})

        digital_certificate = Certificate(raw)

        chain = server_certificates.get("chain", [])
        
        # Inserisci Issuer
        issuer_id = self.insert_issuer(parsed, digital_certificate, chain)

        # Inserisci Subject
        subject_id = self.insert_subject(parsed, digital_certificate)
        
        # Inserisci Certificate e Extensions
        self.insert_certificate_full(json_row, parsed, digital_certificate, issuer_id, subject_id)
        return

    def get_issuer_certificate_count(self):
        """Conta il numero di certificati per ciascun issuer."""
        try:
            self.cursor.execute("""
                WITH IssuersCounts AS (
                    SELECT Issuers.organization, COUNT(*) AS certificate_count
                    FROM Certificates 
                    INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id 
                    WHERE Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''
                    GROUP BY Issuers.organization
                    ORDER BY certificate_count DESC
                ),
                TopIssuers AS (
                    SELECT organization, certificate_count
                    FROM IssuersCounts
                    LIMIT 20
                ),
                Others AS (
                    SELECT 'Others' AS organization, SUM(certificate_count) AS certificate_count
                    FROM IssuersCounts 
                    WHERE organization NOT IN (SELECT organization FROM TopIssuers)
                )
                SELECT * FROM TopIssuers
                UNION ALL
                SELECT * FROM Others;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Issuer per certificato ottenute: {len(results)}")

            issuer_count_dict = {row[0]: row[1] for row in results}
            
            logging.info(f"Totale issuers trovati: {len(issuer_count_dict)}")
            return issuer_count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_certificates_per_country(self) -> dict:
        """Conta quanti certificati sono stati emessi per ciascun paese."""
        try:
            self.cursor.execute("""
                WITH IssuersCounts AS (
                    SELECT Issuers.country, COUNT(*) AS country_count
                    FROM Issuers
                    WHERE TRIM(Issuers.country) <> '' AND TRIM(Issuers.country) <> '--'
                    GROUP BY Issuers.country
                    ORDER BY country_count DESC
                ),
                TopCountry AS (
                    SELECT country, country_count
                    FROM IssuersCounts
                    LIMIT 11
                ),
                Others AS (
                    SELECT 'Others' AS country, SUM(country_count) AS country_count
                    FROM IssuersCounts 
                    WHERE country NOT IN (SELECT country FROM TopCountry)
                )
                SELECT * FROM TopCountry
                UNION ALL
                SELECT * FROM Others;
            """)
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}

    def get_validity_duration_distribution(self) -> dict:
        """Mostra la distribuzione delle durate di validità dei certificati nei 20 anni (dopo è solo rumore)."""
        try:
            self.cursor.execute("""
                SELECT validity_length, COUNT(*) AS count
                FROM Certificates
                WHERE validity_length IS NOT NULL AND validity_length >= 0 AND validity_length <= 630720000
                GROUP BY validity_length
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            convert_to_day = lambda seconds: seconds / 31536000
            count_dict = {convert_to_day(row[0]): row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}

    def get_certificate_expiration_trend(self) -> dict:
        """Rappresenta il numero di certificati che scadranno nel tempo."""
        try:
            self.cursor.execute("""
                SELECT strftime('%Y-%m', validity_end) AS month, COUNT(*) AS count
                FROM Certificates
                WHERE validity_end IS NOT NULL
                GROUP BY month
                HAVING count > 10
                ORDER BY month ASC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_signature_algorithm_distribution(self) -> dict:
        """Mostra la distribuzione degli algoritmi di firma utilizzati."""
        try:
            self.cursor.execute("""
                SELECT signature_algorithm, COUNT(*) AS sign_algorithm_count
                FROM Certificates
                WHERE signature_algorithm IS NOT NULL
                GROUP BY signature_algorithm
                ORDER BY sign_algorithm_count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_key_algorithm_length_distribution(self) -> dict:
        """Esegue una query per ottenere conteggi per un'entità specifica."""
        try:
            self.cursor.execute("""
                SELECT 
                    key_algorithm, 
                    key_length, 
                    COUNT(*) AS certificate_count
                FROM 
                    Certificates
                WHERE 
                    key_algorithm IS NOT NULL AND key_algorithm <> '' AND
                    key_length IS NOT NULL AND key_length <> ''
                GROUP BY 
                    key_algorithm, 
                    key_length
                ORDER BY 
                    key_algorithm, 
                    key_length;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {}
            for row in results:
                algorithm = row[0]
                length = row[1]
                count = row[2]
                
                if algorithm not in count_dict:
                    count_dict[algorithm] = {}
                count_dict[algorithm][length] = count
            
            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_ocsp_status_distribution(self) -> dict:
        """Mostra la distribuzione degli stati OCSP come "Good", "Revoked", ecc..."""
        try:
            self.cursor.execute("""
                SELECT ocsp_check, COUNT(*) AS count
                FROM Issuers
                GROUP BY ocsp_check;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_count_critical_non_critical_extensions(self) -> dict:
        """Conta il numero di certificati che hanno implementato estensioni critiche rispetto a quelle non critiche dell'AIA."""
        try:
            self.cursor.execute("""
                SELECT authority_info_access_is_critical, COUNT(*) AS count
                FROM Issuers
                GROUP BY authority_info_access_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_self_signed_vs_ca_signed(self) -> dict:
        """Rappresenta la proporzione di certificati auto-firmati rispetto a quelli firmati da una CA."""
        try:
            self.cursor.execute("""
                SELECT 
                    CASE 
                        WHEN self_signed = 1 THEN 'True' 
                        ELSE 'False' 
                    END AS is_self_signed,
                    COUNT(*) AS count
                FROM Certificates
                GROUP BY self_signed;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_validation_level_distribution(self) -> dict:
        """Mostra la distribuzione dei diversi validation_level dei certificati."""
        try:
            self.cursor.execute("""
                SELECT validation_level, COUNT(*) AS count
                FROM Certificates
                GROUP BY validation_level;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_certificate_version_distribution(self) -> dict:
        """Mostra la distribuzione delle versioni dei certificati (es. v1, v2, v3)."""
        try:
            self.cursor.execute("""
                SELECT version, COUNT(*) AS count
                FROM Certificates
                GROUP BY version;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_signature_validity_distribution(self) -> dict:
        """Rappresenta la proporzione di firme valide rispetto a quelle non valide."""
        try:
            self.cursor.execute("""
                SELECT
                    CASE 
                        WHEN signature_valid = 1 THEN 'True' 
                        ELSE 'False' 
                    END AS is_valid_signature,
                    COUNT(*) AS count
                FROM Certificates
                GROUP BY signature_valid;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_status_analysis(self) -> dict:
        """Mostra il numero di Success dei certificati e la frequenza dei diversi tipi di errori nei certificati."""
        try:
            self.cursor.execute("""
                SELECT 'success', COUNT(*) AS count
                FROM Certificates
                UNION ALL
                SELECT status, COUNT(*) AS count
                FROM Errors
                GROUP BY status;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_key_usage_distribution(self) -> dict:
        """Mostra quali key_usage sono più comunemente utilizzati nei certificati."""
        try:
            self.cursor.execute("""
                SELECT key_usage, COUNT(*) AS count
                FROM Extensions
                GROUP BY key_usage
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {}
            for row in results:
                key_usage = json.loads(row[0])
                key_usage.pop('value', None)
                count_dict[json.dumps(key_usage)] = row[1]

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_critical_vs_non_critical_key_usage(self) -> dict:
        """Mostra la proporzione di key_usage critici rispetto a quelli non critici."""
        try:
            self.cursor.execute("""
                SELECT key_usage_is_critical, COUNT(*) AS count
                FROM Extensions
                GROUP BY key_usage_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_extended_key_usage_distribution(self) -> dict:
        """Visualizza quali extended_key_usage sono più comuni nei certificati."""
        try:
            self.cursor.execute("""
                SELECT extended_key_usage, COUNT(*) AS count
                FROM Extensions
                GROUP BY extended_key_usage
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_critical_vs_non_critical_extended_key_usage(self) -> dict:
        """Mostra la proporzione di extended_key_usage critici rispetto a quelli non critici."""
        try:
            self.cursor.execute("""
                SELECT extended_key_usage_is_critical, COUNT(*) AS count
                FROM Extensions
                GROUP BY extended_key_usage_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_basic_constraints_distribution(self) -> dict:
        """Mostra la distribuzione dei Basic Constraints nei certificati."""
        try:
            self.cursor.execute("""
                SELECT basic_constraints, COUNT(*) AS count
                FROM Extensions
                GROUP BY basic_constraints
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}

    def get_critical_vs_non_critical_crl_distribution(self) -> dict:
        """Mostra la proporzione di estensioni CRL critical vs non critical."""
        try:
            self.cursor.execute("""
                SELECT crl_distr_point_is_critical, COUNT(*) AS count
                FROM Extensions
                GROUP BY crl_distr_point_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_signed_certificate_timestamp_trend(self) -> dict:
        """Mostra la distribuzione temporale per mese e anno dei Signed Certificate Timestamps."""
        try:
            self.cursor.execute("""
                SELECT 
                    strftime('%Y-%m', datetime(timestamp, 'unixepoch')) AS month_year, 
                    COUNT(*) AS count
                FROM SignedCertificateTimestamps
                GROUP BY month_year
                HAVING count > 10
                ORDER BY month_year ASC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_sct_count_per_certificate(self) -> dict:
        """Conta quanti certificati hanno 1 SCT, 2 SCT, e così via."""
        try:
            self.cursor.execute("""
                SELECT count_sct, COUNT(*) AS certificate_count
                FROM (
                    SELECT COUNT(*) AS count_sct
                    FROM SignedCertificateTimestamps
                    GROUP BY certificate_id) AS sct_counts
                GROUP BY count_sct
                ORDER BY count_sct ASC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            print(count_dict)

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_top_sct_issuers(self) -> dict:
        """Mostra quali log di SCT sono stati usati più spesso."""
        try:
            self.cursor.execute("""
                SELECT log_id, COUNT(*) AS count
                FROM SignedCertificateTimestamps
                GROUP BY log_id
                ORDER BY count DESC;
            """)
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_critical_vs_non_critical_san_extensions(self) -> dict:
        """Mostra la proporzione di estensioni critiche vs non critiche nelle Subject Alternative Name."""
        try:
            self.cursor.execute("""
                SELECT subject_alt_name_is_critical, COUNT(*) AS count
                FROM Subjects
                GROUP BY subject_alt_name_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    """
    def get_count_per_entity(self) -> dict:
        "" Commento. ""
        try:
            self.cursor.execute("""""")
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.info(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    """