import json
import logging
from tqdm.rich import tqdm
from typing import Optional
from datetime import datetime
from bean.certificate import Certificate
from db.database import DatabaseType
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA224, SHA384, SHA512
from cryptography.x509.extensions import UserNotice
from utils.utils import verify_signature, find_raw_cert_issuer, check_ocsp_status, reorder_signature_algorithm, count_intermediate_and_root_certificates

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class CertificateDAO:
    def __init__(self, connection):
        self.conn = connection
        self.cursor = self.conn.cursor()

    def insert_error_row(self, json_row):
        """Inserisce la riga di errore nel database. Vale solo per i certificati Leaf."""
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

    def insert_issuer(self, parsed, handshake_log) -> int:
        """Inserisce un issuer nel database e restituisce l'issuer_id."""
        issuer = parsed.get("issuer", {})
        
        issuer_dn = parsed.get("issuer_dn", "")
        issuer_common_name = ', '.join(issuer.get("common_name", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_organization = ', '.join(issuer.get("organization", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_country = ', '.join(issuer.get("country", [])).encode('utf-8', errors='replace').decode('utf-8')
        issuer_locality = ', '.join(issuer.get("locality", []))
        issuer_province = ', '.join(issuer.get("province", []))
        issuer_organizational_unit = ', '.join(issuer.get("organizational_unit", []))

        authority_key_id = parsed.get("extensions", {}).get("authority_key_id", "")

        chain = handshake_log.get("server_certificates", {}).get("chain", [])
        raw = find_raw_cert_issuer(chain, issuer_dn)

        self.cursor.execute("""
            INSERT INTO Issuers (common_name, organization, country, issuer_dn, locality, province, 
            organizational_unit, authority_key_id, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            issuer_common_name, issuer_organization, issuer_country, issuer_dn, issuer_locality, 
            issuer_province, issuer_organizational_unit, authority_key_id, raw
        ))

        logging.debug(f"Issuer inserito: {issuer_dn}")
        return (self.cursor.lastrowid, issuer_common_name, issuer_dn)

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
        """, (subject_common_name, subject_dn, subject_key_id, subject_alt_name, subject_alt_name_is_critical))

        logging.debug(f"Subject inserito: {subject_dn}")
        return self.cursor.lastrowid

    def insert_certificate(self, json_row, parsed, issuer_id, subject_id, issuer_common_name, issuer_dn, certificate_type: DatabaseType) -> Optional[int]:
        """Inserisce un certificato nel database e restituisce il certificate_id."""
        download_date = json_row.get("data", {}).get("tls", {}).get("timestamp", datetime.now().isoformat())
        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        ocsp_stapling = handshake_log.get("server_hello", {}).get("ocsp_stapling", False)

        serial_number = parsed.get("serial_number", "")
        leaf_domain = json_row.get("domain", "")
        version = parsed.get("version", 0)
        signature_algorithm = parsed.get("signature_algorithm", {}).get("name", "")
        signature_algorithm = reorder_signature_algorithm(signature_algorithm)
        key_algorithm = parsed.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "")
        
        key_length = parsed.get("subject_key_info", {}).get("rsa_public_key", {}).get("length", 0)
        if(key_length == 0):
            key_length = parsed.get("subject_key_info", {}).get("ecdsa_public_key", {}).get("length", 0)

        validity_start = parsed.get("validity", {}).get("start", "")
        validity_end = parsed.get("validity", {}).get("end", "")
        validity_length = parsed.get("validity", {}).get("length", "")
        validation_level = parsed.get("validation_level", "")
        redacted = parsed.get("redacted", False)
                
        raw = handshake_log.get("server_certificates", {}).get("certificate", {}).get("raw", {})
        digital_certificate = Certificate(raw)

        chain = handshake_log.get("server_certificates", {}).get("chain", [])

        self_signed = parsed.get("signature", {}).get("self_signed", False)
        signature_valid = "Error"  # errore di default, nel caso non avesse alcuna catena
        
        if(certificate_type == DatabaseType.ROOT):
            leaf_cert = digital_certificate.get_cert()
            # Il certificato root si autofirma
            signature_valid = verify_signature(cert=leaf_cert, ca_cert=leaf_cert)
        else:
            if len(chain) > 0:
                issuer_cert = digital_certificate.get_certificate_from_raw(find_raw_cert_issuer(chain, issuer_dn))
                leaf_cert = digital_certificate.get_cert()
                if(issuer_cert is None):
                    signature_valid = "Issuer not found"
                else:
                    signature_valid = verify_signature(leaf_cert, issuer_cert)
                    
        ocsp_must_stapling = digital_certificate.is_ocsp_must_staple()
        
        extensions = parsed.get("extensions", {})
        aia = extensions.get("authority_info_access", {})
        authority_info_access = aia

        authority_info_access_is_critical = digital_certificate.is_aia_critical(issuer_common_name)

        ocsp_check = "No Request Done"
        
        certificate = handshake_log.get("server_certificates", {}).get("certificate", {})
        num_intermediate_certificates, has_root_certificate = count_intermediate_and_root_certificates(chain, certificate)
        
        self.cursor.execute("""
            INSERT INTO Certificates (
                serial_number, leaf_domain, version, signature_algorithm, key_algorithm, key_length, 
                validity_start, validity_end, validity_length, issuer_id, 
                subject_id, validation_level, redacted, signature_valid, self_signed, download_date, 
                ocsp_stapling, ocsp_must_stapling, authority_info_access_is_critical, authority_info_access, 
                ocsp_check, num_intermediate_certificates, has_root_certificate, raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            serial_number, leaf_domain, version, signature_algorithm, key_algorithm, key_length,
            validity_start, validity_end, validity_length, issuer_id,
            subject_id, validation_level, redacted, signature_valid, self_signed, download_date, 
            ocsp_stapling, ocsp_must_stapling, authority_info_access_is_critical, json.dumps(authority_info_access), 
            ocsp_check, num_intermediate_certificates, has_root_certificate, raw
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
            
            # Filtra le User Notices
            def filter_user_notice(items): 
                if items is None:
                    items = []
                return list(filter(lambda item: not isinstance(item, UserNotice), items))
            
            cps = filter_user_notice(policy.get('cps', []))
            policy_qualifiers = filter_user_notice(policy.get('policy_qualifiers', []))
            
            is_cp_critical = policy.get('is_cp_critical', False)
            
            self.cursor.execute("""
                INSERT INTO CertificatePolicies (
                    extension_id, policy_identifier, cps, policy_qualifiers, is_cp_critical
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                extension_id, policy_identifier, json.dumps(cps), json.dumps(policy_qualifiers), is_cp_critical
            ))

            logging.debug(f"Policy inserita per l'extension ID: {extension_id}, policy_identifier: {policy_identifier}")

    def insert_signed_certificate_timestamps(self, certificate_id, extensions):
        """Inserisce gli SCT di un certificato nel database."""
        signed_certificate_timestamps = extensions.get("signed_certificate_timestamps", [])
        
        if(len(signed_certificate_timestamps) == 0):
            logging.debug(f"Nessun SCT trovato per il certificate ID: {certificate_id}")
            return
        
        for sct in signed_certificate_timestamps:
            log_id_str = sct.get("log_id", "")
            log_id = self.get_sct_log(log_id_str)
            
            # Inserimento di un nuovo record nella tabella dei logs per log_id che non è stato trovato
            if(log_id == -1):
                operator_id = self.get_sct_unknown_operator()
                json_log = {
                    "log_id": log_id_str
                }
                log_id = self.insert_sct_log(operator_id, json_log)
            
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

    def insert_certificate_full(self, json_row, parsed, digital_certificate: Certificate, issuer_id, subject_id, issuer_common_name, issuer_dn, certificate_type: DatabaseType):
        """Processa e inserisce un certificato nel database, comprese le estensioni."""
        certificate_id = self.insert_certificate(json_row, parsed, issuer_id, subject_id, issuer_common_name, issuer_dn, certificate_type)
        
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

    def process_insert_certificate(self, json_row, certificate_type: DatabaseType):
        """Processa e inserisce un certificato nel database."""
        parsed = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})

        handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        server_certificates = handshake_log.get("server_certificates", {})
        raw = server_certificates.get("certificate", {}).get("raw", {})

        digital_certificate = Certificate(raw)
        
        # Inserisci Issuer
        issuer_id, issuer_common_name, issuer_dn = self.insert_issuer(parsed, handshake_log)

        # Inserisci Subject
        subject_id = self.insert_subject(parsed, digital_certificate)
        
        # Inserisci Certificate e Extensions
        self.insert_certificate_full(json_row, parsed, digital_certificate, issuer_id, subject_id, issuer_common_name, issuer_dn, certificate_type)
        return

    def check_ocsp_status_for_certificates(self, certificate_type: DatabaseType, batch_size=1000):
        """Controlla lo stato OCSP per ciascun certificato nel database e aggiorna il relativo stato."""
        global pbar_ocsp_check
        
        try:
            # Conta il numero di certificati per la barra di progresso
            self.cursor.execute("""
                    SELECT COUNT(c.certificate_id)
                    FROM Certificates AS c 
                    INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
                    WHERE c.ocsp_check = 'No Request Done'
                """)
                
            result = self.cursor.fetchone()
            total_lines = result[0]

            # Controlla il conteggio
            if total_lines == 0:
                logging.info("Nessun certificato da analizzare è presente nel database.")
                return
        
            # Inizializza la barra di caricamento
            tqdm.write("")
            pbar_ocsp_check = tqdm(total=total_lines, desc=" 🕵️‍♂️  [blue bold]Elaborazione Certificati[/blue bold]", unit="cert.", 
                        colour="blue", bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} • ⚡ {rate_fmt}")

            while True:
                self.cursor.execute("""
                    SELECT c.certificate_id, c.authority_info_access, i.common_name, i.raw AS issuer_cert_raw, c.raw AS leaf_cert_raw
                    FROM Certificates AS c 
                    INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
                    WHERE c.ocsp_check = 'No Request Done'
                    LIMIT ?
                """, (batch_size, ))
                
                # Prendi tutti i record
                rows = self.cursor.fetchall()

                # Se non ci sono più record, interrompi il ciclo
                if not rows:
                    break
                
                for row in rows:
                    certificate_id = None
                    
                    try:
                        certificate_id = row['certificate_id']
                        
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
                                    ocsp_check = check_ocsp_status(leaf_cert_raw, hash_algorithm, issuer_url, issuer_common_name, ocsp_url, issuer_cert)
                                    
                                    if(ocsp_check != "Impossible Retrieve OCSP Information"):
                                        break
                                
                                if(ocsp_check != "Impossible Retrieve OCSP Information"):
                                        break
                        
                        if(ocsp_check == "Impossible Retrieve OCSP Information"):
                            logging.error(f"Impossibile recuperare le informazioni OCSP per il certificato ID {certificate_id}. Verifica la connessione o il formato del certificato.")                            
                        
                        # Aggiornamento dell'OCSP status nel db
                        self.cursor.execute("""
                            UPDATE Certificates
                            SET ocsp_check = ?
                            WHERE certificate_id = ?
                        """, (ocsp_check, certificate_id))
                        self.conn.commit()
                        
                         # Aggiorna la barra di caricamento
                        pbar_ocsp_check.update(1)

                    except Exception as e:
                        logging.error(f"Errore durante il controllo dello stato OCSP per il certificato ID {certificate_id}: {e}")
                
        except json.JSONDecodeError as json_err:
            logging.error(f"\nErrore nella deserializzazione del JSON: {json_err}")
        except Exception as e:
            logging.error(f"\nErrore generale durante il controllo dello stato OCSP: {e}")
        
        # Chiusura barra di progresso
        pbar_ocsp_check.close()
        return
    
    def insert_sct_log_operator(self, operator):
        """Inserisce un operatore SCT nel database."""

        name = operator.get("name", "")
        email = ', '.join(operator.get("email", []))
        
        self.cursor.execute("""
            INSERT INTO LogsOperators (name, email) 
            VALUES (?, ?)
        """, (
            name, email
        ))
        
        logging.debug(f"SCT operator inserito: {self.cursor.lastrowid}")
        return self.cursor.lastrowid
    
    def insert_sct_log(self, operator_id, json_log):
        """Inserisce un log SCT nel database associandolo a un operatore."""
        
        description = json_log.get("description", "")
        log_id = json_log.get("log_id", "")
        key = json_log.get("key", "")
        url = json_log.get("url", "")
        mmd = json_log.get("mmd", "")
        state_usable_timestamp = json_log.get("state", {}).get("usable", {}).get("timestamp", "")
        state_retired_timestamp = json_log.get("state", {}).get("retired", {}).get("timestamp", "")
        state_qualified_timestamp = json_log.get("state", {}).get("qualified", {}).get("timestamp", "")
        temporal_start = json_log.get("temporal_interval", {}).get("start_inclusive", "")
        temporal_end = json_log.get("temporal_interval", {}).get("end_exclusive", "")
        
        self.cursor.execute("""
            INSERT INTO Logs (operator_id, description, log_id, key, url, 
                mmd, state_usable_timestamp, state_retired_timestamp, state_qualified_timestamp, temporal_start, temporal_end) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(log_id) DO NOTHING
        """, (
            operator_id, description, log_id, key, url, mmd, state_usable_timestamp, state_retired_timestamp, state_qualified_timestamp,
            temporal_start, temporal_end
        ))
        
        logging.debug(f"Log SCT inserito: {self.cursor.lastrowid}")
        return self.cursor.lastrowid

    def get_sct_unknown_operator(self):
        """Recupera l'id del record dell'operatore fantasma."""
        try:
            self.cursor.execute("""
                SELECT id FROM LogsOperators WHERE name = 'unknown' and email = ''
            """)
            
            result = self.cursor.fetchone()
            return result['id']
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return -1
        
    def get_sct_log(self, log_id):
        """Recupera l'id del record di log in base al log_id."""
        try:
            self.cursor.execute("""
                SELECT id FROM Logs WHERE log_id = ?
            """, (log_id, ))
            
            result = self.cursor.fetchone()
            if result is not None:
                log_id_value = result['id']
                return log_id_value
            
            return -1
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return -1
    
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

            logging.debug(f"Risultati ottenuti: {len(results)}")

            issuer_count_dict = {row[0]: row[1] for row in results}
            
            logging.debug(f"Totale trovati: {len(issuer_count_dict)}")
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
                    SELECT 'Others' AS country, COALESCE(SUM(country_count), 0) AS country_count
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            convert_to_year = lambda seconds: seconds // 31536000
            count_dict = {}
            for row in results:
                year = convert_to_year(row[0])
                value = row[1]
                if year in count_dict:
                    count_dict[year] += value
                else:
                    count_dict[year] = value
                    
            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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
            
            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_ocsp_status_distribution(self) -> dict:
        """Mostra la distribuzione degli stati OCSP come "Good", "Revoked", ecc..."""
        try:
            self.cursor.execute("""
                SELECT ocsp_check, COUNT(*) AS count
                FROM Certificates
                GROUP BY ocsp_check;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_count_critical_non_critical_extensions(self) -> dict:
        """Conta il numero di certificati che hanno implementato estensioni critiche rispetto a quelle non critiche dell'AIA."""
        try:
            self.cursor.execute("""
                SELECT authority_info_access_is_critical, COUNT(*) AS count
                FROM Certificates
                GROUP BY authority_info_access_is_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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
                count_dict[json.dumps(", ".join(key_usage.keys()))] = row[1]

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            count_dict = {}
            for row in results:
                key_usage = json.loads(row[0])
                count_dict[json.dumps(", ".join(key_usage.keys()))] = row[1]

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
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
                    SELECT COUNT(s.certificate_id) AS count_sct
                    FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps s
                    ON s.certificate_id = c.certificate_id 
                    GROUP BY c.certificate_id) AS sct_counts
                GROUP BY count_sct
                ORDER BY count_sct ASC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
        
    def get_top_sct_logs(self) -> dict:
        """Mostra quali log di SCT sono stati usati più spesso."""
        try:
            self.cursor.execute("""
                SELECT l.description, COUNT(*) AS count
                FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
                GROUP BY l.description
                HAVING count > 5
                ORDER BY count DESC;
            """)
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_top_sct_log_operators(self) -> dict:
        """Conta i log di SCT per ogni operatore, mostrando quelli più utilizzati."""
        try:
            self.cursor.execute("""
                SELECT lo.name, COUNT(*) AS count
                FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
                INNER JOIN LogsOperators AS lo ON l.operator_id = lo.id
                GROUP BY lo.name
                ORDER BY count DESC;
            """)
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    
    def get_critical_vs_non_critical_cp_policies(self) -> dict:
        """Mostra la proporzione di certificate policies critici rispetto a quelli non critici."""
        try:
            self.cursor.execute("""
                SELECT is_cp_critical, COUNT(*) AS count
                FROM CertificatePolicies
                GROUP BY is_cp_critical
                ORDER BY count DESC;
            """)
            
            results = self.cursor.fetchall()

            logging.debug(f"Risultati ottenuti: {len(results)}")

            count_dict = {row[0]: row[1] for row in results}

            logging.debug(f"Totale trovati: {len(count_dict)}")
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

            logging.debug(f"Totale trovati: {len(count_dict)}")
            return count_dict
        except Exception as e:
            logging.error("Errore: %s", str(e))
            return {}
    """