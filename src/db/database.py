import sqlite3
from sqlite3 import Connection
from contextlib import contextmanager
import logging
import os
from enum import Enum

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class DatabaseType(Enum):
    LEAF = "leaf",
    INTERMEDIATE = "intermediate"
    ROOT = "root"

class Database:
    def __init__(self, db_path: str, schema_path: str, db_type: DatabaseType):
        self.db_path = db_path
        self.schema_path = schema_path
        self.conn: Connection = None
        self.db_type = db_type
        return

    def connect(self, delete_database=True):
        """Crea una connessione al database SQLite."""
        if(delete_database == True and os.path.exists(self.db_path)):
            os.remove(self.db_path)
            logging.info(f"Database eliminato con successo: {self.db_path}")

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # per accedere ai risultati come dizionari
        self._initialize_database()
        return

    def _initialize_database(self):
        """Crea le tabelle e gli indici se non esistono."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if not tables:
            self.create_tables()
        
        logging.info(f"Connessione al database esistente: 'file://{self.db_path}'")
        return

    def create_tables(self):
        """Crea le tabelle nel database utilizzando lo schema SQL."""
        logging.info(f"Creazione tabelle nel database in corso...")
        
        with open(self.schema_path, 'r') as f:
            schema_sql = f.read()
        cursor = self.conn.cursor()
        cursor.executescript(schema_sql)
        self.conn.commit()
        logging.info("Tabelle create con successo.")
        return

    def create_indexes(self):
        """Crea gli indici per migliorare le prestazioni delle query."""

        logging.info(f"Creazione indici nel database in corso...")
        
        cursor = self.conn.cursor()
        cursor.executescript("""
            -- Indici per la tabella Certificates
            CREATE INDEX IF NOT EXISTS idx_certificate_id_leaf_domain ON Certificates(certificate_id, leaf_domain);
            CREATE INDEX IF NOT EXISTS idx_certificates_issuer_id ON Certificates(issuer_id);
            CREATE INDEX IF NOT EXISTS idx_certificates_subject_id ON Certificates(subject_id);
            CREATE INDEX IF NOT EXISTS idx_certificates_ocsp_check ON Certificates(ocsp_check);
            CREATE INDEX IF NOT EXISTS idx_certificates_authority_info_access ON Certificates(authority_info_access);
            CREATE INDEX IF NOT EXISTS idx_certificates_validity_end ON Certificates(validity_end);
            CREATE INDEX IF NOT EXISTS idx_certificates_version ON Certificates(version);

            -- Indici per la tabella Issuers
            CREATE INDEX IF NOT EXISTS idx_issuers_common_name ON Issuers(common_name);
            CREATE INDEX IF NOT EXISTS idx_issuers_organization ON Issuers(organization);

            -- Indici per la tabella Subjects
            CREATE INDEX IF NOT EXISTS idx_subjects_subject_dn ON Subjects(subject_dn);
            CREATE INDEX IF NOT EXISTS idx_subjects_common_name ON Subjects(common_name);
            CREATE INDEX IF NOT EXISTS idx_subjects_subject_key_id ON Subjects(subject_key_id);

            -- Indici per la tabella Extensions
            CREATE INDEX IF NOT EXISTS idx_extensions_certificate_id ON Extensions(certificate_id);
            CREATE INDEX IF NOT EXISTS idx_extensions_key_usage ON Extensions(key_usage);
            CREATE INDEX IF NOT EXISTS idx_extensions_extended_key_usage ON Extensions(extended_key_usage);
        """)
        
        if self.db_type == DatabaseType.LEAF:
            # Inserisci qui gli indici specifici solo per il database leaf
            cursor.executescript("""
                -- Indici per la tabella Certificates
                CREATE INDEX IF NOT EXISTS idx_certificates_self_signed ON Certificates(self_signed);
                CREATE INDEX IF NOT EXISTS idx_certificates_signature_valid ON Certificates(signature_valid);

                -- Indici per la tabella SignedCertificateTimestamps
                CREATE INDEX IF NOT EXISTS idx_signed_cert_timestamps_certificate_id ON SignedCertificateTimestamps(certificate_id);
                CREATE INDEX IF NOT EXISTS idx_signed_cert_timestamps_log_id ON SignedCertificateTimestamps(log_id);

                -- Indici per la tabella Errors
                CREATE INDEX IF NOT EXISTS idx_errors_domain ON Errors(domain);
                CREATE INDEX IF NOT EXISTS idx_errors_status ON Errors(status);

                -- Indici per la tabella Logs
                CREATE INDEX IF NOT EXISTS idx_logs_operator_id ON Logs(operator_id);
                CREATE INDEX IF NOT EXISTS idx_logs_log_id ON Logs(log_id);
            """)
        elif self.db_type == DatabaseType.INTERMEDIATE:
            # Inserisci qui gli indici specifici solo per il database intermediate
            cursor.executescript("""
                -- Indici per la tabella Certificates
                CREATE INDEX IF NOT EXISTS idx_certificates_self_signed ON Certificates(self_signed);
            """)
        elif self.db_type == DatabaseType.ROOT:
            # Inserisci qui gli indici specifici solo per il database root
            cursor.executescript("""
                -- Indici per la tabella Certificates
                CREATE INDEX IF NOT EXISTS idx_certificates_signature_valid ON Certificates(signature_valid);
            """)
        
        self.conn.commit()
        logging.info("Indici creati con successo.")
        return
    
    def apply_database_corrections(self):
        """Applica correzioni ai dati nel database."""
        logging.info("Inizio delle correzioni al database.")
        
        try:            
            cursor = self.conn.cursor()
            cursor.executescript("""
                -- Rename DigiCert
                UPDATE Issuers
                SET organization = 'DigiCert Inc'
                WHERE organization = 'DigiCert, Inc.';
            """)

            self.conn.commit()
            logging.info("Correzioni al database applicate.")
        except Exception as e:
            logging.error(f"Errore nell'applicare le correzioni: {e}")
            self.conn.rollback()
        return
    
    def _restructure_table_remove_columns(self, table_name: str, columns_to_remove: list[str]):
        """
            Ristruttura la tabella specificata rimuovendo le colonne indicate.
            Crea una nuova tabella con le colonne rimanenti, copia i dati dalla 
            tabella originale e rinomina la nuova tabella.
        """
        cursor = self.conn.cursor()
        
        # Crea una nuova tabella senza le colonne da eliminare
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        
        # Costruisce la query per creare la nuova tabella
        new_columns = [col[1] for col in columns if col[1] not in columns_to_remove]
        new_table_name = f"{table_name}_new"
        
        create_table_query = f"CREATE TABLE {new_table_name} ({', '.join(new_columns)});"
        cursor.execute(create_table_query)
        
        # Copia i dati nella nuova tabella
        columns_to_select = ', '.join(new_columns)
        insert_query = f"INSERT INTO {new_table_name} ({columns_to_select}) SELECT {columns_to_select} FROM {table_name};"
        cursor.execute(insert_query)
        
        cursor.execute(f"DROP TABLE {table_name};")                                 # Eliminare la tabella originale
        cursor.execute(f"ALTER TABLE {new_table_name} RENAME TO {table_name};")     # Rinominare la nuova tabella
        
        self.conn.commit()
        return

    def remove_columns(self):
        """Rimuove colonne specifiche dalla tabella 'Certificates' in base al tipo di database."""
        try:
            logging.info(f"Rimozione colonne non necessarie dal database in corso...")
            
            # Elimina le colonne dalle tabelle specificate
            if(self.db_type == DatabaseType.LEAF):
                columns = [
                    "certificates_emitted_up_to"
                ]
                self._restructure_table_remove_columns("Certificates", columns)
                logging.info("Colonne specificate rimosse dalla tabella 'Certificates'.")
            elif(self.db_type == DatabaseType.INTERMEDIATE):
                columns = [
                    "ocsp_stapling",
                    "ocsp_must_stapling",
                    "signature_valid",
                    "SAN",
                    "domain_matches_san"
                ]
                self._restructure_table_remove_columns("Certificates", columns)
                logging.info("Colonne specificate rimosse dalla tabella 'Certificates'.")
            elif(self.db_type == DatabaseType.ROOT):
                columns = [
                    "ocsp_stapling",
                    "ocsp_must_stapling",
                    "certificates_up_to_root_count",
                    "has_root_certificate",
                    "SAN",
                    "domain_matches_san"
                ]
                self._restructure_table_remove_columns("Certificates", columns)
                logging.info("Colonne specificate rimosse dalla tabella 'Certificates'.")
            
        except Exception as e:
            logging.error("Errore durante la rimozione delle colonne: %s", e)
        return

    def cleanup_unused_tables(self):
        """
            Elimina le tabelle non necessarie in base al tipo di database.
        """
        try:
            logging.info(f"Rimozione tabelle non necessarie in corso...")
            
            cursor = self.conn.cursor()
            
            if self.db_type in {DatabaseType.INTERMEDIATE, DatabaseType.ROOT}:
                cursor.executescript("""
                    DROP TABLE IF EXISTS Errors;
                """)
                self.conn.commit()
                logging.info("La tabella 'Errors' è stata eliminata con successo.")
        
        except Exception as e:
            logging.error("Errore durante la pulizia delle tabelle non utilizzate: %s", e)
        return

    def drop_indexes_for_table(self):
        """Rimuove tutti gli indici esistenti."""
        try:
            logging.info(f"Rimozione indici dal database in corso...")
            
            cursor = self.conn.cursor()
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index';")
            indexes = cursor.fetchall()
            
            # Lista di indici da ignorare durante la rimozione
            ignore = ['idx_certificates_ocsp_check', 
                      'idx_certificates_authority_info_access', 
                      'idx_logs_log_id', 
                      'sqlite_autoindex_Logs_1',
                      'idx_certificate_id_leaf_domain']
            
            if indexes:
                for index in indexes:
                    index_name = index[0]
                    if(index_name not in ignore):
                        cursor.execute(f"DROP INDEX IF EXISTS {index_name};")
                self.conn.commit()
                logging.info(f"Tutti gli indici, eccetto quelli ignorati, sono stati rimossi dal database.")
            else:
                logging.info(f"Nessun indice trovato nel database.")
        except Exception as e:
            logging.error(f"Errore nel rimuovere gli indici: {e}")
            self.conn.rollback()

    @contextmanager
    def transaction(self):
        """Gestisce una transazione con commit o rollback."""
        try:
            yield
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            logging.error(f"Transazione fallita: {e}")
            raise e
        return

    def close(self):
        """Chiude la connessione al database."""
        if self.conn:
            self.conn.close()
            if(self.db_type == DatabaseType.LEAF):
                logging.info(f"Connessione al database Leaf chiusa con successo: 'file://{self.db_path}'")
            elif(self.db_type == DatabaseType.INTERMEDIATE):
                logging.info(f"Connessione al database Intermediate chiusa con successo: 'file://{self.db_path}'")
            elif(self.db_type == DatabaseType.ROOT):
                logging.info(f"Connessione al database Root chiusa con successo: 'file://{self.db_path}'")
        return
