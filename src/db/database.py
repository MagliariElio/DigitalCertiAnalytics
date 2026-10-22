import sqlite3
from sqlite3 import Connection
from contextlib import contextmanager
import logging
import os
from enum import Enum

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class DatabaseType(Enum):
    LEAF = "leaf"
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
        else:
            self._ensure_certificate_id_index()
        
        logging.info(f"Connessione al database esistente: 'file://{self.db_path}'")
        return

    def _ensure_certificate_id_index(self):
        """
            Garantisce un indice su certificate_id per i database generati dalle versioni precedenti, 
            in cui la rimozione delle colonne faceva perdere la PRIMARY KEY della tabella 'Certificates'.
            Senza indice ogni ricerca per certificate_id richiederebbe la scansione dell'intera tabella.
        """
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(Certificates);")
        columns = cursor.fetchall()
        
        if any(col[1] == 'certificate_id' and col[5] == 0 for col in columns):
            logging.info("Creazione dell'indice su 'certificate_id' per un database senza PRIMARY KEY in corso...")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_certificate_id_leaf_domain ON Certificates(certificate_id, leaf_domain);")
            self.conn.commit()
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
            Crea una nuova tabella con le colonne rimanenti (mantenendo tipo, NOT NULL, DEFAULT e PRIMARY KEY), 
            copia i dati dalla tabella originale e rinomina la nuova tabella.
        """
        cursor = self.conn.cursor()
        
        # Legge la definizione delle colonne della tabella originale: (cid, name, type, notnull, dflt_value, pk)
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = [col for col in cursor.fetchall() if col[1] not in columns_to_remove]
        
        # Costruisce la definizione delle colonne mantenendo tipo e vincoli, così da non perdere 
        # la PRIMARY KEY (es. certificate_id resta alias del rowid e quindi indicizzato)
        primary_keys = [col for col in columns if col[5] > 0]
        column_definitions = []
        for col in columns:
            definition = f"{col[1]} {col[2]}".strip()
            if(len(primary_keys) == 1 and col[5] > 0):
                definition += " PRIMARY KEY"
            if(col[3]):
                definition += " NOT NULL"
            if(col[4] is not None):
                definition += f" DEFAULT {col[4]}"
            column_definitions.append(definition)
        
        if(len(primary_keys) > 1):
            primary_keys.sort(key=lambda col: col[5])
            column_definitions.append(f"PRIMARY KEY ({', '.join(col[1] for col in primary_keys)})")
        
        new_columns = [col[1] for col in columns]
        new_table_name = f"{table_name}_new"
        columns_to_select = ', '.join(new_columns)
        
        try:
            # Rimuove eventuali residui di una ristrutturazione precedente non completata
            cursor.execute(f"DROP TABLE IF EXISTS {new_table_name};")
            cursor.execute(f"CREATE TABLE {new_table_name} ({', '.join(column_definitions)});")
            
            # Copia i dati nella nuova tabella
            cursor.execute(f"INSERT INTO {new_table_name} ({columns_to_select}) SELECT {columns_to_select} FROM {table_name};")
            
            cursor.execute(f"DROP TABLE {table_name};")                                 # Eliminare la tabella originale
            cursor.execute(f"ALTER TABLE {new_table_name} RENAME TO {table_name};")     # Rinominare la nuova tabella
            
            self.conn.commit()
        except Exception:
            # Evita che una ristrutturazione parziale (es. tabella originale eliminata ma non rinominata) venga confermata in seguito
            self.conn.rollback()
            raise
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
            # Gli indici automatici (UNIQUE/PRIMARY KEY) non possono essere eliminati
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%';")
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

    def set_bulk_insert_mode(self, enabled: bool):
        """
            Durante l'inserimento massivo dal file JSON (un commit per ogni riga) mantiene il journal in memoria e disabilita 
            l'fsync ad ogni commit: il database viene comunque ricreato da zero ad ogni analisi.
            Il rollback della singola riga in caso di errore continua a funzionare.
        """
        self.conn.commit()      # Il journal_mode non può essere modificato durante una transazione
        
        cursor = self.conn.cursor()
        if(enabled):
            cursor.execute("PRAGMA journal_mode = MEMORY;")
            cursor.execute("PRAGMA synchronous = OFF;")
            logging.info("Modalità di inserimento massivo attivata.")
        else:
            cursor.execute("PRAGMA journal_mode = DELETE;")
            cursor.execute("PRAGMA synchronous = FULL;")
            logging.info("Modalità di inserimento massivo disattivata.")
        return

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
        except BaseException:
            # Interruzione (es. KeyboardInterrupt): annulla le operazioni parziali, evitando che vengano confermate in seguito
            self.conn.rollback()
            raise
        return

    def close(self):
        """Chiude la connessione al database."""
        if self.conn:
            self.conn.close()
            self.conn = None    # Evita una doppia chiusura (es. da close_connections a fine esecuzione)
            if(self.db_type == DatabaseType.LEAF):
                logging.info(f"Connessione al database Leaf chiusa con successo: 'file://{self.db_path}'")
            elif(self.db_type == DatabaseType.INTERMEDIATE):
                logging.info(f"Connessione al database Intermediate chiusa con successo: 'file://{self.db_path}'")
            elif(self.db_type == DatabaseType.ROOT):
                logging.info(f"Connessione al database Root chiusa con successo: 'file://{self.db_path}'")
        return
