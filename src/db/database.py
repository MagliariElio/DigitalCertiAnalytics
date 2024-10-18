import sqlite3
from sqlite3 import Connection
from contextlib import contextmanager
import logging
import os

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

class Database:
    def __init__(self, db_path: str, schema_path: str):
        self.db_path = db_path
        self.schema_path = schema_path
        self.conn: Connection = None

    def connect(self, delete_database=True):
        """Crea una connessione al database SQLite."""
        if(delete_database == True and os.path.exists(self.db_path)):
            os.remove(self.db_path)
            logging.info(f"Database eliminato con successo: {self.db_path}")

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # per accedere ai risultati come dizionari
        self._initialize_database()

    def _initialize_database(self):
        """Crea le tabelle e gli indici se non esistono."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if not tables:
            self.create_tables()
            self.create_indexes()
        else:
            logging.info(f"Connessione al database esistente: {self.db_path}")

    def create_tables(self):
        """Crea le tabelle nel database utilizzando lo schema SQL."""
        with open(self.schema_path, 'r') as f:
            schema_sql = f.read()
        cursor = self.conn.cursor()
        cursor.executescript(schema_sql)
        self.conn.commit()
        logging.info("Tabelle create con successo.")

    def create_indexes(self):
        """Crea gli indici per migliorare le prestazioni delle query."""
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON Certificates(serial_number);
            CREATE INDEX IF NOT EXISTS idx_issuers_issuer_dn ON Issuers(issuer_dn);
            CREATE INDEX IF NOT EXISTS idx_subjects_subject_dn ON Subjects(subject_dn);
            CREATE INDEX IF NOT EXISTS idx_certificates_validity_start ON Certificates(validity_start);
            CREATE INDEX IF NOT EXISTS idx_certificates_validity_end ON Certificates(validity_end);
        """)
        self.conn.commit()
        logging.info("Indici creati con successo.")

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

    def close(self):
        """Chiude la connessione al database."""
        if self.conn:
            self.conn.close()
            logging.info("Connessione al database chiusa.")
