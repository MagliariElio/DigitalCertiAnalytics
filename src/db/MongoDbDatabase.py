from __future__ import annotations

import logging

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database as PyMongoDatabase

from db.database import DatabaseType

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# MongoDB database holding the ZLint results of each certificate type
ZLINT_DB_NAMES = {
    DatabaseType.LEAF: 'Leaf_Zlint_Checks_Google_3',
    DatabaseType.INTERMEDIATE: 'Intermediate_Zlint_Checks_Google_3',
    DatabaseType.ROOT: 'Root_Zlint_Checks',
}


class MongoDbDatabase:
    """MongoDB database of the ZLint results for one certificate type."""

    def __init__(self, db_type: DatabaseType, uri: str = 'mongodb://localhost:27017/'):
        self.uri = uri
        self.db_name = ZLINT_DB_NAMES[db_type]
        self.client: MongoClient | None = None
        self.db: PyMongoDatabase | None = None

    def connect(self) -> None:
        """Connect, dropping the results of a previous run."""
        if self.client is not None:
            return
        try:
            self.client = MongoClient(self.uri)
            logging.info(f"Eliminazione dei risultati precedenti presenti nel database MongoDB '{self.db_name}'.")
            self.client.drop_database(self.db_name)
            self.db = self.client[self.db_name]
            logging.info(f"Connessione al database '{self.db_name}' stabilita.")
        except Exception as e:
            logging.error(f"Errore durante la connessione a MongoDB: {e}")
            # Reset so a later call can retry instead of keeping an unusable client
            if self.client is not None:
                self.client.close()
            self.client = None
            self.db = None
            raise

    def get_collection(self, name: str) -> Collection:
        """Return the named collection, connecting on first use."""
        if self.db is None:
            self.connect()
        return self.db[name]

    def close(self) -> None:
        """Close the connection."""
        if self.client is None:
            return
        self.client.close()
        self.client = None
        logging.info("Connessione a MongoDB chiusa.")
