from __future__ import annotations

import logging

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database as PyMongoDatabase

from db.database import DatabaseType
from db.mongo_server import DEFAULT_URI, BundledServer, app_name, ensure_mongodb

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

    def __init__(self, db_type: DatabaseType, uri: str = DEFAULT_URI):
        self.uri = uri
        self.db_name = ZLINT_DB_NAMES[db_type]
        self.client: MongoClient | None = None
        self.db: PyMongoDatabase | None = None
        self._server: BundledServer | None = None

    def connect(self) -> None:
        """Connect, dropping the results of a previous run.

        When nothing answers at a local URI, the MongoDB server included with the project is started (see
        db.mongo_server); MongoServerError, whose message says what to do, if it cannot be.
        """
        if self.client is not None:
            return
        self._server = ensure_mongodb(self.uri)
        try:
            self.client = MongoClient(self.uri, appname=app_name())
            logging.info(f"Dropping the previous results in the MongoDB database '{self.db_name}'.")
            self.client.drop_database(self.db_name)
            self.db = self.client[self.db_name]
            logging.info(f"Connected to the database '{self.db_name}'.")
        except Exception as e:
            logging.error(f"Error connecting to MongoDB: {e}")
            # Reset so a later call can retry instead of keeping an unusable client
            if self.client is not None:
                self.client.close()
            self.client = None
            self.db = None
            self._release_server()
            raise

    def get_collection(self, name: str) -> Collection:
        """Return the named collection, connecting on first use."""
        if self.db is None:
            self.connect()
        return self.db[name]

    def close(self) -> None:
        """Close the connection; the bundled MongoDB server stops when no other user is left."""
        if self.client is not None:
            self.client.close()
            self.client = None
            logging.info("MongoDB connection closed.")
        self._release_server()

    def _release_server(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.release()
