import logging
from pymongo import MongoClient
from db.database import DatabaseType

class MongoDbDatabase:
    def __init__(self, db_name: DatabaseType, uri='mongodb://localhost:27017/'):
        """
        Inizializza la connessione al database MongoDB.
        """
        self.uri = uri
        self.client = None
        self.db = None
        
        if(db_name == DatabaseType.LEAF):
            self.db_name = 'Leaf_Zlint_Checks'
        elif(db_name == DatabaseType.INTERMEDIATE):
            self.db_name = 'Intermediate_Zlint_Checks'
        else:
            self.db_name = 'Root_Zlint_Checks'
    
    def connect(self):
        """
        Stabilisce la connessione al database.
        """
        if self.client is None:
            try:
                self.client = MongoClient(self.uri)
                self.client.drop_database(self.db_name)
                self.db = self.client[self.db_name]
                logging.info(f"Connessione al database '{self.db_name}' stabilita.")
            except Exception as e:
                logging.error(f"Errore durante la connessione a MongoDB: {e}")
                raise
    
    def get_collection(self, collection_name):
        """
        Restituisce la collezione specificata dal nome.
        """
        if self.db is None:
            self.connect()
        return self.db[collection_name]

    def close(self):
        """
        Chiude la connessione al database.
        """
        if self.client:
            self.client.close()
            logging.info("Connessione a MongoDB chiusa.")

