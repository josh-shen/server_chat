from pymongo import MongoClient

def get_database():
    CONNECTION_STRING = "connection string"

    client = MongoClient(CONNECTION_STRING)

    return client["users"]
