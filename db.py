from pymongo import MongoClient
from pymongo.server_api import ServerApi

import utils

def get_database():
    CONNECTION_STRING = ""

    client = MongoClient(CONNECTION_STRING, server_api=ServerApi('1'))

    # Send a ping to confirm a successful connection
    try:
        client.admin.command("ping")
        utils.terminal_print("Connected to MongoDB", "success")
    except Exception as e:
        utils.terminal_print(e, "error")

    return client["server"]

def get_document(database, filter):
    return database.find_one(filter)