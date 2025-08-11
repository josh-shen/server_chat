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

def get_users(database):
    clients = {}
    users = database["users"]
    item_details = users.find()

    for item in item_details:
        user = {
            "username": item["username"],
            "password": item["password"],
            "salt": None,
            "salted_password": None,
            "port": None,
            "cookie": None,
            "socket": None,
        }
        clients[str(item["_id"])] = user
    
    return clients

def get_sessions(database):
    chat_sessions = {}
    sessions = database["sessions"]
    item_details = sessions.find()

    for item in item_details:
        session = {
            "user1": item["user1"],
            "user2": item["user2"],
            "history": item["history"]
        }
        chat_sessions[str(item["_id"])] = session
    
    return chat_sessions

