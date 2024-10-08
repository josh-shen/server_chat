from pymongo import MongoClient
from pymongo.server_api import ServerApi

def get_database():
    CONNECTION_STRING = ""

    client = MongoClient(CONNECTION_STRING, server_api=ServerApi('1'))

    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
    except Exception as e:
        print(e)

    return client["users"]

def query(database):
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