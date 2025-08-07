import os
from uuid import uuid4

# globals
TIMEOUT_VAL = 60
PRIVATE_ADDRESS = 'localhost'   # server internal IP address, use 'localhost' for testing
SERVER_ADDRESS = 'localhost'    # server external IP address, use 'localhost' for testing
session_timeouts = {}

def messageDict(message_type, senderID, username=None, message_body=None, targetID=None, target_username=None, cookie=None, sessionID=None):
    return { 
        'message_type': message_type,
        'senderID': senderID,
        'username': username,
        'message_body': message_body,
        'targetID': targetID,
        'target_username': target_username,
        'cookie': cookie,
        'sessionID': sessionID
    }

def clear_screen():
    if os.name == 'posix':
        os.system('clear')
    else:
        os.system('cls')
        
def gen_sessionID(existing_sessionIDs):
    while True:
        i = uuid4().int
        mask = '0b111111111111111111111111111111111111111111111111111111111111111'
        i = i & int(mask, 2)
        if i not in existing_sessionIDs:
            return i

def username_to_ID(db, username):
    for n in db:
        if db[n]["username"] == username:
            return n
    
    return None # TODO error handling when this function returns None