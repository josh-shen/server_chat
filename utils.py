import os
from uuid import uuid4

#global constants
TIMEOUT_VAL = 20

def messageDict(senderID, message_type, username = None, message_body = None, targetID = None, cookie = None, salt = None, sessionID = None):
    return { 
    'senderID' : senderID, 
    'message_type' : message_type,
    'username': username,
    'message_body' : message_body,
    'targetID' : targetID,
    'cookie': cookie,
    'sessionID': sessionID
    }

def screenClear():
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
