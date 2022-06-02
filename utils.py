import os
from uuid import uuid4

def messageDict(senderID, message_type, message_body = None, targetID = None, cookie = None, hashed_password = None, salt = None):
    return { 
    'senderID' : senderID, 
    'message_type' : message_type,
    'message_body' : message_body,
    'targetID' : targetID,
    'cookie': cookie,
    }

def screenClear():
    if os.name == 'posix':
        os.system('clear')
    else:
        os.system('cls')