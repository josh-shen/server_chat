import os

TIMEOUT_VAL = 60
PRIVATE_ADDRESS = 'localhost'   # server internal IP address, use 'localhost' for testing
SERVER_ADDRESS = 'localhost'    # server external IP address, use 'localhost' for testing
session_timeouts = {}

def messageDict(message_type, senderID, username=None, targetID=None, target_username=None, sessionID=None, message_body=None, cookie=None):
    return { 
        "message_type": message_type,
        "senderID": senderID,
        "username": username,
        "targetID": targetID,
        "target_username": target_username,
        "sessionID": sessionID,
        "message_body": message_body,
        "cookie": cookie,
    }

def terminal_print(message, type = None):
    if type == "error":
        print(f"\033[91m{message}\033[0m")
    elif type == "success":
        print(f"\033[92m{message}\033[0m")
    elif type == "info":
        print(f"\033[93m{message}\033[0m")
    elif type == "client":
        print(f"\033[94m{message}\033[0m")
    else:
        print(message)

def clear_line():
    print("\033[1A\033[K", end="")

def clear_screen():
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")