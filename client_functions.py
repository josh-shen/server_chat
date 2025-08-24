import pickle, socket

from utils import messageDict, SERVER_ADDRESS, PORT

class client_API:
    def __init__(self, client_username, client_key):
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_username = client_username
        self.client_key = client_key
        self.clientID = "000000000000000000000000"
        self.salt = None
        self.cookie = None

    # AUTH section
    def HELLO(self):
        self.tcp_client.connect((SERVER_ADDRESS, PORT))

    def CONNECT(self):
        message = messageDict(message_type="CONNECT", senderID=self.clientID, username=self.client_username, message_body=self.client_key)
        bytes = pickle.dumps(message)
        message = self.clientID.encode() + bytes
        self.tcp_client.send(message)
    
    # CONNECTED section    
    def CHAT_REQUEST(self, machine, target_username):
        message = messageDict(message_type="CHAT_REQUEST", senderID=self.clientID, username=self.client_username, target_username=target_username)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)

    def CHAT_RESPONSE(self, machine, targetID, target_username, sessionID,  key):
        message = messageDict(message_type="CHAT_RESPONSE", senderID=self.clientID, username=self.client_username, targetID=targetID, target_username=target_username, sessionID=sessionID, message_body=key)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)

    def CHAT(self, machine, message_machine, targetID, target_username, sessionID, body):
        unencrypted_bytes = body.encode("utf-8")
        encrypted_bytes = message_machine.encrypt_message(unencrypted_bytes)
        message = messageDict(message_type="CHAT", senderID=self.clientID, username=self.client_username, targetID=targetID, target_username=target_username, sessionID=sessionID, message_body=encrypted_bytes)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def END_REQUEST(self, machine, targetID, target_username, sessionID):
        message = messageDict(message_type="END_REQUEST", senderID=self.clientID, username=self.client_username, targetID=targetID, target_username=target_username, sessionID=sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def LOG_OFF_REQUEST(self, machine, targetID, target_username, sessionID):
        message = messageDict(message_type="LOG_OFF_REQUEST", senderID=self.clientID, username=self.client_username, targetID=targetID, target_username=target_username, sessionID=sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)