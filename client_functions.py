import bcrypt, pickle, socket

from utils import messageDict, SERVER_ADDRESS
from aes import create_machine

UDP_address = SERVER_ADDRESS
UDP_port = 3389

class client_API:
    def __init__(self, clientID, client_key):
        self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_client.connect((UDP_address, UDP_port))
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientID = clientID
        self.client_key = client_key
        self.salt = None

    # UDP SECTION
    def HELLO(self):
        self.udp_client.send(str.encode("HELLO " + str(self.clientID)))

    def RESPONSE(self, password, salt):
        salted_password = bcrypt.hashpw(str(password).encode(), salt)
        message = str.encode("RESPONSE ")
        self.salt = salt # need this for decryption
        self.udp_client.send(message + salted_password)
    
    # TCP SECTION
    def CONNECT(self, cookie, machine):
        message = messageDict(self.clientID, "CONNECT", cookie = cookie)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def CHAT_REQUEST(self, targetID, machine):
        message = messageDict(self.clientID, message_type = "CHAT_REQUEST", targetID = targetID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)

    def CHAT(self, body, targetID, sessionID, machine):
        message = messageDict(senderID = self.clientID, message_type = "CHAT", message_body = body, targetID = targetID, sessionID = sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def END_REQUEST(self, targetID, sessionID, machine):
        message = messageDict(self.clientID, targetID = targetID, sessionID = sessionID, message_type = "END_REQUEST")
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def LOG_OFF(self, targetID, sessionID, machine):
        message = messageDict(self.clientID, message_type = "LOG_OFF", targetID = targetID, sessionID = sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
