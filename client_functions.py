import bcrypt, pickle, socket

from utils import messageDict
from aes import create_machine

UDP_address = 'localhost'
UDP_port = 6265

class client_API:
    def __init__(self, clientID, client_key):
        self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_client.connect((UDP_address, UDP_port))
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientID = clientID
        self.client_key = client_key
        self.salt = None

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
    
    def CHAT_REQUEST(self, targetID, cookie):
        message = messageDict(self.clientID, message_type = "CHAT_REQUEST", targetID = targetID, cookie = cookie)
        machine = create_machine(self.client_key, self.salt)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
      
    def CHAT(self, body, targetID, cookie, machine):
        message = messageDict(senderID = self.clientID, message_type = "CHAT", message_body = body, targetID = targetID, cookie = cookie)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def END_REQUEST(self, targetID):
        endNotifMessage = messageDict(self.clientID, targetID = targetID, message_type = "END_REQUEST")
        machine = create_machine(self.client_key, self.salt)
        unencBytes = pickle.dumps(endNotifMessage)
        encMessage = machine.encrypt_message(unencBytes)
        totMessage = self.clientID.encode() + encMessage
        self.tcp_client.send(totMessage)
        
    def LOG_OFF(self, targetID, machine):
        message = messageDict(self.clientID, message_type = "LOG_OFF", targetID = targetID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
