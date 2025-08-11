import bcrypt, pickle, socket

from utils import messageDict, SERVER_ADDRESS

UDP_address = SERVER_ADDRESS
UDP_port = 3389

class client_API:
    def __init__(self, client_username, client_key):
        self.udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_client.connect((UDP_address, UDP_port))
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_username = client_username
        self.client_key = client_key
        self.clientID = None
        self.salt = None
        self.cookie = None

    # UDP section
    def HELLO(self):
        self.udp_client.send(str.encode("HELLO " + str(self.client_username)))

    def RESPONSE(self, password, salt):
        salted_password = bcrypt.hashpw(str(password).encode(), salt)
        message = str.encode("RESPONSE ")
        self.salt = salt # need this for decryption
        self.udp_client.send(message + salted_password)
    
    # TCP section
    def CONNECT(self, machine):
        message = messageDict(message_type="CONNECT", senderID=self.clientID, username=self.client_username, cookie=self.cookie)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def CHAT_REQUEST(self, target_username, machine):
        message = messageDict(message_type="CHAT_REQUEST", senderID=self.clientID, username=self.client_username, target_username=target_username)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)

    def CHAT(self, body, target_username, sessionID, machine):
        message = messageDict(message_type="CHAT", senderID=self.clientID, username=self.client_username, target_username=target_username, sessionID=sessionID, message_body=body)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def END_REQUEST(self, target_username, sessionID, machine):
        message = messageDict(message_type="END_REQUEST", senderID=self.clientID, username=self.client_username, target_username=target_username, sessionID=sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
    
    def LOG_OFF_REQUEST(self, target_username, sessionID, machine):
        message = messageDict(message_type="LOG_OFF_REQUEST", senderID=self.clientID, username=self.client_username, target_username=target_username, sessionID=sessionID)
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)