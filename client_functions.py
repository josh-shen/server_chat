import bcrypt, pickle, socket

import utils
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

    # UDP SECTION
    def HELLO(self):
        self.udp_client.send(str.encode("HELLO " + str(self.clientID)))

    def RESPONSE(self, password, salt):
        salted_password = bcrypt.hashpw(str(password).encode(), salt)
        message = str.encode("RESPONSE ")
        self.salt = salt # need this for decryption
        self.udp_client.send(message + salted_password)
    
    # TCP SECTION
    def CONNECT(self, message, machine):
        unencrypted_bytes = pickle.dumps(message)
        encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
        message = self.clientID.encode() + encrypted_bytes
        self.tcp_client.send(message)
