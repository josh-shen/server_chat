import base64, hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class aes_cipher:
    def __init__(self, key):
        self.block_size = AES.block_size # block size of 16
        self.key = key

    def encrypt_message(self, input):
        if type(input) != bytes:
            input = input.encode()
        input = pad(input, self.block_size)
        #create a random initialization vector
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(input)
        iv_message = iv + encrypted_bytes
        return base64.urlsafe_b64encode(iv_message)

    def decrypt_message(self, b64_string):
        iv_message = base64.urlsafe_b64decode(b64_string)
        iv = iv_message[:self.block_size]
        encrypted_bytes = iv_message[self.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_output = cipher.decrypt(encrypted_bytes)
        return unpad(padded_output, self.block_size)

def create_machine(client_key, salt):
    ck_a = hashlib.pbkdf2_hmac('SHA256', str(client_key).encode(), salt, 100000)
    machine = aes_cipher(ck_a)
    return machine 