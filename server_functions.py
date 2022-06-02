import socket, pickle

import utils
from aes import aes_cipher, create_machine

# UDP SECTION
def CHALLENGE(socket, addr, clientID, rand):
    resp = "CHALLENGE "
    message = resp.encode() + rand
    socket.sendto(message, addr)

def AUTH_SUCCESS(socket, addr, cookie, password, salt, port, host):
    resp = "AUTH_SUCCESS " + str(port) + " " + str(host) + " " + cookie
    machine = create_machine(password, salt)
    encrypted_message = machine.encrypt_message(resp)
    auth_type = 'as '.encode()
    encrypted_message = auth_type + encrypted_message
    socket.sendto(encrypted_message, addr)

def AUTH_FAIL(socket, addr):
    resp = "AUTH_FAIL "
    message = resp.encode()
    socket.sendto(message, addr)

# TCP SECTION
def CONNECTED(socket, message, machine):
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)
