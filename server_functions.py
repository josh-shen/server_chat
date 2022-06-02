import socket, pickle

from utils import messageDict
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
def CONNECTED(socket, machine):
    message = messageDict(senderID = "SERVER", message_type = "CONNECTED", message_body = "connected to server")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def CHAT_STARTED (socket, target_clientID, machine):
    body = "connected to client with the ID[" + target_clientID +"]" 
    message = messageDict(senderID = 'Server', targetID=target_clientID, message_type='CHAT_STARTED',message_body=body)
    pickleMessage = pickle.dumps(message)
    encMessage = machine.encrypt_message(pickleMessage) 
    socket.send(encMessage)   

def UNREACHABLE(socket, target_clientID, machine):
    body = "client with ID[" + target_clientID + "] is unreachable"
    message = messageDict(senderID = "server", targetID = target_clientID, message_type = "UNREACHABLE", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)
