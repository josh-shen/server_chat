import socket, pickle

from utils import messageDict
from aes import aes_cipher, create_machine

# UDP SECTION
def CHALLENGE(socket, addr, clientID, rand):
    resp = "CHALLENGE "
    message = resp.encode() + rand
    socket.sendto(message, addr)

def AUTH_SUCCESS(socket, addr, clientID, cookie, password, salt, port, host):
    resp = "AUTH_SUCCESS " + str(clientID) + " " + str(port) + " " + str(host) + " " + cookie
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
    message = messageDict(senderID="SERVER", message_type="CONNECTED", message_body="connected to server")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def CHAT_STARTED (socket, target_client_username, sessionID, machine):
    body = "connected to client [" + target_client_username +"]" 
    message = messageDict(senderID="SERVER", target_username=target_client_username, sessionID=sessionID, message_type="CHAT_STARTED", message_body=body)
    pickleMessage = pickle.dumps(message)
    encMessage = machine.encrypt_message(pickleMessage) 
    socket.send(encMessage)   

def UNREACHABLE(socket, target_client_username, machine):
    body = "client [" + target_client_username + "] is unreachable"
    message = messageDict(senderID="SERVER", target_username=target_client_username, message_type="UNREACHABLE", message_body=body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def END_NOTIF(socket, machine):
    body = "session has been terminated"
    message = messageDict(senderID = "SERVER", message_type = "END_NOTIF", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def TIMEOUT_WARNING(socket, machine):
    body = "chat is disconnecting in 15 seconds, send or recive a message to reset the timer"
    message = messageDict(senderID = "SERVER", message_type = "TIMEOUT_WARN", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def LOG_OFF(socket, machine):
    message = messageDict(senderID = "SERVER", message_type = "LOG_OFF")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def disconnect_message(connectionID, clients, inputs, online_clientIDs):
    socket_index = online_clientIDs.index(connectionID)
    response_socket = inputs[socket_index + 2]
    machine = create_machine(clients[connectionID]["password"], clients[connectionID]["salt"])
    END_NOTIF(response_socket, machine)
