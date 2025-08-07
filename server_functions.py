import pickle, time

from utils import messageDict, session_timeouts, TIMEOUT_VAL, terminal_print
from aes import create_machine

# UDP section
def CHALLENGE(socket, addr, rand):
    resp = "CHALLENGE "
    message = resp.encode() + rand
    socket.sendto(message, addr)

def AUTH_SUCCESS(socket, addr, clientID, cookie, password, salt, port, host):
    resp = f"AUTH_SUCCESS {str(clientID)} {str(port)} {str(host)} {cookie} "
    machine = create_machine(password, salt)
    encrypted_message = machine.encrypt_message(resp)
    auth_type = "as ".encode()
    encrypted_message = auth_type + encrypted_message
    socket.sendto(encrypted_message, addr)

def AUTH_FAIL(socket, addr):
    resp = "AUTH_FAIL "
    message = resp.encode()
    socket.sendto(message, addr)

# TCP section
def CONNECTED(socket, machine):
    message = messageDict(senderID="SERVER", message_type="CONNECTED", message_body="connected to server")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def CHAT_STARTED (socket, target_client_username, sessionID, machine):
    body = f"connected to client [{target_client_username}]"
    message = messageDict(senderID="SERVER", target_username=target_client_username, sessionID=sessionID, message_type="CHAT_STARTED", message_body=body)
    pickleMessage = pickle.dumps(message)
    encMessage = machine.encrypt_message(pickleMessage) 
    socket.send(encMessage)   

def UNREACHABLE(socket, target_client_username, machine):
    body = f"client [{target_client_username}] is unreachable"
    message = messageDict(senderID="SERVER_ERROR", target_username=target_client_username, message_type="UNREACHABLE", message_body=body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def END_NOTIF(socket, machine):
    body = "session has been terminated"
    message = messageDict(senderID = "SERVER_ERROR", message_type = "END_NOTIF", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def TIMEOUT_WARNING(socket, machine):
    body = "chat is disconnecting in 15 seconds, send a message to reset the timer"
    message = messageDict(senderID = "SERVER_WARNING", message_type = "TIMEOUT_WARN", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def LOG_OFF(socket, machine):
    message = messageDict(senderID = "SERVER", message_type = "LOG_OFF")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def TIMEOUT(session, sessionIDs, lock, connected_pair, client, socket1, socket2, machine1, machine2):
    terminal_print(f"\nTimeout thread started for session {session}\n", "info")
    
    timeout = False

    # start timeout counter
    lock.acquire()
    session_timeouts[session] = TIMEOUT_VAL
    lock.release()

    while True:
        time.sleep(1)

        lock.acquire()
        session_timeouts[session] -= 1
        timeout_time = session_timeouts[session]
        lock.release()

        timeout = True if timeout_time == 0 else False

        if timeout_time <= 0:
            lock.acquire()
            session_timeouts[session] = 0
            lock.release()

            terminal_print(f"Exiting timeout thread for session {session}\n", "info")
            break  # timeout
        elif timeout_time == 15:
            TIMEOUT_WARNING(socket1, machine1)
            TIMEOUT_WARNING(socket2, machine2)

            terminal_print(f"Sending timeout warning to session {session}\n", "info")

    # end connection with other client if timeout
    if timeout:
        # remove client pair
        client_pair = [
            tuple_elem
            for tuple_elem in connected_pair
            if tuple_elem[0] == client or tuple_elem[1] == client
        ]

        if client_pair:
            connected_pair.remove(client_pair[0])
        # remove session
        lock.acquire()
        sessionIDs.remove(session)
        lock.release()

        END_NOTIF(socket1, machine1)
        END_NOTIF(socket2, machine2)

        terminal_print(f"Session {session} timed out\n", "error")

def DISCONNECT(connectionID, clients, inputs, online_clientIDs):
    socket_index = online_clientIDs.index(connectionID)
    response_socket = inputs[socket_index + 2]
    machine = create_machine(clients[connectionID]["password"], clients[connectionID]["salt"])
    END_NOTIF(response_socket, machine)

def CLOSE(senderID, targetID, sessionID, online_sessionIDs, lock, connected_pair, clients, inputs, online_clientIDs):
    client_pair = [
        tupleElem for tupleElem in connected_pair 
        if tupleElem[0] == senderID 
        or tupleElem[1] == senderID
    ]

    if client_pair:
        lock.acquire()
        # exit timeout thread for session by setting timeout = 0
        session_timeouts[sessionID] = 0
        lock.release()

        connected_pair.remove(client_pair[0])
        online_sessionIDs.remove(sessionID)

        DISCONNECT(senderID, clients, inputs, online_clientIDs)
        DISCONNECT(targetID, clients, inputs, online_clientIDs)

        terminal_print(f"\nSession {sessionID} removed\n", "info")