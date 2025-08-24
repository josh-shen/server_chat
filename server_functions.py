import pickle, time

from utils import messageDict, session_timeouts, TIMEOUT_VAL, terminal_print

# AUTH section
def AUTH_SUCCESS(socket, clientID, salt):
    message = messageDict(message_type="AUTH_SUCCESS", senderID="SERVER", targetID=clientID, message_body=salt)
    bytes = pickle.dumps(message)
    socket.send(bytes)

def AUTH_FAIL(socket):
    message = messageDict(message_type="AUTH_FAIL", senderID="SERVER")
    bytes = pickle.dumps(message)
    socket.send(bytes)

# CONNECTED section
def CHAT_INIT(socket, machine, targetID, target_username, sessionID, session_salt):
    message = messageDict(message_type="CHAT_INIT", senderID="SERVER", targetID=targetID, target_username=target_username, sessionID=sessionID, message_body=session_salt)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def CHAT_STARTED (socket, machine, targetID, target_client_username, sessionID, key, history):
    server_message = f"connected to client [{target_client_username}]"
    body = {"server_message": server_message, "key": key, "body": history}
    message = messageDict(message_type="CHAT_STARTED", senderID="SERVER", targetID=targetID, target_username=target_client_username, sessionID=sessionID, message_body=body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes) 
    socket.send(encrypted_bytes)   

def UNREACHABLE(socket, machine, target_client_username):
    body = f"client [{target_client_username}] is unreachable"
    message = messageDict(message_type="UNREACHABLE", senderID="SERVER_ERROR", target_username=target_client_username, message_body=body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def END_NOTIF(socket, machine):
    body = "session has been terminated"
    message = messageDict(message_type="END_NOTIF", senderID="SERVER_ERROR", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def TIMEOUT_WARNING(socket, machine):
    body = "chat is disconnecting in 15 seconds, send a message to reset the timer"
    message = messageDict(message_type="TIMEOUT_WARN", senderID="SERVER", message_body = body)
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def LOG_OFF_NOTIF(socket, machine):
    message = messageDict(message_type = "LOG_OFF_NOTIF", senderID = "SERVER")
    unencrypted_bytes = pickle.dumps(message)
    encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
    socket.send(encrypted_bytes)

def TIMEOUT(session, sessionIDs, lock, connected_pair, online_clients, clientID, socket1, socket2, machine1, machine2):
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
            if tuple_elem[0] == clientID or tuple_elem[1] == clientID
        ]

        if client_pair:
            lock.acquire()
            del online_clients[client_pair[0][0]]["public_key"]
            del online_clients[client_pair[0][1]]["public_key"]

            connected_pair.remove(client_pair[0])
            lock.release()
            
        # remove session
        lock.acquire()
        sessionIDs.remove(session)
        lock.release()

        END_NOTIF(socket1, machine1)
        END_NOTIF(socket2, machine2)

        terminal_print(f"Session {session} timed out\n", "error")

def DISCONNECT(clientID, inputs, online_clients):
    socket_index = online_clients[clientID]["index"]
    response_socket = inputs[socket_index]
    machine = online_clients[clientID]["machine"]
    END_NOTIF(response_socket, machine)

def CLOSE(inputs, senderID, targetID, connected_pair, online_clients, sessionID, online_sessionIDs, database, lock):
    client_pair = [
        tupleElem for tupleElem in connected_pair 
        if tupleElem[0] == senderID 
        or tupleElem[1] == senderID
    ]

    if client_pair:
        lock.acquire()
        # exit timeout thread for session by setting timeout = 0
        session_timeouts[sessionID] = 0

        del online_clients[senderID]["public_key"]
        del online_clients[targetID]["public_key"]
        
        connected_pair.remove(client_pair[0])
        online_sessionIDs.remove(sessionID)
        lock.release()

        DISCONNECT(senderID, inputs, online_clients)
        DISCONNECT(targetID, inputs, online_clients)

        terminal_print(f"\nSession {sessionID} removed\n", "info")