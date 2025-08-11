import bcrypt, pickle, queue, socket, select, threading
from secrets import token_urlsafe
from bson.objectid import ObjectId

from aes import create_machine
import server_functions as sv
import db
import utils

if __name__ == "__main__":
    lock = threading.Lock()

    # connection information
    INTERNAL_HOST = utils.PRIVATE_ADDRESS
    EXTERNAL_HOST = utils.SERVER_ADDRESS
    PORT = 3389

    # create server UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # create server TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setblocking(0)

    # sockets
    inputs = [udp_socket, tcp_socket]
    outputs = []

    # connection varaibles
    address_to_ID = {}
    online_clientIDs = []
    online_client_sockets = []
    connected_pair = []
    message_queues = {}
    online_sessionIDs = []

    # user database query
    database = db.get_database()
    clients = db.get_users(database)

    # bind UDP socket
    try:
        udp_socket.bind((INTERNAL_HOST, PORT))
    except socket.error as e:
        utils.terminal_print(str(e), "error")
        exit()
    # bind TCP socket
    try:
        tcp_socket.bind((INTERNAL_HOST, PORT))
    except socket.error as e:
        utils.terminal_print(str(e), "error")
        exit()
    tcp_socket.listen(16) # allow up to 16 connections

    utils.terminal_print("Server running\n", "success")
 
    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            if s is udp_socket:
                bytes, addr = udp_socket.recvfrom(2048)
                data = bytes.decode("utf-8").split()

                utils.terminal_print(f"Received: {data}")

                if data[0] == "HELLO":
                    client_username = data[1]
                    clientID = utils.find_userID(clients, client_username)

                    if not clientID:
                        sv.AUTH_FAIL(udp_socket, addr)
                        continue

                    address_to_ID[addr] = clientID

                    # start auth challenge for client
                    password = clients[clientID]["password"]
                    salt = clients[clientID]["salt"] = bcrypt.gensalt()
                    clients[clientID]["salted_password"] = bcrypt.hashpw(str(password).encode(), salt)
                    sv.CHALLENGE(udp_socket, addr, salt)
                if data[0] == "RESPONSE":
                    salted_password = data[1]
                    clientID = address_to_ID[addr]

                    if clients[clientID]["salted_password"] == salted_password.encode():
                        # authentication success, generate cookie to give to client
                        cookie = clients[clientID]["cookie"] = token_urlsafe(16)
                        password = clients[clientID]["password"]
                        salt = clients[clientID]["salt"]
                        sv.AUTH_SUCCESS(udp_socket, addr, clientID, cookie, password, salt, PORT, EXTERNAL_HOST)
                    else:
                        sv.AUTH_FAIL(udp_socket, addr)
            elif s is tcp_socket:
                # establish TCP connection with client
                connection, client_address = tcp_socket.accept()

                utils.terminal_print(f"\nNew connection from {client_address}\n", "success")

                connection.setblocking(0) # non-blocking
                inputs.append(connection)
                online_client_sockets.append(connection)
                message_queues[connection] = queue.Queue()
            else:
                id_encrypted_bytes = s.recv(65536) # 2^16 bytes
                if len(id_encrypted_bytes) < 24:
                    # invalid message
                    continue
                
                # decrypt received message - from here all messages will be encrypted
                id = id_encrypted_bytes[:24].decode("utf-8")
                encrypted_bytes = id_encrypted_bytes[24:]
                machine = create_machine(clients[id]["password"], clients[id]["salt"])
                decrypted_bytes = machine.decrypt_message(encrypted_bytes)
                message = pickle.loads(decrypted_bytes)

                utils.terminal_print(f"Received {message["message_type"]} from {message["senderID"]}")

                if message["message_type"] == "CONNECT":
                    # verify authentication with cookie, add client to list of online clients
                    if clients[id]["cookie"] == message["cookie"]:
                        connected_clientID = message["senderID"]
                        online_clientIDs.append(connected_clientID)
                        clients[connected_clientID]["socket"] = s
                        sv.CONNECTED(s, machine)
                    else:
                        # authentication failed - cookie mismatch
                        utils.terminal_print("Authentication failed", "error")
                    continue
                elif message["message_type"] == "CHAT_REQUEST":
                    senderID = message["senderID"]
                    targetID = utils.find_userID(clients, message["target_username"])
                    
                    # check if target client is online
                    online = targetID in online_clientIDs
                    if online:
                        # check if target is already in a chat, check if targetID is not same as senderID
                        paired = [
                            tuple_elem
                            for tuple_elem in connected_pair
                            if tuple_elem[0] == targetID or tuple_elem[1] == targetID
                        ]

                        if not paired and senderID != targetID:
                            # add clients to connected pair
                            connected_pair.append(tuple((senderID, targetID)))

                            # check if session exists in database
                            chat_sessions = db.get_sessions(database)
                            sessionID = utils.find_sessionID(chat_sessions, senderID, targetID)

                            if not sessionID:
                                # first time chatting, create session ID and add to database
                                session = {
                                    "user1": senderID,
                                    "user2": targetID,
                                    "history": []
                                }

                                res = database["sessions"].insert_one(session)
                                sessionID = res.inserted_id

                            lock.acquire()
                            online_sessionIDs.append(sessionID)
                            lock.release()

                            chat_history = chat_sessions[sessionID]["history"]       

                            # find sockets and notify both clients of chat connection
                            socket_index = online_clientIDs.index(senderID)
                            sender_socket = inputs[socket_index + 2]  # +2 to account for server udp and tcp socket
                            sv.CHAT_STARTED(sender_socket, message["target_username"], sessionID, machine, chat_history)

                            socket_index = online_clientIDs.index(targetID)
                            target_socket = inputs[socket_index + 2]
                            target_machine = create_machine(clients[targetID]["password"], clients[targetID]["salt"])
                            sv.CHAT_STARTED(target_socket, message["username"], sessionID, target_machine, chat_history)
                            
                            # start timer thread
                            timer_thread = threading.Thread(target=sv.TIMEOUT, args=(sessionID, online_sessionIDs, lock, connected_pair, senderID, sender_socket, target_socket, machine, target_machine))
                            timer_thread.start()
                        else:
                            # target is already in a chat, or target is same as sender
                            senderID = message["senderID"]
                            socket_index = online_clientIDs.index(senderID)
                            response_socket = inputs[socket_index + 2]
                            sv.UNREACHABLE(response_socket, message["target_username"], machine)
                    else:
                        # target client is not online
                        senderID = message["senderID"]
                        socket_index = online_clientIDs.index(senderID)
                        response_socket = inputs[socket_index + 2]
                        sv.UNREACHABLE(response_socket, message["target_username"], machine)
                elif message["message_type"] == "END_REQUEST":
                    senderID = message["senderID"]
                    targetID = utils.find_userID(clients, message["target_username"])
                    sessionID = message["sessionID"]
                    sv.CLOSE(senderID, targetID, sessionID, online_sessionIDs, lock, connected_pair, clients, inputs, online_clientIDs)                    
                    
                    continue
                elif message["message_type"] == "LOG_OFF_REQUEST":
                    senderID = message["senderID"]
                    targetID = utils.find_userID(clients, message["target_username"])
                    socket_index = online_clientIDs.index(senderID)
                    response_socket = inputs[socket_index + 2]
                    sv.LOG_OFF_NOTIF(response_socket, machine)

                    # if logging off from a chat session, end the chat session
                    if message["sessionID"] != None:
                        sv.CLOSE(senderID, targetID, sessionID, online_sessionIDs, lock, connected_pair, clients, inputs, online_clientIDs)                    
                    
                    # end TCP connection
                    online_clientIDs.remove(senderID)
                    socket = clients[senderID]["socket"]
                    if socket in inputs:
                        inputs.remove(socket)
                    if socket in outputs:
                        outputs.remove(socket)
                    
                    continue
                elif message["message_type"] == "CHAT":
                    # construct message and add to message queue
                    outgoing_message = utils.messageDict(
                        message_type="CHAT",
                        senderID=message["senderID"],
                        username=message["username"],
                        targetID=utils.find_userID(clients, message["target_username"]),
                        target_username=message["target_username"],
                        sessionID=message["sessionID"],
                        message_body=message["message_body"]
                    )
                    message_queues[s].put(outgoing_message)

                    if s not in outputs:
                        outputs.append(s)
        for s in writable:
            try:
                next_message = message_queues[s].get_nowait()
            except queue.Empty:
                outputs.remove(s)
            else:
                senderID = next_message["senderID"]
                next_message["username"] = clients[senderID]["username"]

                client_pair = [
                    tupleElem for tupleElem in connected_pair
                    if tupleElem[0] == next_message["senderID"]
                    or tupleElem[1] == next_message["senderID"]
                ]

                # find target client in connected pair
                if client_pair[0][0] == senderID:
                    target = online_clientIDs.index(client_pair[0][1])
                else:
                    target = online_clientIDs.index(client_pair[0][0])
                
                # add message to session chat history in database
                message_body = f"> {next_message['username']}: {next_message['message_body']}"
                sessions = database["sessions"]
                chat_sessions = db.get_sessions(database)
                current_session = chat_sessions[message["sessionID"]]
                chat_history = current_session["history"][-9:]
                chat_history.append(message_body)
                sessions.update_one({"_id": ObjectId(message["sessionID"])}, {"$set": {"history": chat_history}})

                # encrypt message and send
                targetID = next_message["targetID"]
                machine = create_machine(clients[targetID]["password"], clients[targetID]["salt"])
                unencrypted_bytes = pickle.dumps(next_message)
                encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
                inputs[target + 2].send(encrypted_bytes)

                utils.terminal_print(f"Session {message['sessionID']}: sending [{next_message['message_body']}] to {next_message['target_username']}")

                # reset timeout
                lock.acquire()
                utils.session_timeouts[sessionID] = utils.TIMEOUT_VAL
                lock.release()

                utils.terminal_print("\nMessage sent - reset timer\n", "info")
        for s in exceptional: # handle errors - close socket if error (not used right now)
            print("handling error")
            inputs.remove(s)
            if s in outputs:
                outputs.remove(s)
            s.close()
