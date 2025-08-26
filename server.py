import bcrypt, pickle, queue, socket, select, threading
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
    PORT = utils.PORT

    # create server TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setblocking(0)

    # sockets
    inputs = [tcp_socket]
    outputs = []

    # connection varaibles
    online_clients = {}
    connected_pair = []
    message_queues = {}
    online_sessionIDs = []

    # database query
    database = db.get_database()
    
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
            if s is tcp_socket:
                # establish TCP connection with client
                connection, client_address = tcp_socket.accept()

                utils.terminal_print(f"New connection from {client_address}\n", "success")

                connection.setblocking(0) # non-blocking
                inputs.append(connection)
                message_queues[connection] = queue.Queue()
            else:
                bytes = s.recv(65536) # 2^16 bytes
                if len(bytes) < 24:
                    # invalid message
                    continue
                
                id = bytes[:24].decode("utf-8")

                if id == "000000000000000000000000":
                    message = pickle.loads(bytes[24:])          
                    client = db.get_document(database["users"], {"username": message["username"]})
                    
                    # client does not exist
                    if not client:
                        sv.AUTH_FAIL(s)
                        utils.terminal_print("Authentication failed\n", "error")
                        continue

                    clientID = str(client["_id"])
                    
                    # client already logged in
                    if clientID in online_clients:
                        sv.AUTH_FAIL(s)
                        utils.terminal_print("Authentication failed\n", "error")
                        continue

                    # hash password with salt
                    hashed_password = bcrypt.hashpw(message["message_body"].encode(), client["salt"])
                    
                    if hashed_password == client["password"]:
                        salt = bcrypt.gensalt()
                        machine = create_machine(clientID, salt)

                        lock.acquire()
                        online_clients[clientID] = {"machine": machine, "index": len(inputs) - 1, "socket": s} 
                        lock.release()

                        sv.AUTH_SUCCESS(s, clientID, salt)
                        utils.terminal_print(f"Authentication successful: client {clientID} logged in\n", "success")
                    else:
                        sv.AUTH_FAIL(s)
                        utils.terminal_print("Authentication failed\n", "error")
                    continue
                else:
                    client = db.get_document(database["users"], {"_id": ObjectId(id)})

                    # decrypt received message - from here all messages will be encrypted
                    encrypted_bytes = bytes[24:]
                    machine = online_clients[id]["machine"]
                    decrypted_bytes = machine.decrypt_message(encrypted_bytes)
                    message = pickle.loads(decrypted_bytes)

                    utils.terminal_print(f"Received {message["message_type"]} from {message["senderID"]}")
                    
                if message["message_type"] == "CHAT_REQUEST":
                    senderID = message["senderID"]

                    target_client = db.get_document(database["users"], {"username": message["target_username"]})

                    if not target_client:
                        # client does not exist
                        senderID = message["senderID"]
                        socket_index = online_clients[senderID]["index"]
                        response_socket = inputs[socket_index]
                        sv.UNREACHABLE(response_socket, machine, message["target_username"])
                        continue

                    targetID = str(target_client["_id"])

                    # check if target client is online
                    if targetID in online_clients:
                        # check if target is already in a chat, check if targetID is not same as senderID
                        paired = [
                            tuple_elem
                            for tuple_elem in connected_pair
                            if tuple_elem[0] == targetID or tuple_elem[1] == targetID
                        ]

                        if not paired and senderID != targetID:
                            # add clients to connected pair
                            lock.acquire()
                            connected_pair.append(tuple((senderID, targetID)))
                            lock.release()

                            # check if session exists in database
                            session = db.get_document(database["sessions"], {"$or": [
                                {"user1": senderID, "user2": targetID},
                                {"user1": targetID, "user2": senderID}
                            ]})
                            
                            # first time chatting, create session ID and add to database
                            if not session:                      
                                session_salt = bcrypt.gensalt()
                                s = {
                                    "user1": senderID,
                                    "user2": targetID,
                                    "salt": session_salt,
                                    "history": []
                                }

                                res = database["sessions"].insert_one(s)
                                sessionID = str(res.inserted_id)
                            else:
                                sessionID = str(session["_id"])
                                session_salt = session["salt"]                            

                            lock.acquire()
                            online_sessionIDs.append(sessionID)
                            lock.release()

                            # send chat init message to both clients
                            socket_index = online_clients[senderID]["index"]
                            sender_socket = inputs[socket_index]
                            sv.CHAT_INIT(sender_socket, machine, targetID, message["target_username"], sessionID, session_salt)

                            socket_index = online_clients[targetID]["index"]
                            target_socket = inputs[socket_index]
                            target_machine = online_clients[targetID]["machine"]
                            sv.CHAT_INIT(target_socket, target_machine, senderID, message["username"], sessionID, session_salt)
                        else:
                            # target is already in a chat, or target is same as sender
                            senderID = message["senderID"]
                            socket_index = online_clients[senderID]["index"]
                            response_socket = inputs[socket_index]
                            sv.UNREACHABLE(response_socket, machine, message["target_username"])
                    else:
                        # target client is not online
                        senderID = message["senderID"]
                        socket_index = online_clients[senderID]["index"]
                        response_socket = inputs[socket_index]
                        sv.UNREACHABLE(response_socket, machine, message["target_username"])
                elif message["message_type"] == "CHAT_RESPONSE":
                    senderID = message["senderID"]
                    targetID = message["targetID"]
                    target_client = db.get_document(database["users"], {"username": message["target_username"]})

                    key = message["message_body"]
                    lock.acquire()
                    online_clients[senderID]["public_key"] = key
                    lock.release()

                    # wait for both clients to exchange keys
                    if "public_key" not in online_clients[targetID]:
                        continue
                    
                    session = db.get_document(database["sessions"], {"_id": ObjectId(message["sessionID"])})
                    chat_history = session["history"]       

                    # find sockets, exchange public keys, notify both clients of chat connection
                    socket_index = online_clients[senderID]["index"]
                    sender_socket = inputs[socket_index]
                    sv.CHAT_STARTED(sender_socket, machine, targetID, message["target_username"], sessionID, online_clients[targetID]["public_key"], chat_history)

                    socket_index = online_clients[targetID]["index"]
                    target_socket = inputs[socket_index]
                    sv.CHAT_STARTED(target_socket, online_clients[targetID]["machine"], senderID, message["username"], sessionID, online_clients[senderID]["public_key"], chat_history)
                    
                    # start timer thread
                    timer_thread = threading.Thread(target=sv.TIMEOUT, args=(sessionID, online_sessionIDs, lock, connected_pair, online_clients, senderID, sender_socket, target_socket, machine, online_clients[targetID]["machine"]))
                    timer_thread.start()
                elif message["message_type"] == "END_REQUEST":
                    senderID = message["senderID"]
                    targetID = message["targetID"]
                    sessionID = message["sessionID"]
                    sv.CLOSE(inputs, senderID, targetID, connected_pair, online_clients, sessionID, online_sessionIDs, database, lock) 
                    continue
                elif message["message_type"] == "LOG_OFF_REQUEST":
                    senderID = message["senderID"]
                    targetID = message["targetID"]
                    socket_index = online_clients[senderID]["index"]
                    response_socket = inputs[socket_index]
                    sv.LOG_OFF_NOTIF(response_socket, machine)

                    # if logging off from a chat session, end the chat session
                    if message["sessionID"] != None:
                        sv.CLOSE(inputs, senderID, targetID,  connected_pair, online_clients, message["sessionID"], online_sessionIDs, database, lock)                    
                    
                    # end TCP connection
                    client_socket = online_clients[senderID]["socket"]
                    if client_socket in inputs:
                        index = inputs.index(client_socket)
                        inputs.remove(client_socket)
                        
                        # update socket index for all other clients
                        other_clients = {id: client for id, client in online_clients.items() if client["index"] > index}
                        for id in other_clients:
                            other_clients[id]["index"] -= 1
                    if client_socket in outputs:
                        outputs.remove(client_socket)

                    lock.acquire()
                    del online_clients[senderID]
                    lock.release()
                    
                    continue
                elif message["message_type"] == "CHAT":
                    # construct message and add to message queue
                    outgoing_message = utils.messageDict(
                        message_type="CHAT",
                        senderID=message["senderID"],
                        username=message["username"],
                        targetID=message["targetID"],
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
                client_pair = [
                    tupleElem for tupleElem in connected_pair
                    if tupleElem[0] == next_message["senderID"]
                    or tupleElem[1] == next_message["senderID"]
                ]

                # find target client in connected pair
                if client_pair[0][0] == next_message["senderID"]:
                    target = online_clients[client_pair[0][1]]["index"]
                else:
                    target = online_clients[client_pair[0][0]]["index"]
                
                # add message to session chat history in database
                message_body = {next_message['username']: next_message['message_body'].decode("utf-8")}
                session = db.get_document(database["sessions"], {"_id": ObjectId(message["sessionID"])})
                chat_history = session["history"][-9:]
                chat_history.append(message_body)
                database["sessions"].update_one({"_id": ObjectId(message["sessionID"])}, {"$set": {"history": chat_history}})

                targetID = next_message["targetID"]
                target_client = db.get_document(database["users"], {"_id": ObjectId(targetID)})

                # encrypt message and send
                machine = online_clients[targetID]["machine"]
                unencrypted_bytes = pickle.dumps(next_message)
                encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
                inputs[target].send(encrypted_bytes)

                utils.terminal_print(f"Session {message['sessionID']}: sending [{next_message['message_body']}] to {next_message['targetID']}")

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
