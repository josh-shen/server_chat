import bcrypt, pickle, queue, socket, select, secrets, time, threading
from secrets import token_urlsafe

from aes import create_machine
import server_functions as sv
import db
import utils

lock = threading.Lock()
# CONNECTION INFORMATION
INTERNAL_HOST = utils.PRIVATE_ADDRESS # server internal IP address
EXTERNAL_HOST = utils.SERVER_ADDRESS
PORTS = [3389] # have multiple ports available ?
TIMEOUT_TIME = utils.TIMEOUT_VAL

def chat_timeout(session, sessionIDs, connected_pair, client, socket1, socket2, machine1, machine2):
    print("\ntimeout thread started\n")
    timeout = False

    global online_sessions
    lock.acquire()
    online_sessions[session] = utils.TIMEOUT_VAL
    lock.release()

    while True:
        time.sleep(1) 

        lock.acquire()
        online_sessions[session] -= 1
        timeout_time = online_sessions[session]
        lock.release()

        timeout = True if timeout_time == 0 else False

        if timeout_time <= 0:
            print("exiting timeout thread for session ", session, "\n")
            lock.acquire()
            online_sessions[session] = 0
            lock.release()
            break # timeout
        elif timeout_time == 15:
            print("\nsending warning to session ", session, "\n")
            sv.TIMEOUT_WARNING(socket1, machine1)
            sv.TIMEOUT_WARNING(socket2, machine2)
    # end connection with other client
    if timeout:
        #remove client pair
        client_pair = [tuple_elem for tuple_elem in connected_pair 
            if tuple_elem[0] == client or tuple_elem[1] == client]
        if client_pair:
            connected_pair.remove(client_pair[0])
        #remove session
        sessionIDs.remove(session)

        sv.END_NOTIF(socket1, machine1)
        sv.END_NOTIF(socket2, machine2)

if __name__ == '__main__':
    print("server running\n")
    # create server UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # create server TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setblocking(0)

    # SOCKETS
    inputs = [udp_socket, tcp_socket]
    outputs = []
    # CONNECTION VARIABLES
    address_to_ID = {}
    clients = {}
    online_clientIDs = []
    online_client_sockets = []
    connected_pair = []
    message_queues = {}
    online_sessionIDs = []
    online_sessions = {} # timeout values for each session
    
    #user database query
    database = db.get_database()

    users = database["users"]
    item_details = users.find()

    for item in item_details:
        user = {"username": item["username"], "password": item["password"], "salt": None, "salted_password": None, "port": None, "cookie": None, "socket": None}
        clients[str(item["_id"])] = user    

    PORT = secrets.choice(PORTS) # different ports for UDP and TCP?
    # bind UDP socket 
    try:
        udp_socket.bind((INTERNAL_HOST, PORT))
    except socket.error as e:
        print(str(e))
        utils.screenClear()
        exit()
    # bind TCP socket
    try:
        tcp_socket.bind((INTERNAL_HOST, PORT))
    except socket.error as e:
        print(str(e))
        utils.screenClear()
        exit()
    # TCP server socket will listen to up to 16 connections
    tcp_socket.listen(16)
 
    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            # UDP SECTION
            if s is udp_socket: # server UDP socket
                data, addr = udp_socket.recvfrom(2048)
                data = data.decode("utf-8").split()
                print("received: ", data)

                if data[0] == "HELLO":
                    client_username = data[1]
                    # get client ID from username
                    for n in clients:
                        if clients[n]["username"] == client_username:
                            clientID = n
                    address_to_ID[addr] = clientID
                    # start auth challenge for client
                    password = clients[clientID]["password"]
                    salt = clients[clientID]["salt"] = bcrypt.gensalt()
                    clients[clientID]["salted_password"] = bcrypt.hashpw(str(password).encode(), salt)
                    sv.CHALLENGE(udp_socket, addr, clientID, salt)

                if data[0] == "RESPONSE":
                    salted_password = data[1]
                    clientID = address_to_ID[addr]
                    if clients[clientID]["salted_password"] == salted_password.encode():
                        # generate cookie to give to client
                        cookie = clients[clientID]["cookie"] = token_urlsafe(16)
                        password = clients[clientID]["password"]
                        salt = clients[clientID]["salt"]
                        sv.AUTH_SUCCESS(udp_socket, addr, clientID, cookie, password, salt, PORT, EXTERNAL_HOST)
                    else:
                        sv.AUTH_FAIL(udp_socket, addr)
            # TCP SECTION
            elif s is tcp_socket: # server TCP socket ready to accept connections
                connection, client_address = tcp_socket.accept()
                print("\nnew connection from ", client_address, "\n")
                connection.setblocking(0)
                inputs.append(connection)
                online_client_sockets.append(connection)
                message_queues[connection] = queue.Queue()
            else:
                id_encrypted_bytes = s.recv(65536) # 2^16 bytes
                if len(id_encrypted_bytes) < 24:
                    # invalid message
                    continue
                id = id_encrypted_bytes[:24].decode("utf-8")
                encrypted_bytes = id_encrypted_bytes[24:]
                machine = create_machine(clients[id]["password"], clients[id]["salt"])
                decrypted_bytes = machine.decrypt_message(encrypted_bytes)
                message = pickle.loads(decrypted_bytes)
                print("received: ", message)

                if message["message_type"] == "CONNECT":
                    if clients[id]["cookie"] == message["cookie"]:
                        connected_clientID = message["senderID"]
                        sv.CONNECTED(s, machine)
                        online_clientIDs.append(connected_clientID)
                        clients[connected_clientID]["socket"] = s
                    continue
                elif message["message_type"] == "CHAT_REQUEST":
                    # get ID from username
                    ID = utils.username_to_ID(clients, message["target_username"])
                    # check if target ID is online
                    online = ID in online_clientIDs
                    if (online):
                        # check if target is already in a chat, check if targetID is not same as senderID
                        paired = [tuple_elem for tuple_elem in connected_pair
                            if tuple_elem[0] == ID or tuple_elem[1] == ID]
                        if not paired and message["senderID"] != ID:
                            # add clients to connected pair
                            connected_pair.append(tuple((message["senderID"], ID)))
                            connection_senderID = message["senderID"]
                            connection_targetID = ID
                            # create sessionID
                            sessionID = utils.gen_sessionID(online_sessionIDs)
                            lock.acquire() 
                            online_sessions[sessionID] = utils.TIMEOUT_VAL
                            online_sessionIDs.append(sessionID)
                            lock.release()
                            # find sockets
                            socket_index = online_clientIDs.index(connection_senderID)
                            sender_socket = inputs[socket_index + 2] # +2 to account for server udp and tcp socket
                            sv.CHAT_STARTED(sender_socket, message["target_username"], sessionID, machine)

                            socket_index = online_clientIDs.index(connection_targetID)
                            target_socket = inputs[socket_index + 2]
                            target_machine = create_machine(clients[connection_targetID]["password"], clients[connection_targetID]["salt"])
                            sv.CHAT_STARTED(target_socket, message["username"], sessionID, target_machine)
                            # start timer thread
                            timer_thread = threading.Thread(target = chat_timeout, args = (sessionID, online_sessionIDs, connected_pair, connection_senderID, sender_socket, target_socket, machine, target_machine))
                            timer_thread.start()
                        else:
                            connection_senderID = message["senderID"]
                            socket_index = online_clientIDs.index(connection_senderID)
                            response_socket = inputs[socket_index + 2]
                            sv.UNREACHABLE(response_socket, message["target_username"], machine)
                    else:
                        connection_senderID = message["senderID"]
                        socket_index = online_clientIDs.index(connection_senderID)
                        response_socket = inputs[socket_index + 2]
                        sv.UNREACHABLE(response_socket, message["target_username"], machine)
                elif message["message_type"] == "END_REQUEST":
                    client_pair = [tuple_elem for tuple_elem in connected_pair 
                        if tuple_elem[0] == message["senderID"] or tuple_elem[1] == message["senderID"]]
                    if client_pair:
                        connected_pair.remove(client_pair[0])

                    connection_senderID = message["senderID"]
                    connection_targetID = utils.username_to_ID(clients, message["target_username"])
                    sessionID = message["sessionID"]
                    lock.acquire()
                    online_sessions[sessionID] = 0
                    lock.release()
                    sv.disconnect_message(connection_senderID, clients, inputs, online_clientIDs)
                    sv.disconnect_message(connection_targetID, clients, inputs, online_clientIDs)

                    online_sessionIDs.remove(sessionID)
                    print("\nsession ", sessionID, " removed\n")
                    continue
                elif message["message_type"] == "LOG_OFF":
                    senderID = message["senderID"]
                    targetID = utils.username_to_ID(clients, message["target_username"])
                    socket_index = online_clientIDs.index(senderID)
                    response_socket = inputs[socket_index + 2]
                    sv.LOG_OFF(response_socket, machine)

                    # connection teardown
                    client_pair = [tupleElem for tupleElem in connected_pair 
                        if tupleElem[0] == message["senderID"] or tupleElem[1] == message["senderID"]]
                    # if logging off from a chat session, end chat
                    if client_pair:
                        sessionID = message["sessionID"]
                        lock.acquire()
                        online_sessions[sessionID] = 0
                        lock.release()
                        connected_pair.remove(client_pair[0])

                        sv.disconnect_message(senderID, clients, inputs, online_clientIDs)
                        sv.disconnect_message(targetID, clients, inputs, online_clientIDs)

                        online_sessionIDs.remove(sessionID)
                        print("\nsession ", sessionID, " removed\n")
                    # end TCP connection
                    online_clientIDs.remove(senderID)
                    socket = clients[senderID]["socket"]
                    if socket in inputs:
                        inputs.remove(socket)
                    if socket in outputs:
                        outputs.remove(socket)
                    continue
                # message type = CHAT
                if message["message_body"]: 
                    # get ID from username
                    ID = utils.username_to_ID(clients, message["target_username"])
                    outgoing_message = utils.messageDict(
                        senderID=message["senderID"], targetID=ID, target_username=message["target_username"], sessionID=message["sessionID"], message_type="CHAT", message_body=message["message_body"]
                    )
                    message_queues[s].put(outgoing_message)
                    if s not in outputs:
                        outputs.append(s)
        for s in writable:
            try:
                next_message = message_queues[s].get_nowait()
            except queue.Empty:
                # no messages waiting 
                outputs.remove(s)
            else:
                print("session ", message["sessionID"], ": sending", next_message["message_body"], " to ", next_message["target_username"])
                senderID = next_message["senderID"]
                next_message["username"] = clients[senderID]["username"]
                client_pair = [tupleElem for tupleElem in connected_pair 
                    if tupleElem[0] == next_message["senderID"] or tupleElem[1] == next_message["senderID"]]
                
                if client_pair[0][0] == senderID:
                    target = online_clientIDs.index(client_pair[0][1])
                else:
                    target = online_clientIDs.index(client_pair[0][0])

                targetID = next_message["targetID"]
                machine = create_machine(clients[targetID]["password"], clients[targetID]["salt"])
                unencrypted_bytes = pickle.dumps(next_message)
                encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
                inputs[target + 2].send(encrypted_bytes)
                # reset timeout
                print("\nmessage sent - reset timer\n")
                lock.acquire()
                online_sessions[sessionID] = utils.TIMEOUT_VAL
                lock.release()
        for s in exceptional: # handle errors - close socket if error (not used right now)
            print("handleing error")
            inputs.remove(s)
            if s in outputs:
                outputs.remove(s)
            s.close()
