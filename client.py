import bcrypt, pickle, queue, socket, select, secrets
from secrets import token_urlsafe

from aes import create_machine
import server_functions as sv
import db
import utils

# CONNECTION INFORMATION
HOST = 'localhost' # should replace with system IP on GCP later ?
PORTS = [6265] # have multiple ports available ?

if __name__ == '__main__':
    print("server running")
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
    message_queues = {}
    connected_pair = []
    
    query_result = db.user_query()
    for doc in query_result:
        user_dict = doc.to_dict()
        user = {"username": user_dict["username"], "password": user_dict["password"], "salt": None, "salted_password": None, "port": None, "cookie": None, "socket": None} 
        clients[doc.id] = user

    PORT = secrets.choice(PORTS) # different ports for UDP and TCP?
    # bind UDP socket 
    try:
        udp_socket.bind(('localhost', PORT))
    except socket.error as e:
        print(str(e))
        utils.screenClear()
        exit()
    # bind TCP socket
    try:
        tcp_socket.bind(('localhost', PORT))
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
                    clientID = data[1]
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
                        sv.AUTH_SUCCESS(udp_socket, addr, cookie, password, salt, PORT, HOST)
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
                if len(id_encrypted_bytes) < 20:
                    # invalid message
                    continue
                id = id_encrypted_bytes[:20].decode("utf-8")
                encrypted_bytes = id_encrypted_bytes[20:]
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
                    # check if target ID is online
                    online = message["targetID"] in online_clientIDs
                    if (online):
                        # check if target is already in a chat - TODO check if targetID is not same as senderID, TODO check if already paired with targetID
                        paired = [tuple_elem for tuple_elem in connected_pair
                            if tuple_elem[0] == message["targetID"] or tuple_elem[1] == message["targetID"]]
                        if not paired:
                            # add clients to connected pair
                            connected_pair.append(tuple((message["senderID"], message["targetID"])))
                            connection_senderID = message["senderID"]
                            connection_targetID = message["targetID"]
                            # find sockets
                            socket_index = online_clientIDs.index(connection_senderID)
                            response_socket = inputs[socket_index + 2] # +2 to account for server udp and tcp socket
                            sv.CHAT_STARTED(response_socket, connection_targetID, machine)

                            socket_index = online_clientIDs.index(connection_targetID)
                            response_socket = inputs[socket_index + 2]
                            recv_machine = create_machine(clients[connection_targetID]["password"], clients[connection_targetID]["salt"])
                            sv.CHAT_STARTED(response_socket, connection_senderID, recv_machine)
                        else:
                            connection_senderID = message["senderID"]
                            connection_targetID = message["targetID"]
                            socket_index = online_clientIDs.index(connection_senderID)
                            response_socket = inputs[socket_index + 2]
                            sv.UNREACHABLE(response_socket, connection_targetID, machine)
                    else:
                        connection_senderID = message["senderID"]
                        connection_targetID = message["targetID"]
                        socket_index = online_clientIDs.index(connection_senderID)
                        response_socket = inputs[socket_index + 2]
                        sv.UNREACHABLE(response_socket, connection_targetID, machine)
                
                if message["message_body"]: 
                    outgoing_message = utils.messageDict(senderID = message["senderID"], targetID = message["targetID"], message_type = "CHAT", message_body = message["message_body"], port = PORT)
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
                print ("sending", next_message["message_body"], " to ", next_message["targetID"])
                senderID = next_message["senderID"]
                next_message["username"] = clients[senderID]["username"]
                clientID = [tupleElem for tupleElem in connected_pair 
                    if tupleElem[0]== next_message['senderID'] or tupleElem[1] == next_message['senderID']]
                
                if clientID[0][0] == senderID:
                    target = online_clientIDs.index(clientID[0][1])
                else:
                    target = online_clientIDs.index(clientID[0][0])

                targetID = next_message["targetID"]
                machine = create_machine(clients[targetID]["password"], clients[targetID]["salt"])
                unencrypted_bytes = pickle.dumps(next_message)
                encrypted_bytes = machine.encrypt_message(unencrypted_bytes)
                inputs[target + 2].send(encrypted_bytes)
        for s in exceptional: # handle errors - close socket if error (not used right now)
            print("handleing error")
            inputs.remove(s)
            if s in outputs:
                outputs.remove(s)
            s.close()
