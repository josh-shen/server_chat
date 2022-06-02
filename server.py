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
        user = {"password": user_dict["password"], "salt": None, "salted_password": None, "port": None, "cookie": None, "socket": None} # add username later
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
                        message = utils.messageDict(senderID = "SERVER", message_type = "CONNECTED", message_body = "connected to server")
                        sv.CONNECTED(s, message, machine)
                        online_clientIDs.append(connected_clientID)
                        clients[connected_clientID]["socket"] = s
