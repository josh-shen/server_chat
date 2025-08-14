import pickle, socket, sys, time, threading, os
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import TupleHash128

from aes import aes_cipher, create_machine
from utils import terminal_print, clear_line, clear_screen
import client_functions as cl

# message receive thread (from either server or another client)
def msg_recv(machine: aes_cipher):
    global target_username
    global targetID
    global sessionID
    global shared_key
    global message_machine

    while True:
        encrypted_bytes = client_socket.tcp_client.recv(65536)

        if len(encrypted_bytes) == 0:
            break
        
        # decrypt received message
        decrypted_bytes = machine.decrypt_message(encrypted_bytes)
        message = pickle.loads(decrypted_bytes)

        if message["message_type"] == "CHAT_INIT":
            session_salt = message["message_body"]
            targetID = message["targetID"]
            target_username = message["target_username"]
            sessionID = message["sessionID"] 

            # send back public key to server
            public_key = my_key.public_key()
            public_pem = public_key.export_key(format='PEM')
            client_socket.CHAT_RESPONSE(targetID, target_username, sessionID, machine, public_pem)
            continue 
        elif message["message_type"] == "CHAT_STARTED":
            
            def kdf(x):
                h = TupleHash128.new(digest_bytes=32)
                h.update(
                        x,
                        session_salt,
                        b'Email encryption',
                        b'TupleHash128',
                        b'AES256')
                return h.digest()
            
            target_username = message["target_username"]

            # create shared key with target's public key
            their_key = message["message_body"]["key"]
            their_key = ECC.import_key(their_key)
            #global shared_key
            shared_key = key_agreement(static_priv=my_key, static_pub=their_key, kdf=kdf)
            #global message_machine
            message_machine = create_machine(shared_key, session_salt)

            # display chat history
            history = message["message_body"]["body"]
            for n in history:
                client, encrypted_bytes = n.popitem()
                decrypted_message = message_machine.decrypt_message(encrypted_bytes).decode("utf-8")
                terminal_print(f"> {client}: {decrypted_message}", "info")          
            
            message["message_body"] = message["message_body"]["server_message"]
        elif message["message_type"] == "UNREACHABLE":
            target_username = None
        elif message["message_type"] == "END_NOTIF":
            target_username = None
            sessionID = None
        elif message["message_type"] == "LOG_OFF_NOTIF":
            # clear target username and session ID if still in a chat session
            target_username = None
            sessionID = None

            # close sockets and exit thread
            client_socket.tcp_client.close()
            client_socket.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            time.sleep(1)
            sys.exit()
            break
        
        # display received message
        message_type = message["senderID"]
        identifier = message["username"] if "SERVER" not in message["senderID"] else "SERVER"
        # decrypt message body from client with shared key
        if identifier != "SERVER":
            decrypted_bytes = message_machine.decrypt_message(message["message_body"])
            message['message_body'] = decrypted_bytes.decode("utf-8")

        recv_message = f"> {identifier}: {message['message_body'] if message['message_body'] is not None else 'None'}"
        
        if (message_type == "SERVER_ERROR"):
            terminal_print(recv_message, "error")
        elif (message_type == "SERVER"):
            terminal_print(recv_message, "info")
        else:
            terminal_print(recv_message, "client")

        sys.stdout.flush()

if __name__ == "__main__":
    # connection variables
    connect_type = 0
    reply = None
    targetID = None
    target_username = None
    sessionID = None

    # client credentials
    USERNAME = ""
    PASSWORD = ""

    shared_key = None
    message_machine = None

    while True:
        # connect type 0 - not connected to server
        if connect_type == 0: 
            terminal_print("type 'logon' to start connection  or 'exit' to shut the app")

            ins = input("")
            clear_line()

            if ins == "logon":
                connect_type = 1
            elif ins == "exit":
                clear_screen()
                exit()
            else:
                terminal_print("invalid input", "error")
        # connect type 1 - inputting credentials
        elif connect_type == 1:
            USERNAME = input("")
            PASSWORD = input("")
            client_socket = cl.client_API(USERNAME, PASSWORD)

            connect_type = 2
        # connect type 2 - authenticating with server
        elif connect_type == 2: 
            try:
                if reply == None:
                    # start authentication process with server
                    client_socket.HELLO() 
                elif reply != [] and reply[0] == "CHALLENGE":
                    # challenge received from server, send response
                    salt = reply[1]
                    client_socket.RESPONSE(PASSWORD, salt.encode())
                elif reply != [] and reply[0] == "AUTH_SUCCESS":
                    # authentication successful, start TCP connection with server
                    connect_type = 3

                    # set ID received from the server
                    client_socket.clientID = ID

                    # begin TCP connection, and start message receive thread
                    client_socket.tcp_client.connect((HOST, int(PORT)))
                    client_socket.CONNECT(machine)

                    terminal_print("Authentication successful. Sending TCP connect message", "success")
                    
                    recv_thread = threading.Thread(target = msg_recv, args = (machine,))
                    recv_thread.start()

                    if os.path.exists(f"{USERNAME}.pem"):
                        # load key from file
                        my_key = ECC.import_key(open(f"{USERNAME}.pem", "rb").read())
                    else:
                        with open(f"{USERNAME}.pem", "wt") as f:
                            my_key = ECC.generate(curve='p256')
                            data = my_key.export_key(format='PEM')
                            f.write(data)
                elif reply != [] and reply[0] == "AUTH_FAIL":
                    reply = None
                    client_socket.udp_client.close()

                    terminal_print("Authentication failed", "error")
                    
                    connect_type = 1
                
                # response from server
                if connect_type == 2:
                    client_socket.udp_client.settimeout(5)
                    reply = client_socket.udp_client.recv(1024)
                    bytes_check = reply[:2]

                    if bytes_check == b"as":
                        machine = create_machine(PASSWORD, client_socket.salt)
                        reply = machine.decrypt_message(reply[2:])
                        reply = reply.decode("utf-8").split()
                        ID = reply[1]
                        PORT = reply[2]
                        HOST = reply[3]
                        client_socket.cookie = reply[4]
                    else:
                        reply = reply.decode("utf-8").split()
            except socket.timeout:
                reply = None

                terminal_print("Timed out", "error")
                break
        # connect type 3 - connected to server
        elif connect_type == 3:
            message_input = input("")
            clear_line()

            terminal_print(f"> {message_input}")

            if message_input.split()[0] == "chat":
                target_username = message_input.split()[1]
                client_socket.CHAT_REQUEST(target_username, machine)
            elif targetID != None and sessionID != None and message_input == "end chat":
                client_socket.END_REQUEST(targetID, target_username, sessionID, machine)
            elif message_input == "logoff":
                client_socket.LOG_OFF_REQUEST(targetID, target_username, sessionID, machine)

                # reset connection variables
                reply = None
                connect_type = 0
            elif targetID != None and sessionID != None:
                client_socket.CHAT(message_input, targetID, target_username, sessionID, machine, message_machine)
            else:
                terminal_print("Invalid input. If you are trying to send a message, you are not currently connected to a chat session.", "error")
        else:
            break

    client_socket.tcp_client.close()
