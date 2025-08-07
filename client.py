import pickle, socket, sys, time, threading

from aes import aes_cipher, create_machine
import utils
import client_functions as cl

# message receive thread (from either server or another client)
def msg_recv(machine: aes_cipher):
    while True:
        encrypted_bytes = client_socket.tcp_client.recv(65536)

        if len(encrypted_bytes) == 0:
            break
        
        # decrypt received message
        decrypted_bytes = machine.decrypt_message(encrypted_bytes)
        message = pickle.loads(decrypted_bytes)

        if message["message_type"] == "CHAT_STARTED":
            global target_username
            target_username = message["target_username"]
            
            global sessionID 
            sessionID = message["sessionID"] 
        elif message["message_type"] == "UNREACHABLE":
            target_username = None
        elif message["message_type"] == "END_NOTIF":
            target_username = None
            sessionID = None
        elif message["message_type"] == "LOG_OFF":
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
        recv_message = f"> {identifier}: {message['message_body'] if message['message_body'] is not None else 'None'}"
        
        if (message_type == "SERVER_ERROR"):
            utils.terminal_print(recv_message, "error")
        elif (message_type == "SERVER_WARNING"):
            utils.terminal_print(recv_message, "warning")
        elif (message_type == "SERVER"):
            utils.terminal_print(recv_message, "info")
        else:
            utils.terminal_print(recv_message, "client")

        sys.stdout.flush()

if __name__ == "__main__":
    # connection variables
    connect_type = 0
    reply = None
    target_username = None
    sessionID = None

    # client credentials
    USERNAME = ""
    PASSWORD = ""

    client_socket = cl.client_API(USERNAME, PASSWORD)

    while True:
        # connect type 0 - not connected to server
        if connect_type == 0: 
            utils.terminal_print("type 'logon' to start connection  or 'exit' to shut the app")

            ins = input()
            utils.clear_line()

            if ins == "logon":
                connect_type = 1
            elif ins == "exit":
                utils.clear_screen()
                exit()
            else:
                utils.terminal_print("invalid input", "error")
        # connect type 1 - authenticating with server
        elif connect_type == 1: 
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
                    connect_type = 2

                    # set ID received from the server
                    client_socket.clientID = ID

                    # begin TCP connection, and start message receive thread
                    client_socket.tcp_client.connect((HOST, int(PORT)))
                    client_socket.CONNECT(machine)

                    utils.terminal_print("Authentication successful. Sending TCP connect message", "success")
                    
                    recv_thread = threading.Thread(target = msg_recv, args = (machine,))
                    recv_thread.start()
                elif reply != [] and reply[0] == "AUTH_FAIL":
                    reply = None
                    client_socket.udp_client.close()

                    utils.terminal_print("Authentication failed", "error")
                    break
                
                # response from server
                if connect_type == 1:
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

                    #utils.terminal_print(reply, "info")
            except socket.timeout:
                reply = None

                utils.terminal_print("time out", "error")
                break
        # connect type 2 - connected to server
        elif connect_type == 2:
            message_input = input("")
            utils.clear_line()

            utils.terminal_print(f"> {message_input}")

            if message_input.split()[0] == "chat":
                target_username = message_input.split()[1]
                client_socket.CHAT_REQUEST(target_username, machine)
            elif target_username != None and sessionID != None and message_input == "end chat":
                client_socket.END_REQUEST(target_username, sessionID, machine)
            elif message_input == "logoff":
                client_socket.LOG_OFF(target_username, sessionID, machine)
                connect_type = 0
            elif target_username != None and sessionID != None and message_input != "end client":
                client_socket.CHAT(message_input, target_username, sessionID, machine)
            else:
                utils.terminal_print("Invalid input. If you are trying to send a message, you are not currently connected to a chat session.", "error")
        # connect type not 0, 1, or 2 (this should never happen)
        else:
            break

    client_socket.tcp_client.close()
