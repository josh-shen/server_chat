import bcrypt, hashlib, pickle, socket, sys, time, threading

from aes import aes_cipher, create_machine
import utils
import client_functions as cl

# CONNECTION VARIABLES
connect_type = 0
reply = None
target_username = None
sessionID = None

# client credentials
USERNAME = ""
PASSWORD = ""

# message receive thread
def msg_recv(machine: aes_cipher):
    while True:
        encrypted_bytes = client_socket.tcp_client.recv(65536)

        if len(encrypted_bytes) == 0:
            break

        decrypted_bytes = machine.decrypt_message(encrypted_bytes)
        message = pickle.loads(decrypted_bytes)
        if message["message_type"] == "CHAT_STARTED":
            global target_username
            if target_username == None:
                target_username = message["target_username"]
            
            global sessionID 
            sessionID = message["sessionID"] 
        elif message["message_type"] == "UNREACHABLE":
            target_username = None
        elif message["message_type"] == "END_NOTIF":
            target_username = None
            sessionID = None
        elif message["message_type"] == "LOG_OFF":
            client_socket.tcp_client.close()
            client_socket.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            time.sleep(1)
            sys.exit()
            break
        
        identifier = message["username"] if message["senderID"] != "SERVER" else message["senderID"]
        recv_message = "> " + identifier + ": " + (message["message_body"] if message["message_body"] is not None else "None")
        print(recv_message)
        sys.stdout.flush()

client_socket = cl.client_API(USERNAME, PASSWORD)

while True:
    if connect_type == 0:
        print("type 'logon' to start connection  or 'exit' to shut the app")
        ins = input()

        print ("\033[A                             \033[A") #clear input line

        if ins == "logon":
            connect_type = 1
        elif ins == "exit":
            utils.screenClear()
            exit()
        else:
            print("invalid input")
    elif connect_type == 1:
        try:
            if reply == None:
                client_socket.HELLO() 
            elif reply != [] and reply[0] == "CHALLENGE":
                salt = reply[1]
                client_socket.RESPONSE(PASSWORD, salt.encode())
            elif reply != [] and reply[0] == "AUTH_SUCCESS":
                connect_type = 2
                # set ID received from the server
                client_socket.clientID = ID
                # begin TCP connection
                client_socket.tcp_client.connect((HOST, int(PORT)))
                client_socket.CONNECT(cookie, machine)
                print("sent tcp connect message")
                recv_thread = threading.Thread(target = msg_recv, args = (machine,))
                recv_thread.start()
            elif reply != [] and reply[0] == "AUTH_FAIL":
                reply = None
                client_socket.udp_client.close()
                print("authentication failed")
                break

            if connect_type == 1:
                client_socket.udp_client.settimeout(5)
                reply = client_socket.udp_client.recv(1024)
                # authentication
                bytes_check = reply[:2]
                if bytes_check == b'as':
                    machine = create_machine(PASSWORD, client_socket.salt)
                    reply = machine.decrypt_message(reply[2:])
                    reply = reply.decode('utf-8').split()
                    ID = reply[1]
                    PORT = reply[2]
                    HOST = reply[3]
                    cookie = reply[4]
                else:
                    reply = reply.decode('utf-8').split() 

                print("received from server: ", reply)
        except socket.timeout:
            reply = None
            print("time out")
            break
    else:
        message_input = input("")
        print ("\033[A                             \033[A") #clear input line
        print(">", message_input)

        if message_input.split()[0] == "chat":
            target_username = message_input.split()[1]
            client_socket.CHAT_REQUEST(target_username, machine)
        elif message_input == "end chat":
            client_socket.END_REQUEST(target_username, sessionID, machine)
        elif message_input == "logoff":
            client_socket.LOG_OFF(target_username, sessionID, machine)
            connect_type = 0
        elif target_username != None and sessionID != None and message_input != "end client":
            client_socket.CHAT(message_input, target_username, sessionID, machine)
        else:
            print("Invalid input. If you are trying to send a message, you are not currently connected to a chat session.")

client_socket.tcp_client.close()
