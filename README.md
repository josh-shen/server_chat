# Server based chat
A simple chat server implemented using Python and socket programming. Basic encryption methods are used to protect chat messages. MongoDB used for storing client credentials and chat history between two clients. 

## Features
- Chat: clients chat with a target client by sending messages to the server, and the server forwards the message to the target client
- Encryption: messages between client and server are encrypted with PBKDF2, and messages between clients are end-to-end encrypted
- Client profiles: client username and password are stored in MongoDB database with password hashing
- Chat history: encrypted chat history between two clients are saved in MongoDB database

## Requirements
All required modules are listed in the requirements.txt file. All modules can be installed using the command  
  
`$ pip install -r requirements.txt`  
or     
`$ pip3 install -r requirements.txt`  

## Usage

### Server
To run the server code, run `python server.py` or `python3 server.py`  
  
Server code can be hosted on cloud services such as GCP Compute Engine, or on your local machine. Change the internal and external IP addresses in utils.py accordingly 

### Client

To run the client code, run `python client.py` or `python3 client.py`  
  
#### Client commands:
- `logon` connects to server and goes through authentication
- `chat [client ID]` initiate chat with a target client with specified ID
- `end chat` ends current chat session
- `logoff` disconnects from server, if currently chatting, also exits from chat session

### Disclaimer
This project is only a *very* simple implementation of a chat server and encryption methods. This project contains security flaws and is not meant for production use. 