# Server based chat
Server side code is hosted on Google Cloud Platform's Compute Engine and data for user authentication is stored on Firestore. Clients connect to server through UDP protocol. Clients use TCP protocols to chat through the server. AES encryption is used for messages sent between clients. 

## Requirements
#### Python modules
All required modules are listed in the requirements.txt file. All modules can be installed using the command  
`$ pip install -r requirements.txt`  
or     
`$ pip3 install -r requirements.txt`  
  
#### Firestore
Use the following [guide](https://cloud.google.com/firestore/docs/create-database-server-client-library) to set up Firestore. Firestore is used to store user usernames, keys, and IDs.

## Usage
### Run commands
#### Server
To run the server code, type `python server.py` or `python3 server.py`  
  
> Server code can be hosted on Compute Engine, or on local machine. Change the internal and external IP addresses in server.py accordingly 
#### Client
To run the client code, type `python client.py` or `python3 client.py`  
  
> Change external IP address in client_fuctions.py accordingly
  
### Client commands:
- `logon`: connects to server and goes through authentication
- `chat [client ID]`: type chat followed by ID of client to start chat with
- `end chat`: ends current chat session
- `logoff`: disconnects from server, if currently chatting, exits from chat session

