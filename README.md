# Server based chat
Server side code is hosted on Google Cloud Platform's Compute Engine and data for user authentication is stored on Firestore. Clients connect to server through UDP protocol. Clients use TCP protocols to chat through the server. AES encryption is used for messages sent between clients. 

## Requirements
All required modules are listed in the requirements.txt file. All modules can be installed using the command  
  
`$ pip install -r requirements.txt`  
or     
`$ pip3 install -r requirements.txt`  

## Usage

### Server
To run the server code, run `python server.py` or `python3 server.py`  
  
> Server code can be hosted on cloud service such as GCP Compute Engine, or on local machine. Change the internal and external IP addresses in utils.py accordingly 
### Client

To run the client code, run `python client.py` or `python3 client.py`  
  
#### Client commands:
- `logon` connects to server and goes through authentication
- `chat [client ID]` initiate chat with a target client with specified ID
- `end chat` ends current chat session
- `logoff` disconnects from server, if currently chatting, also exits from chat session
