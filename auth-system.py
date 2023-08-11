from src import api_server
from src import auth
import sys
user = list(sys.argv[1:])
if len(sys.argv) == 2:
    if sys.argv[1] == "-help":
        print("-ip: default localhost\n-port: Default 1234\n-logs: Log file. Default is logs.json")
        sys.exit()

# Get the args of the user
ip = next((user[i+1] for i, data in enumerate(user) if data == "-ip"), "localhost")
port = next((user[i+1] for i, data in enumerate(user) if data == "-port"), 1234)
logs = next((user[i+1] for i, data in enumerate(user) if data == "-logs"), "logs.json")
verbose = next((user[i] for i, data in enumerate(user) if data == "-v"), True)

if verbose:
    verbose = True
api_server.Cloud(ip, port, auth.Authenticator(logs), verbose).connect()