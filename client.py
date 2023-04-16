import socket
import json
import os
import subprocess
HOST = "127.0.0.1"
PORT = 1234
class serverAuth:
    def __init__(self, ip, port) -> None:
        self.ip = ip
        self.port = port
        self.socket = socket.socket()
        self.socket.connect((self.ip, self.port))

    def gethwid(self) -> str:
        if os.name == "nt":
            command = "reg query HKEY_USERS"
            runcmd = subprocess.Popen(command,shell=True, stdout=subprocess.PIPE)
            return runcmd.stdout.read().decode().split("\n")[4][11:40]
        return "UNKNOWN"
        
    def login(self) -> str:
        print("LOGIN")
        username = input("Please enter your username: ")
        password = input("Please enter your password: ")
        value = {"option":1, "username": username, "password": password, "hwid": self.gethwid()}
        json_data = json.dumps(value).encode('utf-8')
        self.socket.sendall(json_data)
        return self.socket.recv(2048).decode()

    def signup(self) -> str:
        print("CREATE YOUR ACCOUNT")
        username = input("Please enter your username: ")
        password = input("Please enter your password: ")
        value = {"option":2, "username": username,"password": password}
        json_data = json.dumps(value).encode('utf-8')
        self.socket.sendall(json_data)
        return self.socket.recv(2048).decode()

    def authenticate(self) -> str:
        key = input("Please enter your product key: ")
        value = {"option":3, "key": key}
        json_data = json.dumps(value).encode('utf-8')
        self.socket.send(json_data)
        return self.socket.recv(2048).decode()

    def selecter(self, option) -> str:
        if option == "1": return self.login()
        elif option == "2": return self.signup()
        elif option == "3": return self.authenticate()

    def process_data(self, info) -> None:
        os.system("cls" if os.name == "nt" else "clear")
        if info['option'] == 1 and info['status'] == "success":
            creds = info['result']
            print("You have logged in\n" + "="*36)
            print("{:<15}  {:<30}".format("User_ID", creds[4]))
            print("{:<15}  {:<30}".format("Username", creds[0]))
            print("{:<15}  {:<30}".format("Key", creds[1]))
            print("{:<15}  {:<30}".format("Expiration_date", creds[2]))
            print("{:<15}  {:<30}".format("Hardware_ID", creds[3]))
            print("="*(36))
        elif info['option'] == 1 and info['status'] == "failed":
            print(info['result'])
        elif info['option'] in (2,3) and info['status'] == "success":
            print(info['result'])
        else:
            print(info['result'])

    def menu(self):
        self.socket.sendall(b"HELLOWORLD")
        data = self.socket.recv(10)
        while True:
            option = input("Please enter an option\n1: Login\n2: Create account\n3: Authentication")
            if option in ['1','2','3']:
                info = self.selecter(option)
                self.process_data(json.loads(info))
serverAuth(HOST, PORT).menu()