import random
import string
from datetime import date
import os
import json
import subprocess
import hashlib
import socket
import threading

class Authenticator:
    def __init__(self, filename) -> None:
        self.filename = filename
        self.log_data = self.open_logs(self.filename)

    def open_logs(self, file) -> json:
        if os.path.exists(file):
            try:
                with open(file, "r") as open_creds:
                    log_data = json.loads(open_creds.read())
                    return log_data
            except:
                print("You don't have enough perms to modify this file")
        else:
            if input(f"{file} Does not exist. Shall we create one for you?").lower == "yes":
                with open(file, "w") as f:
                    f.write("{}")
                with open(file, "r") as open_creds:
                    log_data = json.loads(open_creds.read())
                    return log_data
                
    def gethwid(self) -> str:
        if os.name == "nt":
            data = "reg query HKEY_USERS"
            runcmd = subprocess.Popen(data,shell=True, stdout=subprocess.PIPE)
            return runcmd.stdout.read().decode().split("\n")[4][11:40]
        return "UNKNOWN"

    def generate_key(self) -> str:
        while True:
            key = ""
            for i in range(4):
                key += ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                if i < 3:
                    key += "-"
            for value in self.log_data.values():
                if key == value["key"]:
                    continue
            break
        return key

    def hashpass(self, password) -> str:
        return hashlib.md5(password.encode('utf-8')).hexdigest()

    def login(self, username, password) -> tuple:
        for user_id, user in self.log_data.items():
            if username == user["username"] and self.hashpass(password) == user["password"]:
                data = (user["username"], user["key"], user["data"],user["hwid"], user_id)
                value = json.dumps({"option": 1, "status": "success", "result": list(data)})
                return True, value
        return False, 1

    def checkuser(self, username, password) -> bool:
        for user in self.log_data.values():
            if user["username"].lower() == username.lower():
                return False
        return True

    def verify_format(self, user) -> bool:
        ascii_value = [ord(a) for a in user]
        for num in ascii_value:
            if not num or not (32 <= num <= 126):
                return False
        return True

    def create_account(self, create_user, create_pass) -> json: 
        if len(create_user) <= 4:
            return {"option": 2, "status": "failed", "result": "Please enter a username above 4 characters"}
        elif len(create_pass) <= 4:
             return {"option": 2, "status": "failed", "result": "Please enter a password above 4 characters"}
        elif not self.verify_format(create_user):
            return {"option": 2, "status": "failed", "result": "Invalid format. Please use normal characters."}
        elif len(create_user) >= 26:
            return {"option": 2, "status": "failed", "result": "Username cannot be longer than 26 characters"}
        if self.checkuser(create_user, create_pass):
            new_data = {
            "username": create_user,
            "password": hashlib.md5(create_pass.encode('utf-8')).hexdigest(),
            "key": self.generate_key(),
            "data": date.today().strftime("%d/%m/%Y"),
            "hwid": self.gethwid()
            }
            self.log_data[len(self.log_data)] = new_data
            json_data = json.dumps(self.log_data,indent=4)
            if self.update(json_data):
                return {"option": 2, "status": "success", "result": "Account created"}
        else:   
            return {"option": 2, "status": "failed", "result": "Username has been taken"}

    def update(self, data) -> bool:
        try:
            with open(self.filename, "w") as creds:
                creds.write(data)
                return True
        except:
            return False

    def value(self, key) -> tuple:
        with open(self.filename, "r") as open_creds:
            log_data = json.loads(open_creds.read())
        for user_id, value in log_data.items():
            if key != value["key"]:
                continue
            return True, user_id
        return False, "FATAL"

class Cloud:
    def __init__(self, ip, port, auth) -> None:
        self.ip = ip
        self.port = port
        self.auth = auth
        self.socket = socket.socket()
        self.socket.bind((ip, port))
        self.socket.listen()
        self.connect()
    
    def connect(self) -> None:
        print("SERVER IS CURRENTLY LISTENING ON: {}:{}".format(self.ip, self.port))
        while True:
            conn, addr = self.socket.accept()
            client_recv = conn.recv(10)
            if client_recv == b"HELLOWORLD":
                conn.send(b"Hello")
                print("New connection from the host -> {}:{}".format(addr[0], addr[1]))
                threading.Thread(target=self.functions, args=(conn, addr)).start()

    def functions(self, conn, addr) -> None:
        while True:
            try:
                buffer = conn.recv(1028).decode()
                values = json.loads(buffer)
                if int(values['option']) == 1:
                    info = self.auth.login(values['username'], values['password'])
                    if info[0] == True:
                        user_id = json.loads(info[1])['result'][4]
                        print(user_id)
                        self.auth.log_data[user_id]['hwid'] = values['hwid']
                        new_info = json.dumps(self.auth.log_data,indent=4)
                        self.auth.update(new_info)
                        conn.sendall(info[1].encode('utf-8'))
                    else:
                        conn.sendall(json.dumps({"option": 1, "status": "failed", "result": "Invalid username or password"}).encode('utf-8'))
                elif int(values['option']) == 2:
                    info = self.auth.create_account(values['username'], values['password']) 
                    conn.send(json.dumps(info).encode('utf-8'))
                elif int(values['option']) == 3:
                    verify = self.auth.value(values['key'])
                    print(verify)
                    if verify[0]:
                        conn.sendall(json.dumps({"option": 3, "status": "success", "result": "VALID KEY"}).encode('utf-8'))
                    elif verify[0] == False:
                        conn.sendall(json.dumps({"option": 3, "status": "failed", "result": "INVALID KEY"}).encode('utf-8'))
            except Exception as e:
                break
server = Cloud("localhost", 1234, Authenticator("logs.json"))
server.connect()