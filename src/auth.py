import json
import subprocess
import os
import random
import string
import hashlib
from datetime import date
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