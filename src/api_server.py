import random
import string
import os
import json
import subprocess
import hashlib
import socket
import threading
import time
import marshal
from src.debug import PrintDebug, PrintError

class Cloud:
    def __init__(self, ip, port, auth, verbose) -> None:
        self.ip = ip
        self.port = port
        self.auth = auth
        self.socket = socket.socket()
        self.socket.bind((ip, port))
        self.socket.listen()
        self.verbose = verbose

    def connect(self) -> None:
        PrintDebug("SERVER IS CURRENTLY LISTENING ON: {}:{}".format(self.ip, self.port), verbose=self.verbose)
        while True:
            conn, addr = self.socket.accept()
            client_recv = conn.recv(10)
            if client_recv == b"HELLOWORLD":
                conn.send(b"Hello")
                PrintDebug("New connection from the host -> {}:{}".format(addr[0], addr[1]), verbose=self.verbose)
                threading.Thread(target=self.functions, args=(conn, addr)).start()

    def functions(self, conn, addr) -> None:
        while True:
            buffer = conn.recv(1028).decode()
            values = json.loads(buffer)
            if int(values['option']) == 1:
                info = self.auth.login(values['username'], values['password'])
                if info[0] == True:
                    user_id = json.loads(info[1])['result'][4]
                    
                    self.auth.log_data[user_id]['hwid'] = values['hwid']
                    new_info = json.dumps(self.auth.log_data,indent=4)
                    self.auth.update(new_info)
                    conn.sendall(info[1].encode('utf-8'))
                    PrintDebug("User {} logged in successfully.".format(user_id),verbose=self.verbose)
                else:
                    conn.sendall(json.dumps({"option": 1, "status": "failed", "result": "Invalid username or password"}).encode('utf-8'))
            elif int(values['option']) == 2:
                print("RUNNING CREATE_ACCOUNT")
                info = self.auth.create_account(values['username'], values['password'])
                print("CREATE_ACCOUNT RETURNED")
                print(info)
                conn.send(json.dumps(info).encode('utf-8'))
                print("SENT SUCCESS")
            elif int(values['option']) == 3:
                PrintDebug("OPTION 3", verbose=self.verbose)
                print(values['key'])
                verify = self.auth.value(values['key'])
                # PrintDebug(verify, verbose=self.verbose)
                if verify[0]:
                    conn.sendall(json.dumps({"option": 3, "status": "success", "result": "VALID KEY"}).encode('utf-8'))
                    time.sleep(2)
                    PrintDebug("User authentication success.", verbose=self.verbose)
                    # with open("bluepill.py", "r") as r:
                    #     file_b = r.read()
                    #     conn.sendall(str(int(len(file_b))).encode('utf-8') + b" " + file_b.encode('utf-8'))
                    #     PrintDebug("Sent contents to user.", verbose=self.verbose)
                elif verify[0] == False:
                    conn.sendall(json.dumps({"option": 3, "status": "failed", "result": "INVALID KEY"}).encode('utf-8'))