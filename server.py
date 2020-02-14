from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor, ssl
# from Crypto.Cipher import AES
from sqlite3 import connect
from requests import post
from os import environ
# from hashlib import md5
# from random import randint
from pymysql import connect as pymysql_connect


class Server(Protocol):
    def __init__(self):
        # self.clients_db = connect("clients.db")
        # self.clients_db_cursor = self.clients_db.cursor()
        self.videocreator_db = pymysql_connect(host=environ["video_creator_db_host"],
                                               user=environ["video_creator_db_user"],
                                               password=environ["video_creator_db_pass"],
                                               db="videocreator",
                                               charset='utf8mb4')
        self.videocreator_db_cursor = self.videocreator_db.cursor()

    def connectionMade(self):
        print(self.transport.getPeer())
        print("new connection")

    def dataReceived(self, data):
        request = self.parse_request(data.decode())
        if self.validate_request(request):
            response_dict = self.process_request(request)
        else:
            response_dict = {"status": "bad_request"}
        response = self.make_response(response_dict)
        self.transport.write(response.encode("utf-8"))

    def make_response(self, reposnse_dict: dict) -> str:
        str_response = ""
        for response_field_key in reposnse_dict:
            str_response += response_field_key+"="
            if response_field_key == "params":
                str_response += "["
                for param in reposnse_dict[response_field_key]:
                    str_response += param+";"
                str_response += "]"
            else:
                str_response += reposnse_dict[response_field_key]+" "
        return str_response[:-1]

    def parse_request(self, data: str) -> dict:
        try:
            request_method, request_params = data.rstrip().split(" ")
            request_params = request_params.replace("(", "").replace(")", "").split(";")
            return {"request_method": request_method, "request_params": request_params}
        except Exception:
            return {"request_method": "", "request_params": ()}

    def validate_request(self, request: dict) -> bool:
        request_method = request["request_method"]
        request_params = request["request_params"]
        # if request_method == "identification":
        #     if len(request_params) == 1:
        #         if len(request_params[0]) == 8:
        #             return True
        # if request_method == "keygen":
        #     if len(request_params) == 3:
        #         for param in request_params:# if all parameters are digits
        #             if param.isdigit():
        #                 continue
        #             return False
        #         return True
        # if self.check_client(sender_ip):
        if request_method == "login":
            print(request_params)
            if len(request_params) == 2:
                if request_params[0] != "" and request["request_params"][1] != "":
                    return True
        if request_method == "check_subscription":
            print(request_params)
            if len(request_params) == 1:
                if request_params[0] != "":
                    return True
        # if request_method == "exchange_authorization_code":
        #     if len(request_params) == 1:
        #         if request_params[0] != "":
        #             return True
        # elif request_method == "refresh_token":
        #     if len(request_params) == 1:
        #         if request_params[0] != "":
        #             return True
        return False

    def process_request(self, request: dict) -> dict:
        # if request["request_method"] == "identification":
        #     self.add_client(sender_ip, request["request_params"][0])
        # elif request["request_method"] == "keygen":
        #     key = self.generate_key(request["request_params"])
        #     self.add_client(sender_ip, key)
        #     return {"method": "keygen", "status": "successful"}
        if request["request_method"] == "login":
            response = self.login(request["request_params"][0], request["request_params"][1])
            return response
        if request["request_method"] == "check_subscription":
            response = self.check_subscription(request["request_params"][0])
            return response
        # if request["request_method"] == "exchange_authorization_code":
        #     response = self.exchange_authorization_code(request["request_params"][0])
        #     return response
        # elif request["request_method"] == "refresh_token":
        #     response = self.refresh_token(request["request_params"][0])
        #     return response

    # def generate_key(self, request_params: list) -> bytes:
    #     # To understand how it works, read https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange
    #     b = randint(10000, 10000000)
    #     g, p, A = request_params
    #     B = int(g) ** b % int(p)
    #     self.transport.write(str(B).encode("utf-8"))
    #     key = int(A) ** b % int(p)
    #     return md5(str(key).encode("utf-8")).hexdigest()

    # def login(self, login: str, password: str) -> dict:
    #     print(login, password)
    #     self.videocreator_db_cursor.execute("SELECT * FROM registr WHERE login=%s", (login))
    #     user = self.videocreator_db_cursor.fetchone()
    #     if user:
    #         if password == user[2]:
    #             return {"method": "login", "status": "successful"}
    #         else:
    #             return {"method": "login", "status": "failed", "details": "invalid_password"}
    #     else:
    #         return {"method": "login", "status": "failed", "details": "invalid_login"}

    def exchange_authorization_code(self, authorization_code: str) -> dict:
        response = post("https://www.googleapis.com/oauth2/v4/token", data={"code": authorization_code,
                                                                            "client_id": "491387305895-m2mbk74s9cssruqit5eptrl4vdegcb7e.apps.googleusercontent.com",
                                                                            "client_secret": "xR0edgycnXOKjzIZoawqweSa",
                                                                            "redirect_uri": "http://127.0.0.1:5000",
                                                                            "grant_type": "authorization_code"})
        print(response.json())
        try:
            response.json()["access_token"]
            response.json()["refresh_token"]
        except:
            return {"method": "exchange_authorization_code", "status": "failed", "details": "invalid_authorization_code"}
        else:
            return {"method": "exchange_authorization_code", "status": "successful",
                    "params": (response.json()["access_token"], response.json()["refresh_token"])}

    def refresh_token(self, refresh_token: str) -> dict:
        response = post("https://www.googleapis.com/oauth2/v4/token",
                        data={"client_id": "491387305895-m2mbk74s9cssruqit5eptrl4vdegcb7e.apps.googleusercontent.com",
                              "client_secret": "xR0edgycnXOKjzIZoawqweSa",#TODO AAAAAAAAAAAAA
                              "refresh_token": refresh_token,
                              "grant_type": "refresh_token"})
        try:
            response.json()["access_token"]
        except:
            return {"method": "refresh_token", "status": "failed", "details": "invalid_refresh_token"}
        else:
            return {"method": "refresh_token", "status": "successful", "params": [response.json()["access_token"]]}

    def login(self, login, password):
        print(login, password)
        self.videocreator_db_cursor.execute("SELECT * FROM registr WHERE login=%s", (login))
        user = self.videocreator_db_cursor.fetchone()
        if user:
            if password == user[2]:
                return {"method": "login", "status": "successful"}
            else:
                return {"method": "login", "status": "failed", "details": "invalid_password"}
        else:
            return {"method": "login", "status": "failed", "details": "invalid_login"}

    def check_subscription(self, login):
        subscription_status = self.videocreator_db_cursor.execute("SELECT subscription FROM registr WHERE login=%s",
                                                                  (login))
        if subscription_status:
            return {"method": "check_subscription", "status": "successful"}
        else:
            return {"method": "check_subscription", "status": "failed"}



    # def encrypt(self, string: str, key: str) -> str:
    #     encr_key = key.encode()
    #     nonce = encr_key[:16]
    #     cipher = AES.new(encr_key, AES.MODE_EAX, nonce=nonce)
    #     encrypted_string = cipher.encrypt_and_digest(string.encode("utf-8"))[0]
    #     return encrypted_string.decode()
    #
    # def decrypt(self, string: str, key: str) -> str:
    #     encr_key = key.encode()
    #     nonce = encr_key[:16]
    #     cipher = AES.new(encr_key, AES.MODE_EAX, nonce=nonce)
    #     return cipher.decrypt(bytes(string)).decode()
    #
    # def check_client(self, ip: int) -> bool:
    #     self.clients_db_cursor.execute("""SELECT * FROM clients""")
    #     clients = self.clients_db_cursor.fetchall()
    #     for client in clients:
    #         if client[0] == ip:
    #             return True
    #     return False
    #
    # def add_client(self, ip: str, id: str) -> bool:
    #     self.clients_db_cursor.execute("""INSERT INTO clients VALUES(?, ?)""", (ip, id))
    #     self.clients_db.commit()
    #     return True
    #
    # def add_key(self, ip, key):
    #     self.clients_db_cursor.execute("""UPDATE clients SET key=? WHERE ip=?""", (key, ip))
    #     self.clients_db.commit()
    #     return True
    #
    # def get_client(self, ip: str) -> list:
    #     self.clients_db_cursor.execute("""SELECT * FROM clients WHERE ip='%s'""" % (ip))
    #     client = self.clients_db_cursor.fetchone()
    #     return client


if __name__ == '__main__':
    f = Factory()
    f.protocol = Server
    reactor.listenSSL(30590, f, ssl.DefaultOpenSSLContextFactory('keys/private.key', 'keys/server.crt'))
    reactor.run()
