import socket
import subprocess
import sys
import rsa
import rsa.randnum
from Crypto.Cipher import AES

import authenticator

class Py_ssh_server:

    def __init__(self, host="", port=22, hostname="localhost"):
        self.generateKeys()
        self.HOST = host
        self.HOSTNAME = hostname
        self.PORT = port
        self.user = ""
        self.password = ""
        (self.publicKey, self.privateKey, self.sharedKey) = self.loadKeys()
        self.auth = False
        self.recievedPublicKey = None

    def start(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.bind((self.HOST, self.PORT))
            s.listen()

            conn, addr = s.accept()

            with conn:

                self.publicKeyTransaction(conn)
                self.sendSharedKey(conn)

                while True:

                    if not self.auth:
                        data = self.authentication(conn)
                    else:
                        data = self.commands(conn)

                    if not data:
                        conn.close()
                        return data

                    print(data)

    def publicKeyTransaction(self, conn):

        self.sendPublicKey(conn)

        recivedPublicKey = self.recievePublicKey(conn)
        recivedPublicKey = str(recivedPublicKey).split("(")[1].split(",")
        recivedPublicKey[1] = recivedPublicKey[1].split(")")[0].strip()

        keyN = int(recivedPublicKey[0])
        keyE = int(recivedPublicKey[1])

        self.recievedPublicKey = rsa.PublicKey(keyN, keyE)


    def authentication(self, conn):

        if self.user == "":
            self.send(conn, "User:")
            data = self.recieve(conn)
            self.user = data

        elif self.password == "":
            self.send(conn, "Password:")
            data = self.recieve(conn)
            self.password = data
            self.auth = authenticator.auth(self.user, self.password)

            if not self.auth:
                self.send(conn, "auth error")
                conn.close()
                sys.exit("Authentifizierung fehlgeschlagen")
        else:
            data = "Error"

        return data

    def commands(self, conn):

        self.send(conn, "{}@{}:".format(self.user, self.HOSTNAME))
        command = self.recieve(conn).split(" ")

        if command[0].lower() == "exit":
            conn.close()
            sys.exit()

        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.send(conn, "{}".format(output.stdout))
        except:
            self.send(conn, "command not found: {}".format(command[0]))
            output = "command not found: {}".format(command[0])

        return output


    def recievePublicKey(self, sock):
        data = sock.recv(1024)
        return data

    def sendPublicKey(self, conn):
        conn.sendall(bytes("{}".format(self.publicKey), "utf-8"))

    def testVerschluesselung(self):
        print("SharedKey: {}".format(self.sharedKey))
        message = rsa.encrypt(self.sharedKey, self.publicKey)
        print("Encrypted SharedKey: {}".format(message))
        message = rsa.decrypt(message, self.privateKey)
        print("Entschlüsselter SharedKey: {}".format(message))
        sys.exit("Test Ver- und entschlüsselung durchgeführt")

    def sendSharedKey(self, conn):
        message = rsa.encrypt(self.sharedKey, self.recievedPublicKey)
        #conn.sendall(bytes("{}".format(message), "utf-8"))
        conn.sendall(bytes("{}".format(self.sharedKey), "utf-8"))


    def send(self, conn, message):
        sender = AES.new("self.sharedKey12", AES.MODE_ECB)
        #message = sender.encrypt(message*16)
        conn.sendall(bytes("{}".format(message), "utf-8"))

    def recieve(self, conn):
        data = conn.recv(1024).decode("utf-8")
        reciever = AES.new("self.sharedKey12", AES.MODE_ECB)
        #data = reciever.decrypt(data)
        return str(data)


    def generateKeys(self):
        (publicKey, privateKey) = rsa.newkeys(1024)
        with open('keys/publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))
        with open('keys/sharedKey', 'wb') as p:
            p.write(rsa.randnum.read_random_bits(128))

    def loadKeys(self):
        with open('keys/publicKey.pem', 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())
        with open('keys/privateKey.pem', 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        with open('keys/sharedKey', 'rb') as s:
            sharedKey = s.read()
        return publicKey, privateKey, sharedKey