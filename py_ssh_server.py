import socket
import subprocess
import sys
import pyDH
import rsa

import authenticator

diffieHellman = pyDH.DiffieHellman()

class Py_ssh_server:

    def __init__(self, host="", port=22):
        self.generateKeys()
        self.HOST = host
        self.PORT = port
        self.user = ""
        self.password = ""
        self.auth = False
        (self.publicKey, self.privateKey) = self.loadKeys()
        self.sharedKey = None

    def start(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.bind((self.HOST, self.PORT))
            s.listen()

            conn, addr = s.accept()

            with conn:

                self.sendPublicKey(conn)

                recivevedpub = self.recievePublicKey(s)
                recivevedpub = str(recivevedpub).split("(")[1].split(",")
                recivevedpub[1] = recivevedpub[1].split(")")[0].strip()

                keyN = int(recivevedpub[0])
                keyE = int(recivevedpub[1])
                pub = rsa.PublicKey(keyN, keyE)

                self.sharedKey = diffieHellman.gen_shared_key(
                    pub
                )

                self.send(conn, "User:")

                while True:

                    if not self.auth:
                        data = self.recieve(conn)
                        data = self.authentication(conn, data)
                    else:
                        data = self.commands(conn)

                    if not data:
                        conn.close()
                        return data

                    print(data)

    def authentication(self, conn, data):

        if self.user == "":
            self.user = data
            if self.user != "":
                self.send(conn, "Password:")
            else:
                print("Username not recived!")

        elif self.password == "":
            self.password = data
            self.auth = authenticator.auth(self.user, self.password)

            if not self.auth:
                self.send(conn, "auth error")
                conn.close()
                sys.exit("Authentifizierung fehlgeschlagen")

        return data

    def commands(self, conn):

        self.send(conn, "{}@Server:".format(self.user))
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

    def sendPublicKey(self, conn):
        conn.sendall(bytes("{}".format(self.publicKey), "utf-8"))

    def send(self, conn, message):
        message = rsa.encrypt(message.encode('ascii'), self.publicKey)
        conn.sendall(bytes("{}".format(message), "utf-8"))

    def recievePublicKey(self, sock):
        data = sock.recv(1024)
        return data

    def recieve(self, conn):
        data = conn.recv(1024)
        data = rsa.decrypt(data, self.sharedKey)
        return str(data)

    def generateKeys(self):
        (publicKey, privateKey) = rsa.newkeys(1024)
        with open('keys/publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))

    def loadKeys(self):
        with open('keys/publicKey.pem', 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())
        with open('keys/privateKey.pem', 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        return publicKey, privateKey