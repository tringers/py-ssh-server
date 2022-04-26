import socket
import subprocess
import sys

import authenticator

class Py_ssh_server:

    def __init__(self, host="", port=22):
        self.HOST = host
        self.PORT = port
        self.user = ""
        self.password = ""
        self.auth = False

    def send(self, conn, message):
        conn.sendall(bytes("{}".format(message), "utf-8"))

    def recieve(self, conn):
        data = conn.recv(1024)
        return str(data.decode("utf-8"))

    def start(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()

            with conn:

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

        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.send(conn, "{}".format(output.stdout))



        return output
