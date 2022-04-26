import authenticator
from py_ssh_server import Py_ssh_server

server = Py_ssh_server()

#print(authenticator.auth("timo", "encrypt"))

server.start()