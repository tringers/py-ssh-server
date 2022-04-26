import unittest

from py_ssh_server import Py_ssh_server

class ClientTests(unittest.TestCase):

    def runServerTest(self):
        server = Py_ssh_server()
        server.start()