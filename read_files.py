
class Reader():

    def __init__(self, file):
        self.file = open("shadow", "r")
        self.lines = self.file.readlines()

    def getUsernames(self):

        usernames = []

        for line in self.lines:
            entries = line.replace("\n", "")
            usernames.append(entries.split(":")[0])

        return usernames

    def getEncryptedUserPassword(self):

        passwords = []

        for line in self.lines:
            entries = line.replace("\n", "")
            passwords.append(entries.split(":")[1])

        return passwords
