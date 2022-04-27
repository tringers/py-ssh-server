import hashlib

from read_files import Reader

def auth(try_user, try_password):

    shadow = Reader("shadow")
    users = shadow.getUsernames()
    passwords = shadow.getEncryptedUserPassword()

    for counter in range(len(users)):
        if users[counter].lower() == try_user.lower():
            if passwords[counter] == str(try_password):
                return True

    return False