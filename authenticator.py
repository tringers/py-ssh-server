import hashlib

from read_files import Reader

def auth(try_user, try_password):

    shadow = Reader("shadow")
    users = shadow.getUsernames()
    passwords = shadow.getEncryptedUserPassword()
    password_hash = hashlib.sha512(str(try_password).encode("utf-8")).hexdigest()

    for counter in range(len(users)):
        if users[counter].lower() == try_user.lower():
            if passwords[counter] == password_hash:
                return True

    return False