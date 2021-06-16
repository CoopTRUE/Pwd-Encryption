from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet

def get_cipher(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encrypted_password = urlsafe_b64encode(kdf.derive(password))
    cipher_suite = Fernet(encrypted_password)
    return cipher_suite

def raw_encrypt(data, password, salt):
    cipher_suite = get_cipher(password, salt)
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

def raw_decrypt(encrypted_data, password, salt):
    cipher_suite = get_cipher(password, salt)
    decryted_data = cipher_suite.decrypt(encrypted_data)
    return decryted_data

def get_salt():
    with open('salt', 'rb') as salt_file:
        salt = salt_file.read()
    return salt

def strs_to_bytes(*args):
    return [arg.encode() if isinstance(arg, str) else arg for arg in args]

def encrypt(data = False, password = False, salt = False):
    print("ENCRYPT")
    data = data or input("Text: ")
    password = password or input("Password: ")
    salt = salt or get_salt()

    data, password, salt = strs_to_bytes(data, password, salt)

    cipher_suite = get_cipher(password, salt)
    encrypted_text = cipher_suite.encrypt(data)
    print(encrypted_text)


if __name__ == '__main__':
    encrypt('Coop', 'test')