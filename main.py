from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet


def raw_encrypt(data, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encrypted_password = urlsafe_b64encode(kdf.derive(password))
    cipher_suite = Fernet(encrypted_password)
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

if __name__ == '__main__':
    with open('salt', 'rb') as salt_file:
        salt = salt_file.read()
    print(raw_encrypt(b'Hello dis is coop', b'test', salt))