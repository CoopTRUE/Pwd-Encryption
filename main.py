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

def encrypt(data = False, password = False, salt = False):
    print("ENCRYPTING")
    input_text = data or input("Text: ")
    input_password = password or input("Password: ")
    assert input_password == input("Confirm Password: ")
    encrypted_text = raw_encrypt(input_text.encode(), input_password.encode(), salt or get_salt())
    print(f"Encrypted text '{encrypted_text.decode()}'",)


if __name__ == '__main__':
    encrypt()