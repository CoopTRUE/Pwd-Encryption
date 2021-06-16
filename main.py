
def raw_encrypt(data, password, salt):
    pass

if __name__ == '__main__':
    with open('salt.txt', 'rt') as salt_file:
        salt = salt_file.read()