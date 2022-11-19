from cryptography.fernet import Fernet
import base64
import getpass


def encrypt_data(data):
    # generate fernet key from encryption key
    password = getpass.getpass(prompt='Please enter encryption key: ')
    password_padded = str.ljust(password, 32, ' ')
    password_encoded = password_padded.encode('ascii')
    password_base64 = base64.b64encode(password_encoded)
    fernet = Fernet(password_base64)
    return fernet.encrypt(data.encode('utf-8')).decode('utf-8')


def decrypt_data(data):
    password = getpass.getpass(prompt='Please enter encryption key: ')
    password_padded = str.ljust(password, 32, ' ')
    password_encoded = password_padded.encode('ascii')
    password_base64 = base64.b64encode(password_encoded)
    fernet = Fernet(password_base64)
    return fernet.decrypt(data.encode('utf-8')).decode('utf-8')


def encrypt_env_file():
    with open('.env', 'rb') as file:
        original = file.read()
    encrypted = encrypt_data(original)
    with open('.env_encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


def decrypt_env_file():
    with open('.env_encrypted', 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = encrypt_data(encrypted)
    with open('.env', 'wb') as dec_file:
        dec_file.write(decrypted)


def generate_string_from_pem(private_key_pem_utf):
    split_key = private_key_pem_utf.split('\n')
    actual_key_parts = split_key[1:-2]
    long_string = ''.join(actual_key_parts)
    return long_string


def generate_pem_from_string(private_key_string_utf):
    header = '-----BEGIN PRIVATE KEY-----'
    footer = '-----END PRIVATE KEY-----'

    n = 64
    split_key = [private_key_string_utf[i:i + n] for i in range(0, len(private_key_string_utf), n)]
    split_key.insert(0, header)
    split_key.append(footer)
    split_key.append('')
    private_key_pem_utf = '\n'.join(split_key)
    return private_key_pem_utf
