# fileencryption/utils.py

from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
CIPHER_SUITE = Fernet(KEY)

def generate_key():
    return Fernet.generate_key()
# def encrypt_file(file):
#     data = file.read()
#     encrypted_data = CIPHER_SUITE.encrypt(data)
#     return encrypted_data
#
# def decrypt_file(encrypted_data):
#     decrypted_data = CIPHER_SUITE.decrypt(encrypted_data)
#     return decrypted_data
def encrypt_file(file_content, key):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(file_content)
    return encrypted_data

def decrypt_file(encrypted_data, key):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data