import socket
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def generate_aes_key():
    """Генерирует случайный AES ключ."""
    return os.urandom(32)

def encrypt_aes_key(public_key, aes_key):
    """Шифрует AES ключ с использованием открытого RSA ключа."""
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def load_public_key(pem_data):
    """Загружает открытый RSA ключ из PEM данных."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def start_client():
    """Запускает клиента и взаимодействует с сервером."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    public_key_pem = client_socket.recv(1024)
    public_key = load_public_key(public_key_pem)
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_aes_key(public_key, aes_key)
    client_socket.sendall(encrypted_aes_key)
    print(aes_key.hex())
    print("Зашифрованный AES ключ отправлен серверу.")
    client_socket.close()

if __name__ == "__main__":
    start_client()
