import socket
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_rsa_key_pair():
    """Генерирует пару RSA ключей."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Сериализует открытый RSA ключ в PEM формат."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def start_server():
    """Запускает сервер и обрабатывает клиента."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Сервер запущен. Ожидание подключения...")

    client_socket, addr = server_socket.accept()
    print(f"Подключено к {addr}")

    # Генерация пары RSA ключей
    private_key, public_key = generate_rsa_key_pair()
    
    # Сериализация открытого ключа и отправка клиенту
    public_key_pem = serialize_public_key(public_key)
    client_socket.sendall(public_key_pem)

    # Получение зашифрованного AES ключа от клиента
    encrypted_aes_key = client_socket.recv(256)  # Размер буфера для AES ключа
    print("Получен зашифрованный AES ключ от клиента.")

    # Дешифрование AES ключа
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Расшифрованный AES ключ: {aes_key.hex()}")

    # Закрытие соединений
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
