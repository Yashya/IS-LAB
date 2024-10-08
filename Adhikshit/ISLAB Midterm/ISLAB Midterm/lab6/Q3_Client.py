import socket
from Crypto.Util.number import getPrime
import random

class DiffieHellmanClient:
    def __init__(self, key_size):
        self.p = getPrime(key_size)
        self.g = random.randint(2, self.p-1)
        self.private_key = random.randint(1, self.p-1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, server_public_key):
        return pow(server_public_key, self.private_key, self.p)

# Client setup
client = DiffieHellmanClient(256)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))

# Receive server's public key
server_public_key = int(client_socket.recv(1024).decode())

# Send client's public key
client_socket.send(str(client.public_key).encode())

# Generate shared key
shared_key = client.generate_shared_key(server_public_key)
print(f"Shared key: {shared_key}")

client_socket.close()
