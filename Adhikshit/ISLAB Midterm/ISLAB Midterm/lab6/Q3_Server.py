import socket
from Crypto.Util.number import getPrime
import random

class DiffieHellmanServer:
    def __init__(self, key_size):
        self.p = getPrime(key_size)
        self.g = random.randint(2, self.p-1)
        self.private_key = random.randint(1, self.p-1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, client_public_key):
        return pow(client_public_key, self.private_key, self.p)

# Server setup
server = DiffieHellmanServer(256)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("Server listening on port 9999")

conn, addr = server_socket.accept()
print(f"Connected to {addr}")

# Send server's public key to client
conn.send(str(server.public_key).encode())

# Receive client's public key
client_public_key = int(conn.recv(1024).decode())
shared_key = server.generate_shared_key(client_public_key)
print(f"Shared key: {shared_key}")

conn.close()
server_socket.close()
