import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

# Set up the client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_host = '127.0.0.1'  # Server's IP address (localhost)
server_port = 12345         # Same port number as the server

client_socket.connect((server_host, server_port))
print("Connected to the server.")

# Input the data to be sent
data = input("Enter the data to send: ").encode()

# Send the data to the server
client_socket.sendall(data)
print(f"Data sent to server: {data.decode()}")

# Receive the computed hash from the server
server_hash = client_socket.recv(1024).decode()
print(f"Hash received from server: {server_hash}")

# Compute the hash locally
local_hash = compute_hash(data)
print(f"Locally computed hash: {local_hash}")

# Verify integrity
if server_hash == local_hash:
    print("Data integrity verified: No corruption or tampering detected.")
else:
    print("Data integrity verification failed: Possible corruption or tampering detected.")

client_socket.close()
