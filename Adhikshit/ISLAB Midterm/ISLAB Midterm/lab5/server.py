import socket
import hashlib


def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()


# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_host = '127.0.0.1'  # Localhost
server_port = 12345  # Port number

server_socket.bind((server_host, server_port))
server_socket.listen(1)
print(f"Server is listening on {server_host}:{server_port}")

while True:
    # Accept a connection from the client
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Receive data from the client
    data = conn.recv(1024)
    if not data:
        break
    print(f"Data received from client: {data.decode()}")

    # Compute the hash of the received data
    received_hash = compute_hash(data)
    print(f"Computed hash: {received_hash}")

    # Send the hash back to the client
    conn.sendall(received_hash.encode())

    conn.close()
    print("Connection closed with the client.\n")
