import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_server(host='127.0.0.1', port=65432):
    """Start the server to listen for incoming connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print(f"Received data: {data}")

            # Compute the hash of the received data
            data_hash = compute_hash(data)
            print(f"Computed Hash: {data_hash}")

            # Send the hash back to the client
            conn.sendall(data_hash.encode('utf-8'))

if __name__ == "__main__":
    start_server()
