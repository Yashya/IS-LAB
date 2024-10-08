import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def send_data(host='127.0.0.1', port=65432, message=b'Hello, Secure World!'):
    """Send data to the server and verify the integrity using hash."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Sending data: {message}")
        s.sendall(message)

        # Receive the hash from the server
        received_hash = s.recv(64).decode('utf-8')  # SHA-256 hash is 64 hex characters
        print(f"Received Hash from server: {received_hash}")

        # Compute the hash of the sent data locally
        local_hash = compute_hash(message)
        print(f"Local Hash: {local_hash}")

        # Verify integrity
        if local_hash == received_hash:
            print("Data integrity verified. No tampering detected.")
        else:
            print("Data integrity compromised! Hash mismatch detected.")

if __name__ == "__main__":
    send_data()
