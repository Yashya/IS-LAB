import socket
import hashlib


# Function to compute hash of a given message
def compute_hash(data):
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    return hash_object.hexdigest()


# Server to receive message parts and compute hash
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))  # Bind to localhost and port 65432
    server_socket.listen(1)
    print("Server listening for connections...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    reassembled_message = ""

    while True:
        # Receive message part by part (1024 bytes at a time)
        data = conn.recv(1024)
        if not data:
            break  # End of message parts, no more data

        # Append received data to reassembled message
        reassembled_message += data.decode('utf-8')

    print("Message reassembled on server:", reassembled_message)

    # Compute hash of the reassembled message
    reassembled_hash = compute_hash(reassembled_message)
    print(f"Hash of reassembled message: {reassembled_hash}")

    # Send the hash back to the client
    conn.sendall(reassembled_hash.encode('utf-8'))

    # Close the connection
    conn.close()
    server_socket.close()


if __name__ == '__main__':
    start_server()
