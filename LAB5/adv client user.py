import socket
import hashlib

# Function to compute hash of a given message
def compute_hash(data):
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    return hash_object.hexdigest()

# Client to send message parts and verify hash
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))  # Connect to localhost and port 65432

    # Take user input for the message to be sent
    original_message = input("Enter the message to be sent: ")

    # Split the message into parts (e.g., parts of 10 characters each)
    message_parts = [original_message[i:i+10] for i in range(0, len(original_message), 10)]

    # Send each part to the server
    for part in message_parts:
        client_socket.sendall(part.encode('utf-8'))

    # After sending all parts, close the sending side
    client_socket.shutdown(socket.SHUT_WR)

    # Compute the hash of the original message on the client side
    original_hash = compute_hash(original_message)
    print(f"Hash of original message (client-side): {original_hash}")

    # Receive the hash from the server
    server_hash = client_socket.recv(1024).decode('utf-8')
    print(f"Hash received from server: {server_hash}")

    # Verify integrity by comparing hashes
    if original_hash == server_hash:
        print("Message integrity verified. No tampering detected.")
    else:
        print("Message integrity verification failed. Data may have been corrupted.")

    # Close the connection
    client_socket.close()

if __name__ == '__main__':
    start_client()
