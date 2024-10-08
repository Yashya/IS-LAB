import numpy as np


# Function to generate the Hill cipher key matrix
def generate_key_matrix(key):
    return np.array(key).reshape(2, 2)


# Function to mod 26 for letters
def mod26(x):
    return x % 26


# Function to encipher a plaintext using the Hill cipher
def hill_encrypt(plaintext, key):
    # Generate the key matrix
    key_matrix = generate_key_matrix(key)

    # Clean and prepare the plaintext
    plaintext = plaintext.lower().replace(" ", "")  # Remove spaces and convert to lower case
    while len(plaintext) % 2 != 0:  # Ensure even length by appending 'x'
        plaintext += 'x'

    ciphertext = ''

    # Process the plaintext in pairs (digraphs)
    for i in range(0, len(plaintext), 2):
        # Take two letters
        digraph = plaintext[i:i + 2]
        # Convert letters to numbers (a=0, b=1, ..., z=25)
        vector = np.array([ord(digraph[0]) - ord('a'), ord(digraph[1]) - ord('a')])

        # Perform matrix multiplication and mod 26
        encrypted_vector = mod26(np.dot(key_matrix, vector))

        # Convert back to letters
        ciphertext += chr(encrypted_vector[0] + ord('a'))
        ciphertext += chr(encrypted_vector[1] + ord('a'))

    return ciphertext


# Main function to take user input and encrypt the message
if __name__ == "__main__":
    # Key matrix provided as a list
    key = [3, 3, 2, 7]
    plaintext = "We live in an insecure world"

    encrypted_message = hill_encrypt(plaintext, key)
    print(f"Encrypted Message: {encrypted_message}")
