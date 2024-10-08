# Create the Playfair matrix
def generate_playfair_matrix(key):
    key = key.lower().replace("j", "i")  # Replace 'j' with 'i'
    matrix = []
    used = set()

    # Step 1: Add the key letters to the matrix
    for char in key:
        if char not in used and char.isalpha():
            matrix.append(char)
            used.add(char)

    # Step 2: Fill the rest of the matrix with remaining letters
    alphabet = 'abcdefghiklmnopqrstuvwxyz'  # 'j' is omitted
    for char in alphabet:
        if char not in used:
            matrix.append(char)

    # Reshape the matrix into 5x5 grid
    matrix_5x5 = [matrix[i:i + 5] for i in range(0, 25, 5)]
    return matrix_5x5


# Function to find the position of a letter in the Playfair matrix
def find_position(letter, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None


# Playfair cipher encryption
def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.lower().replace(" ", "").replace("j", "i")  # Handle spaces and 'j'

    # Step 1: Prepare the plaintext into digraphs
    digraphs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 < len(plaintext):
            b = plaintext[i + 1]
        else:
            b = 'x'  # If it's odd length, append 'x'

        if a == b:
            digraphs.append(a + 'x')  # Add 'x' between identical letters
            i += 1
        else:
            digraphs.append(a + b)
            i += 2

    # Step 2: Encrypt each digraph
    ciphertext = ''
    for digraph in digraphs:
        a, b = digraph
        row_a, col_a = find_position(a, matrix)
        row_b, col_b = find_position(b, matrix)

        if row_a == row_b:
            # Same row, replace with letter to the right
            ciphertext += matrix[row_a][(col_a + 1) % 5]
            ciphertext += matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            # Same column, replace with letter below
            ciphertext += matrix[(row_a + 1) % 5][col_a]
            ciphertext += matrix[(row_b + 1) % 5][col_b]
        else:
            # Form a rectangle, swap the corners
            ciphertext += matrix[row_a][col_b]
            ciphertext += matrix[row_b][col_a]

    return ciphertext


# Main function to take user input
if __name__ == "__main__":
    key = input("Enter the secret key (no spaces, use only letters): ")
    plaintext = input("Enter the message to encrypt (spaces will be ignored): ")

    encrypted_message = playfair_encrypt(plaintext, key)
    print(f"Encrypted Message: {encrypted_message}")
