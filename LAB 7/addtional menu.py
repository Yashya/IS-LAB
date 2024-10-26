import random
from sympy import mod_inverse, isprime

# Function to generate a prime number
def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure it is odd and has the right length
    return p

def generate_prime(length):
    p = 4  # Placeholder for an even number
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

# ElGamal Key Generation
def generate_elgamal_keys(p, g):
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), x  # public key, private key

# ElGamal Encryption
def elgamal_encrypt(p, g, y, m):
    k = random.randint(1, p - 2)  # Random k
    c1 = pow(g, k, p)  # First part of ciphertext
    c2 = (m * pow(y, k, p)) % p  # Second part of ciphertext
    return (c1, c2)

# ElGamal Decryption
def elgamal_decrypt(p, x, ciphertext):
    c1, c2 = ciphertext
    s = pow(c1, x, p)  # Compute shared secret
    m = (c2 * mod_inverse(s, p)) % p  # Decrypt
    return m

# Homomorphic Multiplication for ElGamal
def elgamal_homomorphic_multiply(enc1, enc2, p):
    c1_1, c2_1 = enc1
    c1_2, c2_2 = enc2
    # Multiply encrypted messages
    c1 = (c1_1 * c1_2) % p
    c2 = (c2_1 * c2_2) % p
    return (c1, c2)

# Paillier Key Generation
def generate_paillier_keys(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    g = n + 1  # Use g = n + 1 for simplicity
    return (n, g), (p, q)  # Public key, Private key

# Paillier Encryption
def paillier_encrypt(n, g, m):
    r = random.randint(1, n - 1)  # Random r
    c = (pow(g, m, n**2) * pow(r, n, n**2)) % (n**2)  # Ciphertext
    return c

# Paillier Decryption
def paillier_decrypt(n, p, q, c):
    # Decryption logic
    lambd = (p - 1) * (q - 1)
    mu = mod_inverse(lambd, n)
    u = (pow(c, lambd, n**2) - 1) // n
    m = (u * mu) % n
    return m

# Paillier Homomorphic Addition
def paillier_homomorphic_add(c1, c2, n):
    return (c1 * c2) % (n**2)

# Main Menu
def main_menu():
    while True:
        print("\n--- PHE Operations Menu ---")
        print("1. ElGamal Homomorphic Multiplication")
        print("2. Paillier Secure Data Sharing")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            elgamal_operations()
        elif choice == '2':
            paillier_operations()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

# ElGamal Operations
def elgamal_operations():
    p = 23  # A prime number
    g = 5   # A generator
    public_key, private_key = generate_elgamal_keys(p, g)

    num_inputs = int(input("Enter the number of messages to multiply: "))
    encrypted_messages = []

    for i in range(num_inputs):
        m = int(input(f"Enter message {i + 1}: "))
        enc = elgamal_encrypt(p, g, public_key[2], m)
        encrypted_messages.append(enc)

    # Perform homomorphic multiplication
    result_enc = encrypted_messages[0]
    for enc in encrypted_messages[1:]:
        result_enc = elgamal_homomorphic_multiply(result_enc, enc, p)

    # Decrypt the product
    product = elgamal_decrypt(p, private_key, result_enc)
    print(f"ElGamal - Decrypted product of messages: {product}")

# Paillier Operations
def paillier_operations():
    bits = 8  # Bit length for keys
    paillier_public_key, paillier_private_key = generate_paillier_keys(bits)

    num_inputs = int(input("Enter the number of data inputs to share: "))
    encrypted_data = []

    for i in range(num_inputs):
        data = int(input(f"Enter data {i + 1}: "))
        enc_data = paillier_encrypt(paillier_public_key[0], paillier_public_key[1], data)
        encrypted_data.append(enc_data)

    # Perform homomorphic addition
    result_enc = encrypted_data[0]
    for enc in encrypted_data[1:]:
        result_enc = paillier_homomorphic_add(result_enc, enc, paillier_public_key[0])

    # Decrypt the sum
    sum_result = paillier_decrypt(paillier_public_key[0], paillier_private_key[0], paillier_private_key[1], result_enc)
    print(f"Paillier - Decrypted sum of data inputs: {sum_result}")

# Run the program
if __name__ == "__main__":
    main_menu()
