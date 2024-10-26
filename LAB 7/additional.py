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

# Example usage
if __name__ == "__main__":
    # ElGamal Example
    p = 23  # A prime number
    g = 5   # A generator
    public_key, private_key = generate_elgamal_keys(p, g)
    m1 = 6  # Plaintext message 1
    m2 = 7  # Plaintext message 2

    # Encrypt messages using ElGamal
    enc1 = elgamal_encrypt(p, g, public_key[2], m1)
    enc2 = elgamal_encrypt(p, g, public_key[2], m2)

    # Perform homomorphic multiplication with ElGamal
    enc_product = elgamal_homomorphic_multiply(enc1, enc2, p)

    # Decrypt the product
    product = elgamal_decrypt(p, private_key, enc_product)
    print(f"ElGamal - Decrypted product of {m1} and {m2}: {product}")

    # Paillier Example
    bits = 8  # Bit length for keys
    paillier_public_key, paillier_private_key = generate_paillier_keys(bits)
    data1 = 10  # Party 1's data
    data2 = 15  # Party 2's data

    # Encrypt data using Paillier
    enc_data1 = paillier_encrypt(paillier_public_key[0], paillier_public_key[1], data1)
    enc_data2 = paillier_encrypt(paillier_public_key[0], paillier_public_key[1], data2)

    # Perform homomorphic addition with Paillier
    enc_sum = paillier_homomorphic_add(enc_data1, enc_data2, paillier_public_key[0])

    # Decrypt the sum
    sum_result = paillier_decrypt(paillier_public_key[0], paillier_private_key[0], paillier_private_key[1], enc_sum)
    print(f"Paillier - Decrypted sum of {data1} and {data2}: {sum_result}")
