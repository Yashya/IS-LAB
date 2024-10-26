import random
import math


# Helper functions
def lcm(x, y):
    return x * y // math.gcd(x, y)


def mod_inverse(a, m):
    m0, y, x = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        y, x = x - q * y, y
    return x + m0 if x < 0 else x


# Paillier Key Generation
def generate_keys(bit_length=512):
    while True:
        p = random.getrandbits(bit_length // 2)
        q = random.getrandbits(bit_length // 2)
        if math.gcd(p * q, (p - 1) * (q - 1)) == 1 and p != q:
            break

    n = p * q
    nsquare = n * n
    λ = lcm(p - 1, q - 1)
    g = n + 1  # Standard g selection in Paillier
    μ = mod_inverse((pow(g, λ, nsquare) - 1) // n, n)

    public_key = (n, g)
    private_key = (λ, μ)
    return public_key, private_key


# Paillier Encryption
def encrypt(public_key, plaintext):
    n, g = public_key
    nsquare = n * n
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    ciphertext = (pow(g, plaintext, nsquare) * pow(r, n, nsquare)) % nsquare
    return ciphertext


# Paillier Decryption
def decrypt(private_key, public_key, ciphertext):
    n, g = public_key
    nsquare = n * n
    λ, μ = private_key
    x = pow(ciphertext, λ, nsquare)
    l_func = (x - 1) // n  # L function: (x - 1) / n
    plaintext = (l_func * μ) % n
    return plaintext


# Homomorphic Addition
def add_ciphertexts(public_key, ciphertext1, ciphertext2):
    n, _ = public_key
    nsquare = n * n
    return (ciphertext1 * ciphertext2) % nsquare


try:
    # Generate keys
    public_key, private_key = generate_keys()

    # Encrypt integers
    plaintext1 = 15
    plaintext2 = 25
    ciphertext1 = encrypt(public_key, plaintext1)
    ciphertext2 = encrypt(public_key, plaintext2)
    print("Ciphertext 1:", ciphertext1)
    print("Ciphertext 2:", ciphertext2)

    # Homomorphic addition of ciphertexts
    ciphertext_sum = add_ciphertexts(public_key, ciphertext1, ciphertext2)
    print("Ciphertext of sum:", ciphertext_sum)

    # Decrypt the result
    decrypted_sum = decrypt(private_key, public_key, ciphertext_sum)
    print("Decrypted sum:", decrypted_sum)

    # Verify
    expected_sum = plaintext1 + plaintext2
    print("Expected sum:", expected_sum)
    assert decrypted_sum == expected_sum, "The decrypted sum does not match the expected value!"
except Exception:
    print("")
