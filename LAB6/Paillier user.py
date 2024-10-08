import random
from math import gcd


def mod_inverse(a, m):
    # Extended Euclidean Algorithm to find the modular inverse
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def lcm(a, b):
    return abs(a * b) // gcd(a, b)


def L(u, n):
    return (u - 1) // n


def generate_paillier_keypair(bits=512):
    # Step 1: Select two large prime numbers p and q
    p = random.getrandbits(bits)
    q = random.getrandbits(bits)
    while not gcd(p * q, (p - 1) * (q - 1)) == 1:
        p = random.getrandbits(bits)
        q = random.getrandbits(bits)

    n = p * q  # n = p * q
    nsquared = n * n  # n^2
    g = n + 1  # g can be n + 1 in Paillier

    # Step 2: Compute lambda = lcm(p-1, q-1)
    lambda_val = lcm(p - 1, q - 1)

    # Step 3: Compute mu = (L(g^lambda mod n^2))^-1 mod n
    u = pow(g, lambda_val, nsquared)
    mu = mod_inverse(L(u, n), n)

    return (n, g), (lambda_val, mu, p, q)


def encrypt(public_key, plaintext):
    n, g = public_key
    r = random.randint(1, n - 1)
    ciphertext = (pow(g, plaintext, n ** 2) * pow(r, n, n ** 2)) % n ** 2
    return ciphertext


def add_encrypted(public_key, c1, c2):
    n, _ = public_key
    return (c1 * c2) % (n ** 2)


def decrypt(private_key, public_key, ciphertext):
    n, _ = public_key
    lambda_val, mu, p, q = private_key
    u = pow(ciphertext, lambda_val, n ** 2)
    return L(u, n) * mu % n


def main():
    # Generate Paillier keypair
    print("Generating Paillier keypair...")
    public_key, private_key = generate_paillier_keypair()

    # Get user input for two integers
    try:
        plaintext1 = int(input("Enter the first integer to encrypt: "))
        plaintext2 = int(input("Enter the second integer to encrypt: "))
    except ValueError:
        print("Invalid input! Please enter integers only.")
        return

    # Encrypt two integers
    ciphertext1 = encrypt(public_key, plaintext1)
    ciphertext2 = encrypt(public_key, plaintext2)

    print(f"Ciphertext of {plaintext1}: {ciphertext1}")
    print(f"Ciphertext of {plaintext2}: {ciphertext2}")

    # Perform addition on encrypted integers
    encrypted_sum = add_encrypted(public_key, ciphertext1, ciphertext2)
    print(f"Encrypted sum of {plaintext1} and {plaintext2}: {encrypted_sum}")

    # Decrypt the result of the addition
    decrypted_sum = decrypt(private_key, public_key, encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")
    print(f"Original sum: {plaintext1 + plaintext2}")


if __name__ == "__main__":
    main()
