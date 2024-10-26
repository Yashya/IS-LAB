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
def add_ciphertexts(public_key, ciphertexts):
    n, _ = public_key
    nsquare = n * n
    result = 1
    for ciphertext in ciphertexts:
        result = (result * ciphertext) % nsquare
    return result


def menu():
    print("Paillier Cryptosystem Menu")
    print("1. Generate Keys")
    print("2. Encrypt Numbers")
    print("3. Homomorphic Addition")
    print("4. Decrypt Sum")
    print("5. Exit")


public_key = None
private_key = None
ciphertexts = []

while True:
    menu()
    choice = input("Enter your choice: ")

    try:
        if choice == '1':
            # Generate keys
            public_key, private_key = generate_keys()
            print("Keys generated successfully.")

        elif choice == '2':
            # Encrypt numbers
            if not public_key:
                print("Please generate keys first.")
                continue
            num_inputs = int(input("Enter the number of integers to encrypt: "))
            ciphertexts = []
            for i in range(num_inputs):
                plaintext = int(input(f"Enter integer {i + 1}: "))
                ciphertext = encrypt(public_key, plaintext)
                ciphertexts.append(ciphertext)
                print(f"Ciphertext for integer {plaintext}: {ciphertext}")

        elif choice == '3':
            # Homomorphic addition
            if not ciphertexts:
                print("Please encrypt some numbers first.")
                continue
            ciphertext_sum = add_ciphertexts(public_key, ciphertexts)
            print("Ciphertext of the sum:", ciphertext_sum)

        elif choice == '4':
            # Decrypt the sum
            if not private_key or not ciphertexts:
                print("Please generate keys and encrypt numbers first.")
                continue
            ciphertext_sum = add_ciphertexts(public_key, ciphertexts)
            decrypted_sum = decrypt(private_key, public_key, ciphertext_sum)
            print("Decrypted sum:", decrypted_sum)

        elif choice == '5':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please select a valid option.")

    except Exception:
        print("An error occurred during execution.")
