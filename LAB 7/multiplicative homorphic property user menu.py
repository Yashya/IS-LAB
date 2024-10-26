import random
import math
from sympy import randprime


# Helper function for modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


# RSA Key Generation
def generate_rsa_keys(bit_length=512):
    p = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))
    q = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Common choice for e
    e = 65537
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Calculate d as the modular inverse of e mod phi_n
    d = pow(e, -1, phi_n)

    # Public key (n, e) and Private key (n, d)
    return (n, e), (n, d)


# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    n, e = public_key
    return mod_exp(plaintext, e, n)


# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    n, d = private_key
    return mod_exp(ciphertext, d, n)


# Main menu-driven program
def main():
    public_key = private_key = None
    ciphertexts = []
    original_plaintexts = []

    while True:
        print("\nRSA Multiplicative Homomorphic Encryption Program")
        print("1. Generate RSA Keys")
        print("2. Encrypt Integers")
        print("3. Perform Homomorphic Multiplication")
        print("4. Decrypt the Result of Multiplication")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            public_key, private_key = generate_rsa_keys()
            print("Keys generated successfully!")
            print("Public Key:", public_key)
            print("Private Key:", private_key)

        elif choice == "2":
            if not public_key:
                print("Generate keys first (Option 1).")
            else:
                num_inputs = int(input("Enter the number of integers to encrypt: "))
                for i in range(num_inputs):
                    plaintext = int(input(f"Enter integer {i + 1}: "))
                    original_plaintexts.append(plaintext)
                    ciphertext = rsa_encrypt(public_key, plaintext)
                    ciphertexts.append(ciphertext)
                    print(f"Ciphertext {i + 1}:", ciphertext)

        elif choice == "3":
            if len(ciphertexts) < 2:
                print("Encrypt at least two integers first (Option 2).")
            else:
                # Multiply all ciphertexts together
                ciphertext_product = 1
                for ciphertext in ciphertexts:
                    ciphertext_product = (ciphertext_product * ciphertext) % public_key[0]
                print("Ciphertext of product (homomorphic multiplication):", ciphertext_product)

        elif choice == "4":
            if not private_key:
                print("Generate keys first (Option 1).")
            elif len(ciphertexts) < 2:
                print("Encrypt at least two integers first (Option 2).")
            else:
                # Compute the product of the original integers
                expected_product = 1
                for plaintext in original_plaintexts:
                    expected_product *= plaintext

                # Compute decrypted product
                ciphertext_product = 1
                for ciphertext in ciphertexts:
                    ciphertext_product = (ciphertext_product * ciphertext) % public_key[0]

                decrypted_product = rsa_decrypt(private_key, ciphertext_product)
                print("Decrypted product:", decrypted_product)
                print("Expected product:", expected_product)
                if decrypted_product == expected_product:
                    print("The decrypted product matches the expected product!")
                else:
                    print("Mismatch: The decrypted product does not match the expected product.")

        elif choice == "5":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")


# Run the main program
if __name__ == "__main__":
    main()
