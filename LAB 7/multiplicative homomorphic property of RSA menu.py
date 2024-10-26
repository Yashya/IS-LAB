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
    ciphertext1 = ciphertext2 = None

    while True:
        print("\nRSA Multiplicative Homomorphic Encryption Program")
        print("1. Generate RSA Keys")
        print("2. Encrypt Two Integers")
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
                plaintext1 = int(input("Enter the first integer to encrypt: "))
                plaintext2 = int(input("Enter the second integer to encrypt: "))
                ciphertext1 = rsa_encrypt(public_key, plaintext1)
                ciphertext2 = rsa_encrypt(public_key, plaintext2)
                print("Ciphertext 1:", ciphertext1)
                print("Ciphertext 2:", ciphertext2)

        elif choice == "3":
            if not (ciphertext1 and ciphertext2):
                print("Encrypt integers first (Option 2).")
            else:
                ciphertext_product = (ciphertext1 * ciphertext2) % public_key[0]
                print("Ciphertext of product (homomorphic multiplication):", ciphertext_product)

        elif choice == "4":
            if not private_key:
                print("Generate keys first (Option 1).")
            elif not (ciphertext1 and ciphertext2):
                print("Encrypt integers first (Option 2).")
            else:
                # Compute homomorphic multiplication if not already computed
                ciphertext_product = (ciphertext1 * ciphertext2) % public_key[0]
                decrypted_product = rsa_decrypt(private_key, ciphertext_product)
                expected_product = plaintext1 * plaintext2
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
