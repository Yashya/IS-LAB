# Import necessary modules for encryption
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

# Menu-driven program for selecting encryption
while True:
    print("\n--- Hospital Encryption Menu ---")
    print("Select your role:")
    print("1. Doctor")
    print("2. Nurse")
    print("3. Patient")
    print("4. Exit")
    role_choice = int(input("Enter your choice: "))

    if role_choice == 4:
        print("Exiting the program.")
        break

    if role_choice not in [1, 2, 3]:
        print("Invalid role choice! Please select a valid role.")
        continue

    print("\nSelect an option:")
    print("1. RSA Encryption/Decryption")
    print("2. ElGamal Encryption/Decryption")
    print("3. ECC Encryption/Decryption")
    algorithm_choice = int(input("Enter your choice: "))

    if algorithm_choice == 1:
        # RSA Encryption/Decryption
        print("\nYou selected RSA Encryption/Decryption")
        key = RSA.generate(1024)
        n, e, d = key.n, key.e, key.d
        print("n (modulus):", n)
        print("e (public exponent):", e)
        print("d (private exponent):", d)
        message = b"Asymmetric Encryption"
        c = pow(int.from_bytes(message, "big"), e, n)
        print("Encrypted message:", hex(c))
        m = pow(c, d, n)
        print("Decrypted message:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())

    elif algorithm_choice == 2:
        # ElGamal Encryption/Decryption
        print("\nYou selected ElGamal Encryption/Decryption")
        p = getPrime(256)
        g = random.randint(2, p - 1)
        x = random.randint(1, p - 2)
        h = pow(g, x, p)
        print("p (prime):", p)
        print("g (generator):", g)
        print("h (public key):", h)
        print("x (private key):", x)
        message = b"Confidential Data"
        k = random.randint(1, p - 2)
        c1 = pow(g, k, p)
        m = bytes_to_long(message)
        c2 = (m * pow(h, k, p)) % p
        print("c1:", c1)
        print("c2:", c2)
        s = pow(c1, x, p)
        s_inv = inverse(s, p)
        m_decrypted = (c2 * s_inv) % p
        decrypted_message = long_to_bytes(m_decrypted)
        print("Decrypted message:", decrypted_message.decode())

    elif algorithm_choice == 3:
        # ECC Encryption/Decryption
        print("\nYou selected ECC Encryption/Decryption")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("Public Key (PEM):")
        print(pem_public_key.decode())
        other_private_key = ec.generate_private_key(ec.SECP256R1())
        other_public_key = other_private_key.public_key()
        shared_secret = other_private_key.exchange(ec.ECDH(), public_key)
        aes_key = hashes.Hash(hashes.SHA256())
        aes_key.update(shared_secret)
        aes_key = aes_key.finalize()[:32]
        message = b"Secure Transactions"
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag
        print("Ciphertext:", ciphertext.hex())
        print("Nonce:", nonce.hex())
        print("Tag:", tag.hex())
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        print("Decrypted message:", decrypted_message.decode())

    else:
        print("Invalid encryption choice! Please select a valid option.")

    # Ask if user wants to continue or exit
    cont = input("\nDo you want to try again? (yes/no): ").strip().lower()
    if cont != 'yes':
        print("Exiting the program.")
        break
