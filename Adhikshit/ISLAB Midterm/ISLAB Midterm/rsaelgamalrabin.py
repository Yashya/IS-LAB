# Import necessary modules for encryption
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

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
    print("3. Rabin Encryption/Decryption")
    algorithm_choice = int(input("Enter your choice: "))

    message = input("Enter the message you want to encrypt: ").encode()  # User-provided message

    if algorithm_choice == 1:
        # RSA Encryption/Decryption
        print("\nYou selected RSA Encryption/Decryption")
        key = RSA.generate(1024)
        n, e, d = key.n, key.e, key.d
        print("n (modulus):", n)
        print("e (public exponent):", e)
        print("d (private exponent):", d)
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
        # Rabin Encryption/Decryption
        print("\nYou selected Rabin Encryption/Decryption")
        p = getPrime(256)
        q = getPrime(256)
        n = p * q
        print("p:", p)
        print("q:", q)
        print("n (modulus):", n)

        # Encrypt the message
        m = bytes_to_long(message)
        c = pow(m, 2, n)
        print("Encrypted message:", c)

        # Decrypt the message using Rabin's decryption formula
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)
        q_inv = inverse(q, p)

        # Chinese Remainder Theorem (CRT) to combine results
        r1 = (q * q_inv * mp + p * ((inverse(p, q)) * mq)) % n
        r2 = n - r1
        r3 = (q * q_inv * mp - p * ((inverse(p, q)) * mq)) % n
        r4 = n - r3

        # Displaying the possible decrypted messages
        print("Possible decrypted messages:")
        print("1:", long_to_bytes(r1).decode(errors='ignore'))
        print("2:", long_to_bytes(r2).decode(errors='ignore'))
        print("3:", long_to_bytes(r3).decode(errors='ignore'))
        print("4:", long_to_bytes(r4).decode(errors='ignore'))

    else:
        print("Invalid encryption choice! Please select a valid option.")

    # Ask if user wants to continue or exit
    cont = input("\nDo you want to try again? (yes/no): ").strip().lower()
    if cont != 'yes':
        print("Exiting the program.")
        break
