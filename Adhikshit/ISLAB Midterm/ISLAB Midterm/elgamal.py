def isprime(n):
    if n <= 1:
        return 0
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return 0
    return 1


def encrypt(pt, r, e2, p):
    # Encrypt the plaintext using modular exponentiation
    c2 = pow(e2, r, p)
    c2 = (c2 * pt) % p
    return c2


def decrypt(c1, c2, d, p):
    # Calculate C1^d mod p
    k = pow(c1, d, p)

    # Calculate the modular inverse of k under modulo p
    # This gives us (C1^d)^-1 mod p
    k_inverse = pow(k, p - 2, p)  # Fermat's Little Theorem
    pt = (c2 * k_inverse) % p
    return pt


def main():
    # Input prime values for p, e1 (primitive root), and d (secret key)
    p = int(input("Enter a large prime value for p: "))
    e1 = int(input("Enter primitive root e1 such that 1 <= e1 <= p-2: "))
    d = int(input("Enter the secret key d such that 1 <= d <= p-2: "))

    # Calculate public key e2
    e2 = pow(e1, d, p)
    print(f"The public keys are (e1, e2, p) = ({e1}, {e2}, {p})")
    print(f"The private key is d = {d}")

    # Choose a random integer r
    r = int(input("Enter a random integer r such that 1 <= r <= p-2: "))
    c1 = pow(e1, r, p)  # Calculate C1
    print(f"C1 is {c1}\n")

    # Input plaintext as a string and convert each character to its ASCII value
    pt = input("Enter the plaintext: ")
    c2 = []  # Store encrypted values as a list of integers
    print("Encryption:\n")
    for i in pt:
        c2.append(encrypt(ord(i), r, e2, p))  # Encrypt each ASCII value
    print(f"C2 (ciphertext) is: {c2}\n")  # Display the encrypted values

    # Decrypt the ciphertext back to plaintext (as a list of integers)
    pt2 = []  # Store decrypted integer values
    print("Decryption\n")
    for c in c2:
        pt2.append(decrypt(c1, c, d, p))  # Decrypt each value back to its integer form
    print(f"The decrypted list of ASCII values is: {pt2}")  # Display as a list of integers


if __name__ == "__main__":
    main()
