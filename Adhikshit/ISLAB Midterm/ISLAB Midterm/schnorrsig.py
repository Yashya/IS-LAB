from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
import hashlib
import random

# 1. Key Generation
def generate_schnorr_keys():
    q = getPrime(160)  # Smaller prime q
    p = getPrime(512)  # Larger prime p
    while (p - 1) % q != 0:  # Ensure p-1 is divisible by q
        p = getPrime(512)
    g = pow(2, (p - 1) // q, p)  # Generator g of the subgroup of order q
    x = random.randint(1, q - 1)  # Private key x
    y = pow(g, x, p)  # Public key y
    return p, q, g, x, y

# 2. Signing Function
def schnorr_sign(message, p, q, g, x):
    # Choose a random k such that 1 <= k <= q-1
    k = random.randint(1, q - 1)
    r = pow(g, k, p)  # r = g^k mod p
    # Compute hash of the message and r concatenated (message || r)
    hash_value = hashlib.sha256(message + long_to_bytes(r)).digest()
    e = bytes_to_long(hash_value) % q  # e = H(message || r) mod q
    s = (k + x * e) % q  # s = (k + x * e) mod q
    return (r, s)

# 3. Verification Function
def schnorr_verify(message, r, s, p, q, g, y):
    if not (0 < r < p):
        return False
    # Compute e = H(message || r) mod q
    hash_value = hashlib.sha256(message + long_to_bytes(r)).digest()
    e = bytes_to_long(hash_value) % q
    # Check if g^s mod p == r * y^e mod p
    left = pow(g, s, p)
    right = (r * pow(y, e, p)) % p
    return left == right

# Main function to simulate the signing and verification process
def main():
    # Generate Schnorr keys for demonstration
    p, q, g, x, y = generate_schnorr_keys()
    print("Public Key (p, q, g, y):", (p, q, g, y))
    print("Private Key (x):", x)

    while True:
        print("\n--- Schnorr Digital Signature ---")
        print("1. Sign a Message")
        print("2. Verify a Message")
        print("3. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            # Signing Operation
            message = input("Enter the message to be signed: ").encode()
            r, s = schnorr_sign(message, p, q, g, x)
            print(f"\nMessage: {message.decode()}")
            print(f"Signature: (r: {r}, s: {s})")

        elif choice == 2:
            # Verification Operation
            message = input("Enter the message to be verified: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verification_result = schnorr_verify(message, r, s, p, q, g, y)
                if verification_result:
                    print("\nSignature verified successfully! The message is authentic.")
                else:
                    print("\nSignature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")

        elif choice == 3:
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please select a valid option.")

# Run the program
if __name__ == "__main__":
    main()
