from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
import random


# 1. Key Generation for ElGamal
def generate_keys():
    p = getPrime(256)  # Large prime number
    g = random.randint(2, p - 1)  # Generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return (p, g, h, x)


# 2. Signing Function
def elgamal_sign(message, p, g, x):
    while True:
        k = random.randint(1, p - 2)  # Random ephemeral key
        if GCD(k, p - 1) == 1:  # Check if `k` is coprime with `p-1`
            break

    r = pow(g, k, p)  # Compute r = g^k mod p
    m = bytes_to_long(message)  # Convert message to a long integer
    s = (m - x * r) * inverse(k, p - 1) % (p - 1)  # Compute s
    return (r, s)


# 3. Verification Function
def elgamal_verify(message, r, s, p, g, h):
    if not (0 < r < p):
        return False
    m = bytes_to_long(message)
    v1 = pow(g, m, p)  # v1 = g^m mod p
    v2 = (pow(h, r, p) * pow(r, s, p)) % p  # v2 = (h^r * r^s) mod p
    return v1 == v2


# Main function with if-elif-else structure
def main():
    # Generate keys for demonstration
    p, g, h, x = generate_keys()
    print("Public Key (p, g, h):", (p, g, h))
    print("Private Key (x):", x)

    while True:
        print("\n--- ElGamal Digital Signature ---")
        print("1. Sign a Message")
        print("2. Verify a Message")
        print("3. Exit")

        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        # Using if-elif-else instead of match-case
        if choice == 1:  # Signing Operation
            message = input("Enter the message to be signed: ").encode()
            r, s = elgamal_sign(message, p, g, x)
            print(f"\nMessage: {message.decode()}")
            print(f"Signature: (r: {r}, s: {s})")

        elif choice == 2:  # Verification Operation
            message = input("Enter the message to be verified: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verification_result = elgamal_verify(message, r, s, p, g, h)
                if verification_result:
                    print("\nSignature verified successfully! The message is authentic.")
                else:
                    print("\nSignature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")

        elif choice == 3:  # Exit
            print("Exiting the program.")
            break

        else:  # Default case, if no valid option is chosen
            print("Invalid choice! Please select a valid option.")


# Run the program
if __name__ == "__main__":
    main()
