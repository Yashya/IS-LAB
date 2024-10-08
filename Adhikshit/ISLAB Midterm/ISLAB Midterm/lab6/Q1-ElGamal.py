from Crypto.Util.number import getPrime, inverse
import random


class ElGamal:
    def __init__(self, key_size):
        """Initialize the ElGamal encryption scheme with key generation."""
        # Step 1: Generate a large prime number `p` for the group
        self.p = getPrime(key_size)

        # Step 2: Choose a random generator `g` such that 1 < g < p-1
        self.g = random.randint(2, self.p - 1)

        # Step 3: Choose a private key `x` in the range [1, p-2]
        self.x = random.randint(1, self.p - 2)

        # Step 4: Compute the public key `h` using the private key
        self.h = pow(self.g, self.x, self.p)  # h = g^x mod p

        # Display keys for demonstration purposes
        print(f"Public Key (p, g, h): ({self.p}, {self.g}, {self.h})")
        print(f"Private Key (x): {self.x}")

    def encrypt(self, plaintext):
        """Encrypt an integer plaintext using the ElGamal encryption scheme."""
        # Step 1: Choose a random value `y` for encryption in the range [1, p-2]
        y = random.randint(1, self.p - 2)

        # Step 2: Compute the first part of the ciphertext
        c1 = pow(self.g, y, self.p)  # c1 = g^y mod p

        # Step 3: Compute the shared secret `s = h^y mod p`
        s = pow(self.h, y, self.p)

        # Step 4: Compute the second part of the ciphertext
        c2 = (plaintext * s) % self.p  # c2 = (plaintext * s) mod p

        return (c1, c2)  # Return the ciphertext as a tuple (c1, c2)

    def decrypt(self, c1, c2):
        """Decrypt the ciphertext (c1, c2) using the private key."""
        # Step 1: Compute the shared secret using `c1` and private key `x`
        s = pow(c1, self.x, self.p)  # s = c1^x mod p

        # Step 2: Compute the modular inverse of `s`
        s_inverse = inverse(s, self.p)  # s_inverse = s^(-1) mod p

        # Step 3: Recover the plaintext
        plaintext = (c2 * s_inverse) % self.p  # plaintext = (c2 * s_inverse) mod p

        return plaintext


# Example usage of ElGamal encryption
if __name__ == "__main__":
    # Initialize the ElGamal encryption scheme with a 256-bit key size
    key_size = 256
    elgamal = ElGamal(key_size)

    # Encrypt a sample message
    message = 12345  # Example integer message to be encrypted
    print(f"\nOriginal Plaintext: {message}")

    # Perform encryption
    ciphertext = elgamal.encrypt(message)
    print(f"Encrypted Ciphertext: {ciphertext}")

    # Perform decryption
    decrypted_message = elgamal.decrypt(*ciphertext)
    print(f"Decrypted Plaintext: {decrypted_message}")
