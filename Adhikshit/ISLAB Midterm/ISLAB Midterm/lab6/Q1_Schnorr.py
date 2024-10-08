from Crypto.Util.number import getPrime, inverse
import random
from hashlib import sha256

class Schnorr:
    def __init__(self, key_size):
        # Generate prime p and generator g
        self.p = getPrime(key_size)
        self.q = getPrime(key_size - 1)  # Smaller prime q
        self.g = pow(2, (self.p - 1) // self.q, self.p)

        # Private key x
        self.x = random.randint(1, self.q - 1)

        # Public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

    def sign(self, message):
        k = random.randint(1, self.q - 1)  # Random value k
        r = pow(self.g, k, self.p)  # Calculate r = g^k mod p
        e = int(sha256((str(r) + message).encode()).hexdigest(), 16) % self.q  # Hash to obtain e
        s = (k - e * self.x) % self.q  # Corrected calculation for s
        return (r, s)

    def verify(self, message, r, s):
        e = int(sha256((str(r) + message).encode()).hexdigest(), 16) % self.q
        lhs = pow(self.g, s, self.p)
        rhs = (r * pow(self.y, e, self.p)) % self.p
        return lhs == rhs

# Example usage
schnorr = Schnorr(256)
message = "test message"

# Signing
signature = schnorr.sign(message)
print(f"Signature: {signature}")

# Verifying
is_valid = schnorr.verify(message, *signature)
print(f"Signature valid: {is_valid}")
