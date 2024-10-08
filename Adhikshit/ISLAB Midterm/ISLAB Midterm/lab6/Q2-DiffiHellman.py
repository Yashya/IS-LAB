import random
from Crypto.Util.number import getPrime

class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)

# Common parameters: Prime p and base g
key_size = 256
p = getPrime(key_size)
g = random.randint(2, p - 1)  # Shared base

# Create Alice and Bob with the same p and g values
alice = DiffieHellman(p, g)
bob = DiffieHellman(p, g)

# Exchange public keys and generate shared keys
alice_shared_key = alice.generate_shared_key(bob.public_key)
bob_shared_key = bob.generate_shared_key(alice.public_key)

print(f"Alice's public key: {alice.public_key}")
print(f"Bob's public key: {bob.public_key}")
print(f"Alice's shared key: {alice_shared_key}")
print(f"Bob's shared key: {bob_shared_key}")
print(f"Keys match: {alice_shared_key == bob_shared_key}")
