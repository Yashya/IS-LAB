from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

# ----------------------------------------
# Key Generation Section
# ----------------------------------------

# Generate a large prime number p
p = getPrime(256)

# Choose a random generator g in the range [2, p-1]
g = random.randint(2, p - 1)

# Choose a random private key x in the range [1, p-2]
x = random.randint(1, p - 2)

# Calculate the public key h as g^x mod p
h = pow(g, x, p)

# Print the generated keys
print("p (prime):", p)
print("g (generator):", g)
print("h (public key):", h)
print("x (private key):", x)

# ----------------------------------------
# Message Encryption Section
# ----------------------------------------

# Define the message to be encrypted
message = b"Confidential Data"

# Choose a random ephemeral key k in the range [1, p-2]
k = random.randint(1, p - 2)

# Calculate c1 as g^k mod p (part of the ciphertext)
c1 = pow(g, k, p)

# Convert the message to an integer
m = bytes_to_long(message)

# Calculate c2 as (m * h^k) mod p (second part of the ciphertext)
c2 = (m * pow(h, k, p)) % p

# Print the ciphertext components
print("c1:", c1)
print("c2:", c2)

# ----------------------------------------
# Message Decryption Section
# ----------------------------------------

# Calculate the shared secret s as c1^x mod p
s = pow(c1, x, p)

# Calculate the modular inverse of s
s_inv = inverse(s, p)

# Decrypt the message by calculating m_decrypted
m_decrypted = (c2 * s_inv) % p

# Convert the decrypted integer back to bytes
decrypted_message = long_to_bytes(m_decrypted)

# Print the decrypted message
print("Decrypted message:", decrypted_message.decode())
