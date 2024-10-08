from random import randint

# ElGamal parameters
p = 7919  # large prime number
g = 2     # generator
h = 6465  # public key h = g^x mod p
x = 2999  # private key

# Function to compute modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Encryption function
def elgamal_encrypt(p, g, h, message):
    encrypted_message = []
    for char in message:
        m = ord(char)  # Convert character to ASCII
        y = randint(1, p-2)  # Random y
        c1 = mod_exp(g, y, p)
        s = mod_exp(h, y, p)  # Shared secret
        c2 = (m * s) % p
        encrypted_message.append((c1, c2))
    return encrypted_message

# Decryption function
def elgamal_decrypt(p, x, ciphertext):
    decrypted_message = ''
    for c1, c2 in ciphertext:
        s = mod_exp(c1, x, p)  # Shared secret
        s_inv = mod_exp(s, p-2, p)  # Modular inverse of s
        m = (c2 * s_inv) % p
        decrypted_message += chr(m)
    return decrypted_message

# Message to encrypt
message = "Asymmetric Algorithms"

# Encrypt the message
ciphertext = elgamal_encrypt(p, g, h, message)
print("Ciphertext:", ciphertext)

# Decrypt the message
decrypted_message = elgamal_decrypt(p, x, ciphertext)
print("Decrypted message:", decrypted_message)
