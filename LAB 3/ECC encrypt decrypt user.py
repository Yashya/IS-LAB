from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Simulate another party's ECC key pair for demonstration
other_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
other_public_key = other_private_key.public_key()

# Get user input for the message
message = input("Enter the message to encrypt: ").encode()

# Generate shared secret using ECDH
shared_secret = private_key.exchange(ec.ECDH(), other_public_key)

# Derive a symmetric key from the shared secret
symmetric_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
symmetric_key.update(shared_secret)
symmetric_key = symmetric_key.finalize()

# Encrypt the message using AES
iv = os.urandom(16)  # Initialization vector
cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = iv + encryptor.update(message) + encryptor.finalize()

print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Decrypt the ciphertext using the same symmetric key
cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(ciphertext[:16]), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()

print(f"Decrypted message: {decrypted_message.decode()}")
