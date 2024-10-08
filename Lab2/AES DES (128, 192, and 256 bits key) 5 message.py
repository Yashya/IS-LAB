from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import os

# Function to encrypt a message with DES
def encrypt_des(key, message):
    des = DES.new(key, DES.MODE_CBC)  # Using CBC mode
    ciphertext = des.encrypt(pad(message.encode(), DES.block_size))
    return des.iv + ciphertext  # Prepend IV to ciphertext for later decryption

# Function to encrypt a message with AES
def encrypt_aes(key, message):
    aes = AES.new(key, AES.MODE_CBC)  # Using CBC mode
    ciphertext = aes.encrypt(pad(message.encode(), AES.block_size))
    return aes.iv + ciphertext  # Prepend IV to ciphertext for later decryption

# Messages to encrypt
messages = [
    "Hello, World!",
    "This is a test message.",
    "AES and DES encryption example.",
    "Python is great for cryptography.",
    "Keep your secrets safe!"
]

# Key generation (DES requires 8 bytes key, AES requires 16, 24, or 32 bytes key)
des_key = os.urandom(8)  # Random 8 bytes key for DES
aes_key_128 = os.urandom(16)  # 128 bits (16 bytes) key for AES
aes_key_192 = os.urandom(24)  # 192 bits (24 bytes) key for AES
aes_key_256 = os.urandom(32)  # 256 bits (32 bytes) key for AES

# Encrypting messages
encrypted_messages = {}
for msg in messages:
    encrypted_messages[msg] = {
        "DES": encrypt_des(des_key, msg),
        "AES-128": encrypt_aes(aes_key_128, msg),
        "AES-192": encrypt_aes(aes_key_192, msg),
        "AES-256": encrypt_aes(aes_key_256, msg)
    }

# Output the encrypted messages in hex format for readability
for msg, enc in encrypted_messages.items():
    print(f"Original: {msg}")
    print(f"DES: {enc['DES'].hex()}")
    print(f"AES-128: {enc['AES-128'].hex()}")
    print(f"AES-192: {enc['AES-192'].hex()}")
    print(f"AES-256: {enc['AES-256'].hex()}")
    print()
