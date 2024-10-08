from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to convert a string key into bytes (hexadecimal)
def get_key():
    key = input("Enter a 64-character hexadecimal key (AES-256 requires 32 bytes, i.e., 64 hex characters): ")
    if len(key) != 64:
        raise ValueError("The key must be exactly 64 characters long.")
    return bytes.fromhex(key)

# Get user input for the message and key
message = input("Enter the message to encrypt: ").encode()
key = get_key()

# AES-256 requires a block size of 16 bytes
block_size = 16

# Create AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt the message
ciphertext = cipher.encrypt(pad(message, block_size))
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Decrypt the ciphertext
decrypted_message = unpad(cipher.decrypt(ciphertext), block_size)
print(f"Decrypted message: {decrypted_message.decode()}")
