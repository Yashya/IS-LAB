from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Fixed AES-256 key (64-character hexadecimal key)
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

# Get user input for the message
message = input("Enter the message to encrypt: ").encode()

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
