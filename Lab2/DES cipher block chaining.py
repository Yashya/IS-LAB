from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# DES requires an 8-byte key and an 8-byte IV
key = b'A1B2C3D4'  # 8-byte key
iv = b'12345678'   # 8-byte IV

# Message to encrypt
message = "Secure Communication".encode()

# DES uses a block size of 8 bytes
block_size = 8

# Create a DES cipher in CBC mode
cipher = DES.new(key, DES.MODE_CBC, iv)

# Encrypt the message
ciphertext = cipher.encrypt(pad(message, block_size))
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Decrypt the ciphertext
decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_message = unpad(decipher.decrypt(ciphertext), block_size)
print(f"Decrypted message: {decrypted_message.decode()}")
