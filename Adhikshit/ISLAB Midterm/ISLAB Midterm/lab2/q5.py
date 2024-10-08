from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Given message and corrected 24-byte AES-192 key
message = "Top Secret Data"
key = b"1234567890ABCDEF12345678"  # 24-byte key for AES-192

# Ensure the key length is exactly 24 bytes for AES-192
assert len(key) == 24, "AES-192 key must be exactly 24 bytes long."

# Create AES-192 cipher object in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt the message
padded_message = pad(message.encode('utf-8'), AES.block_size)  # Pad to match block size
ciphertext = cipher.encrypt(padded_message)
print(f"Encrypted Ciphertext: {ciphertext.hex()}")

# Decrypt the message to verify
decrypted_padded_message = cipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded_message, AES.block_size).decode('utf-8')
print(f"Decrypted Message: {decrypted_message}")
