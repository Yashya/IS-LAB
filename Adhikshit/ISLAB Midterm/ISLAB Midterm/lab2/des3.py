from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Correct message and 3DES key
message = "Classified Text"
key = b"12345678ABCDEFGH12345678"  # 24 bytes = 192 bits, correct for three-key 3DES

# Ensure the key length is exactly 24 bytes for Triple DES
assert len(key) == 24, "Triple DES key must be exactly 24 bytes long."

# Create a Triple DES cipher object in ECB mode
cipher = DES3.new(key, DES3.MODE_ECB)

# Encrypt the message
padded_message = pad(message.encode('utf-8'), DES3.block_size)  # Pad to match the block size
ciphertext = cipher.encrypt(padded_message)
print(f"Encrypted Ciphertext: {ciphertext.hex()}")

# Decrypt the message to verify
decrypted_padded_message = cipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded_message, DES3.block_size).decode('utf-8')
print(f"Decrypted Message: {decrypted_message}")
