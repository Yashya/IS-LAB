from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

# Message for encryption
message = "Performance Testing of Encryption Algorithms"

# Padding function to ensure message is compatible with block size
def pad(text, block_size):
    while len(text) % block_size != 0:
        text += ' '
    return text

# DES Setup
des_key = b'8bytekey'  # DES key must be 8 bytes
des_cipher = DES.new(des_key, DES.MODE_ECB)
padded_message_des = pad(message, DES.block_size).encode('utf-8')  # Pad and encode

# AES-256 Setup

aes_key = b'ThisIsA32ByteLongSecretKeyForAES'
# AES-256 key must be 32 bytes
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
padded_message_aes = pad(message, AES.block_size).encode('utf-8')  # Pad and encode

# DES Encryption and Decryption Time
start_time = time.time()
des_encrypted = des_cipher.encrypt(padded_message_des)
end_time = time.time()
des_encryption_time = end_time - start_time

start_time = time.time()
des_decrypted = des_cipher.decrypt(des_encrypted)
end_time = time.time()
des_decryption_time = end_time - start_time

# AES Encryption and Decryption Time
start_time = time.time()
aes_encrypted = aes_cipher.encrypt(padded_message_aes)
end_time = time.time()
aes_encryption_time = end_time - start_time

start_time = time.time()
aes_decrypted = aes_cipher.decrypt(aes_encrypted)
end_time = time.time()
aes_decryption_time = end_time - start_time

# Print the results
print(f"DES Encryption Time: {des_encryption_time:.8f} seconds")
print(f"DES Decryption Time: {des_decryption_time:.8f} seconds")
print(f"AES Encryption Time: {aes_encryption_time:.8f} seconds")
print(f"AES Decryption Time: {aes_decryption_time:.8f} seconds")
