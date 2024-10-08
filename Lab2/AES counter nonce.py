from Crypto.Cipher import AES
from Crypto.Util import Counter

# Fixed AES-256 key (64-character hexadecimal key)
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
nonce = b'\x00' * 8  # Nonce of 8 bytes
message = "Cryptography Lab Exercise".encode()

# Create a counter with the nonce
ctr = Counter.new(64, prefix=nonce)

# Create AES cipher in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

# Encrypt the message
ciphertext = cipher.encrypt(message)
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Decrypt the ciphertext (using the same counter)
decipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
decrypted_message = decipher.decrypt(ciphertext)
print(f"Decrypted message: {decrypted_message.decode()}")
