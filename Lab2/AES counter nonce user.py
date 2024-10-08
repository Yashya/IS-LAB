from Crypto.Cipher import AES
from Crypto.Util import Counter

# Function to convert a hexadecimal key and nonce into bytes
def get_input_hex(prompt):
    while True:
        value = input(prompt)
        try:
            # Convert hex string to bytes
            return bytes.fromhex(value)
        except ValueError:
            print("Invalid input. Please enter a valid hexadecimal string.")

# Get user input for the key (must be 64 characters for AES-256)
key = get_input_hex("Enter a 64-character hexadecimal key (AES-256 requires 32 bytes): ")
if len(key) != 32:
    raise ValueError("The key must be exactly 64 hex characters (32 bytes) long.")

# Get user input for the nonce (must be 16 characters)
nonce = get_input_hex("Enter a 16-character hexadecimal nonce: ")
if len(nonce) != 8:
    raise ValueError("The nonce must be exactly 16 hex characters (8 bytes) long.")

# Get user input for the message
message = input("Enter the message to encrypt: ").encode()

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
