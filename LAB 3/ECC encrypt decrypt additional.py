from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize the keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()  # Use NoEncryption for simplicity
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Message to encrypt
message = b"Secure Transactions"


# Encrypt the message using the public key
def encrypt(public_key, message):
    # Generate a shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key from the shared secret
    key = hashes.Hash(hashes.SHA256())
    key.update(shared_secret)
    symmetric_key = key.finalize()[:16]  # Use the first 16 bytes for AES

    # Encrypt the message using AES
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher = AES.new(symmetric_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = iv + cipher.encrypt(pad(message, AES.block_size))

    return ciphertext


# Decrypt the message using the private key
def decrypt(private_key, ciphertext):
    # Extract the IV
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Generate a shared secret again using the public key
    public_key = private_key.public_key()
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive the symmetric key from the shared secret
    key = hashes.Hash(hashes.SHA256())
    key.update(shared_secret)
    symmetric_key = key.finalize()[:16]  # Use the first 16 bytes for AES

    # Decrypt the message using AES
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return decrypted_message


# Encrypt the message
ciphertext = encrypt(public_key, message)
print(f"Ciphertext: {ciphertext}")

# Decrypt the message
decrypted_message = decrypt(private_key, ciphertext)
print(f"Decrypted Message: {decrypted_message.decode()}")

# Verify the original message
if decrypted_message == message:
    print("Decryption Successful! Original message verified.")
else:
    print("Decryption Failed! Original message does not match.")
