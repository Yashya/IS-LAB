from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


# Function to encrypt a block of data using DES
def encrypt_des(key, data):
    des = DES.new(key, DES.MODE_CBC)  # Using CBC mode
    padded_data = pad(data, DES.block_size)  # Pad data to be multiple of block size
    iv = des.iv  # Get the initialization vector
    ciphertext = des.encrypt(padded_data)  # Encrypt the padded data
    return iv + ciphertext  # Return IV + ciphertext for decryption later


# Function to decrypt a block of data using DES
def decrypt_des(key, ciphertext):
    iv = ciphertext[:DES.block_size]  # Extract the IV
    des = DES.new(key, DES.MODE_CBC, iv)  # Create a new DES cipher with the extracted IV
    decrypted_data = des.decrypt(ciphertext[DES.block_size:])  # Decrypt the ciphertext
    return unpad(decrypted_data, DES.block_size)  # Unpad the decrypted data


def main():
    # DES key (must be 16 hex characters, which is 8 bytes)
    key_hex = "A1B2C3D4E5F60708"
    key = bytes.fromhex(key_hex)

    # Data to be encrypted
    block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"  # "Mathematica"
    block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"  # "And this is the second block"

    # Convert hexadecimal to bytes
    block1 = bytes.fromhex(block1_hex)
    block2 = bytes.fromhex(block2_hex)

    # Encrypt the blocks
    encrypted_block1 = encrypt_des(key, block1)
    encrypted_block2 = encrypt_des(key, block2)

    # Decrypt the blocks
    decrypted_block1 = decrypt_des(key, encrypted_block1)
    decrypted_block2 = decrypt_des(key, encrypted_block2)

    # Output the results
    print(f"Original Block 1: {block1_hex}")
    print(f"Encrypted Block 1: {encrypted_block1.hex()}")
    print(f"Decrypted Block 1: {decrypted_block1.hex()}")

    print(f"\nOriginal Block 2: {block2_hex}")
    print(f"Encrypted Block 2: {encrypted_block2.hex()}")
    print(f"Decrypted Block 2: {decrypted_block2.hex()}")


if __name__ == "__main__":
    main()
