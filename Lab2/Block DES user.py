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


def is_hexadecimal(s):
    """Check if the string is a valid hexadecimal number."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def main():
    # User input for DES key (must be 16 hex characters, which is 8 bytes)
    key_hex = input("Enter the DES key (16 hex characters): ")
    while not (is_hexadecimal(key_hex) and len(key_hex) == 16):
        print("Invalid key! The key must be 16 hexadecimal characters (0-9, A-F).")
        key_hex = input("Enter the DES key (16 hex characters): ").strip().upper()  # Uppercase for consistency
    key = bytes.fromhex(key_hex)

    # User input for data to be encrypted
    block1_hex = input("Enter the first block of data to encrypt (in hex): ")
    while not (is_hexadecimal(block1_hex) and len(block1_hex) % 2 == 0):
        print("Invalid block! The block must be a valid hexadecimal string.")
        block1_hex = input("Enter the first block of data to encrypt (in hex): ").strip()

    block2_hex = input("Enter the second block of data to encrypt (in hex): ")
    while not (is_hexadecimal(block2_hex) and len(block2_hex) % 2 == 0):
        print("Invalid block! The block must be a valid hexadecimal string.")
        block2_hex = input("Enter the second block of data to encrypt (in hex): ").strip()

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
    print(f"\nOriginal Block 1: {block1_hex}")
    print(f"Encrypted Block 1: {encrypted_block1.hex()}")
    print(f"Decrypted Block 1: {decrypted_block1.hex()}")

    print(f"\nOriginal Block 2: {block2_hex}")
    print(f"Encrypted Block 2: {encrypted_block2.hex()}")
    print(f"Decrypted Block 2: {decrypted_block2.hex()}")


if __name__ == "__main__":
    main()
