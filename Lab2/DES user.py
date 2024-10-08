from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii


def des_encrypt(plaintext, key):
    # Create a DES cipher object
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC)

    # Pad the plaintext to make sure it's a multiple of the block size (8 bytes)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)

    # Encrypt the padded plaintext
    ciphertext = des.encrypt(padded_plaintext)

    # Return the IV and the ciphertext in hexadecimal format
    return des.iv.hex(), binascii.hexlify(ciphertext).decode('utf-8')


def des_decrypt(ciphertext, key, iv):
    # Create a DES cipher object with the same IV used for encryption
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC, bytes.fromhex(iv))

    # Decrypt the ciphertext
    decrypted_padded_plaintext = des.decrypt(binascii.unhexlify(ciphertext))

    # Unpad the plaintext
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size).decode('utf-8')

    return decrypted_plaintext


# Main function to take user input and run encryption and decryption
def main():
    key = input("Enter a key (8 characters long): ").strip()

    # Ensure the key is 8 characters long
    if len(key) != 8:
        print("Key must be exactly 8 characters long.")
        return

    plaintext = input("Enter the plaintext to encrypt: ").strip()

    # Encrypt the plaintext
    iv, ciphertext = des_encrypt(plaintext, key)
    print(f"IV: {iv}")
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_plaintext = des_decrypt(ciphertext, key, iv)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")


# Run the main function
if __name__ == "__main__":
    main()
