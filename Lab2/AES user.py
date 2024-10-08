from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii


def aes_encrypt(plaintext, key):
    # Create an AES cipher object with the provided key
    aes = AES.new(key.encode('utf-8'), AES.MODE_CBC)

    # Pad the plaintext to make sure it's a multiple of the block size (16 bytes)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = aes.encrypt(padded_plaintext)

    # Return the IV and the ciphertext in hexadecimal format
    return aes.iv.hex(), binascii.hexlify(ciphertext).decode('utf-8')


def aes_decrypt(ciphertext, key, iv):
    # Create an AES cipher object with the same IV used for encryption
    aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, bytes.fromhex(iv))

    # Decrypt the ciphertext
    decrypted_padded_plaintext = aes.decrypt(binascii.unhexlify(ciphertext))

    # Unpad the plaintext
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size).decode('utf-8')

    return decrypted_plaintext


# Main function to take user input and run encryption and decryption
def main():
    key = input("Enter a 16-byte key for AES-128: ").strip()

    # Ensure the key is 16 bytes long
    if len(key) != 16:
        print("Key must be exactly 16 characters long.")
        return

    plaintext = input("Enter the plaintext to encrypt: ").strip()

    # Encrypt the plaintext
    iv, ciphertext = aes_encrypt(plaintext, key)
    print(f"IV: {iv}")
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_plaintext = aes_decrypt(ciphertext, key, iv)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")


# Run the main function
if __name__ == "__main__":
    main()
