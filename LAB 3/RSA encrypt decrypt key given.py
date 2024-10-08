from Crypto.Util.number import bytes_to_long, long_to_bytes

# RSA Public Key
n = 323  # Modulus
e = 5  # Public exponent

# RSA Private Key
d = 173  # Private exponent


# Function to encrypt a message using RSA
def rsa_encrypt(message, n, e):
    ciphertext = []
    for char in message:
        message_int = ord(char)  # Convert character to its ASCII integer representation
        if message_int >= n:
            raise ValueError(f"Character '{char}' exceeds modulus n={n}.")
        encrypted_char = pow(message_int, e, n)  # Encrypt using the formula: c = m^e mod n
        ciphertext.append(encrypted_char)
    return ciphertext


# Function to decrypt a ciphertext using RSA
def rsa_decrypt(ciphertext, n, d):
    decrypted_message = ""
    for encrypted_char in ciphertext:
        decrypted_int = pow(encrypted_char, d, n)  # Decrypt using the formula: m = c^d mod n
        decrypted_message += chr(decrypted_int)  # Convert back to character
    return decrypted_message


def main():
    message = "Cryptographic Protocols"

    # Encrypt the message
    ciphertext = rsa_encrypt(message, n, e)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_message = rsa_decrypt(ciphertext, n, d)
    print(f"Decrypted Message: {decrypted_message}")

    # Verify the original message
    if decrypted_message == message:
        print("Decryption Successful! Original message verified.")
    else:
        print("Decryption Failed! Original message does not match.")


if __name__ == "__main__":
    main()
