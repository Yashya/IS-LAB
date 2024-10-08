def additive_decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():  # Check if the character is a letter
            # Convert character to number (A=0, ..., Z=25)
            offset = ord('A') if char.isupper() else ord('a')
            C = ord(char) - offset
            # Decrypt the character using the additive cipher formula
            P = (C - key) % 26
            # Convert back to character
            plaintext += chr(P + offset)
        else:
            plaintext += char  # Keep non-alphabet characters as is
    return plaintext


def brute_force_additive(ciphertext):
    # Assume key is around Alice's birthday (13), so we'll try keys from 1 to 12 and 14 to 25
    keys_to_try = list(range(1, 13)) + list(range(14, 26))

    for key in keys_to_try:
        decrypted_message = additive_decrypt(ciphertext, key)
        print(f"Key {key}: Decrypted Message: {decrypted_message}")


# Main function to take user input and run the brute-force attack
def main():
    ciphertext = input("Enter the ciphertext to decrypt: ").strip()
    brute_force_additive(ciphertext)


# Run the main function
if __name__ == "__main__":
    main()
