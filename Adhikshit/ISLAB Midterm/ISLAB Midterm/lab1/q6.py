import string

# Function to convert letters to numbers
def letter_to_number(letter):
    return ord(letter) - ord('a')

# Function to convert numbers back to letters
def number_to_letter(number):
    return chr(number + ord('a'))

# Given encryption and decryption functions
def encrypt(pt, k1, k2):
    pt = pt.replace(" ", "").lower()
    if k1 == 13 or k1 % 2 == 0:
        print("Invalid choice for K1, try again\n")
        return None
    ct = ""
    for char in pt:
        if char in string.ascii_lowercase:  # Only process alphabetic characters
            c = (((ord(char) - ord('a')) * k1) + k2) % 26
            ct += chr(c + ord('a'))
    return ct

def decrypt(ct, k1, k2):
    try:
        kin = pow(k1, -1, 26)  # Calculate multiplicative inverse of k1 under modulo 26
    except ValueError:
        return None  # If no multiplicative inverse exists, return None
    pt = ""
    for char in ct:
        if char in string.ascii_lowercase:  # Only process alphabetic characters
            p = (((ord(char) - ord('a')) - k2) * kin) % 26
            pt += chr(p + ord('a'))
    return pt

# Known mappings from problem statement
plaintext = "ab"
ciphertext = "gl"

# Brute-force search for k1 and k2
for k1 in range(1, 26):
    if k1 % 2 != 0 and k1 != 13:  # Ensure k1 is coprime with 26
        for k2 in range(0, 26):
            # Encrypt the plaintext "ab" with current k1 and k2
            encrypted = encrypt(plaintext, k1, k2)
            if encrypted and encrypted == ciphertext.lower():
                print(f"Found keys! k1 = {k1}, k2 = {k2}")
                break

# Decrypt the given message with found keys
ciphertext_given = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS".lower()
k1 = 5  # From the result above
k2 = 6  # From the result above
plaintext_decrypted = decrypt(ciphertext_given, k1, k2)
print(f"Decrypted message: {plaintext_decrypted.upper()}")
