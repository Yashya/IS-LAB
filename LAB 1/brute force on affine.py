def mod_inverse(a, m):
    # Function to find the modular inverse of a under modulo m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # Return None if no inverse is found


def affine_decrypt(ciphertext, a, b):
    # Decrypt the ciphertext using the affine cipher formula
    m = 26
    a_inv = mod_inverse(a, m)

    if a_inv is None:  # Check if a_inv is None
        return None  # No valid decryption if no inverse

    plaintext = ""

    for char in ciphertext:
        if char.isalpha():
            # Convert character to number (A=0, ..., Z=25)
            C = ord(char.upper()) - ord('A')
            # Apply the decryption formula
            P = (a_inv * (C - b)) % m
            # Convert back to character
            plaintext += chr(P + ord('a'))
        else:
            plaintext += char  # Keep spaces and other characters as is

    return plaintext


def brute_force_affine(ciphertext):
    # Iterate through all possible values of a (1-25) and b (0-25)
    for a in range(1, 26):
        if gcd(a, 26) != 1:  # Check if a is coprime with 26
            continue
        for b in range(26):
            decrypted_message = affine_decrypt(ciphertext, a, b)
            # Print all decrypted messages for review
            print(f"Key (a={a}, b={b}): Decrypted Message: {decrypted_message}")
            if decrypted_message.startswith("ab"):
                print(f"**Valid Key Found**: (a={a}, b={b}): Decrypted Message: {decrypted_message}")


def gcd(x, y):
    # Function to compute the greatest common divisor
    while y:
        x, y = y, x % y
    return x


# Ciphertext provided
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Run the brute-force attack
brute_force_affine(ciphertext)
