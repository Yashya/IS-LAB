def custom_hash(input_string):
    # Initialize the hash value
    hash_value = 5381

    # Process each character in the input string
    for char in input_string:
        # Multiply the current hash value by 33 and XOR with the ASCII value of the character
        hash_value = (hash_value * 33) ^ ord(char)

    # Ensure the hash value is within a 32-bit range
    hash_value &= 0xFFFFFFFF  # Apply a mask to keep it within 32 bits

    return hash_value

# Main function to get user input and display the hash value
if __name__ == "__main__":
    user_input = input("Enter a string to hash: ")
    hash_result = custom_hash(user_input)
    print(f"Hash value for '{user_input}': {hash_result}")
