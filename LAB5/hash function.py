def custom_hash(input_string):
    # Initialize the hash value
    hash_value = 5381

    # Process each character in the input string
    for char in input_string:
        # Multiply the current hash value by 33
        hash_value = (hash_value * 33) ^ ord(char)  # Use XOR for mixing bits

    # Ensure the hash value is within a 32-bit range
    hash_value &= 0xFFFFFFFF  # Apply a mask to keep it within 32 bits

    return hash_value

# Example usage
if __name__ == "__main__":
    test_string = "Hello, World!"
    hash_result = custom_hash(test_string)
    print(f"Hash value for '{test_string}': {hash_result}")
