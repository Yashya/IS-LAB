import hashlib
import time

# Step 1: Define two sample strings for hashing
string1 = "This is the first test string."
string2 = "This is the second test string."


# Function to compute hash and measure time taken
def compute_hash(algorithm, input_string):
    """Compute the hash value and return the hash and time taken"""
    hasher = hashlib.new(algorithm)
    start_time = time.time()
    hasher.update(input_string.encode('utf-8'))
    hash_value = hasher.hexdigest()
    time_taken = time.time() - start_time
    return hash_value, time_taken


# List of hash algorithms to test
hash_algorithms = ['md5', 'sha1', 'sha256']

# Compute hashes and print results immediately for each algorithm
for algo in hash_algorithms:
    # Calculate hash and time for both strings using the current algorithm
    hash1, time1 = compute_hash(algo, string1)
    hash2, time2 = compute_hash(algo, string2)

    # Print the results for the current algorithm immediately
    print(f"\n--- {algo.upper()} Results ---")
    print(f"String 1 Hash: {hash1}")
    print(f"String 2 Hash: {hash2}")
    print(f"String 1 Time: {time1:.6f} seconds")
    print(f"String 2 Time: {time2:.6f} seconds")
    print(f"Collision Detected: {hash1 == hash2}")
