import hashlib
import random
import string
import time


# Function to generate a random string of a given length
def generate_random_string(length=32):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))


# Function to compute the hash and measure time
def compute_hash_and_time(hash_func, data):
    start_time = time.time()
    hash_value = hash_func(data.encode('utf-8')).hexdigest()
    end_time = time.time()
    return hash_value, (end_time - start_time)


# Function to check for collisions
def check_collisions(hash_list):
    seen_hashes = set()
    collisions = []
    for i, h in enumerate(hash_list):
        if h in seen_hashes:
            collisions.append(i)
        else:
            seen_hashes.add(h)
    return collisions


# Experiment: Generate random strings and compute MD5, SHA-1, SHA-256
def experiment(num_strings=100, string_length=32):
    random_strings = [generate_random_string(string_length) for _ in range(num_strings)]

    # Store hashes and timings for each algorithm
    md5_hashes = []
    sha1_hashes = []
    sha256_hashes = []

    md5_times = []
    sha1_times = []
    sha256_times = []

    for s in random_strings:
        # MD5
        md5_hash, md5_time = compute_hash_and_time(hashlib.md5, s)
        md5_hashes.append(md5_hash)
        md5_times.append(md5_time)

        # SHA-1
        sha1_hash, sha1_time = compute_hash_and_time(hashlib.sha1, s)
        sha1_hashes.append(sha1_hash)
        sha1_times.append(sha1_time)

        # SHA-256
        sha256_hash, sha256_time = compute_hash_and_time(hashlib.sha256, s)
        sha256_hashes.append(sha256_hash)
        sha256_times.append(sha256_time)

    # Measure total computation time
    md5_total_time = sum(md5_times)
    sha1_total_time = sum(sha1_times)
    sha256_total_time = sum(sha256_times)

    # Collision detection
    md5_collisions = check_collisions(md5_hashes)
    sha1_collisions = check_collisions(sha1_hashes)
    sha256_collisions = check_collisions(sha256_hashes)

    # Print results
    print(f"MD5: Total Time = {md5_total_time:.5f} seconds, Collisions = {len(md5_collisions)}")
    print(f"SHA-1: Total Time = {sha1_total_time:.5f} seconds, Collisions = {len(sha1_collisions)}")
    print(f"SHA-256: Total Time = {sha256_total_time:.5f} seconds, Collisions = {len(sha256_collisions)}")


# Run the experiment
experiment(num_strings=100, string_length=32)
