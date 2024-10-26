import random
import time

def print_random_time():
    # Generate a random time in seconds (e.g., between 0.1 and 2 seconds)
    time_taken = random.uniform(0.1, 2.0)
    time.sleep(time_taken)  # Simulate time taken for encryption
    print(f"Time taken for encryption: {time_taken:.2f} seconds")

# Call the function to see the output
print_random_time()
