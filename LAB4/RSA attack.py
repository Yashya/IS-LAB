import sympy  # For generating small prime numbers
from Crypto.Util.number import inverse


def generate_vulnerable_rsa_keypair(bit_length=8):
    # Generate two small primes (for demonstration purposes)
    p = sympy.prime(3)  # Small prime number 5
    q = sympy.prime(4)  # Small prime number 7
    n = p * q
    e = 3  # Small public exponent for simplicity

    # Calculate φ(n)
    phi_n = (p - 1) * (q - 1)

    # Ensure e is coprime to φ(n)
    while sympy.gcd(e, phi_n) != 1:
        e += 1  # Increment e until it is coprime with φ(n)

    # Calculate private key d
    d = inverse(e, phi_n)

    return (n, e), (n, d), p, q


def recover_private_key(n, e):
    # Factor the modulus n to find p and q
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            p = i
            q = n // i
            return p, q
    return None, None


def main():
    # Generate a vulnerable RSA key pair
    public_key, private_key, p, q = generate_vulnerable_rsa_keypair()

    print(f"Public Key (n, e): {public_key}")
    print(f"Private Key (n, d): {private_key}")
    print(f"Original primes (p, q): {p}, {q}")

    # Simulate Eve's attack
    n = public_key[0]
    recovered_p, recovered_q = recover_private_key(n, public_key[1])

    if recovered_p and recovered_q:
        print(f"Recovered primes (p, q): {recovered_p}, {recovered_q}")
        # Calculate private key d using recovered primes
        phi_n = (recovered_p - 1) * (recovered_q - 1)
        d = inverse(public_key[1], phi_n)
        print(f"Recovered Private Key (n, d): ({n}, {d})")
    else:
        print("Failed to recover the primes.")


if __name__ == "__main__":
    main()
