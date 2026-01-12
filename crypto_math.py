import random

# --- Miller-Rabin Primality Test ---
# Probabilistic algorithm to check if a number is prime.
# Used to generate large prime numbers for keys.
def is_prime(n, k=40):
    if n == 2 or n == 3: return True
    if n % 2 == 0 or n < 2: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# --- Prime Number Generator ---
# Generates a large prime number of 'bits' size.
# Ensures the prime p satisfies p = 3 mod 4 (Blum Integer condition),
# which is required for efficient Rabin decryption/signing.
def generate_prime(bits):
    while True:
        # Generate a random odd number
        p = random.getrandbits(bits)
        if p % 2 == 0: 
            p += 1
        
        # Check condition p % 4 == 3 and primality
        if p % 4 == 3 and is_prime(p):
            return p

# --- Extended Euclidean Algorithm ---
# Finds coefficients x, y such that: ax + by = gcd(a, b)
# Essential for finding modular inverse and CRT.
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# --- Modular Inverse ---
# Finds d such that: (a * d) % m == 1
def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        # Inverse does not exist if numbers are not coprime
        return None 
    return (x % m + m) % m