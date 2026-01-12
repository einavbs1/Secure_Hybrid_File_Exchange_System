import hashlib
import random
# Import math tools from our helper file
from crypto_math import generate_prime, extended_gcd

class RabinSignature:
    """
    Static implementation of the Rabin Digital Signature Algorithm.
    No instance is needed; keys are passed directly to the functions.
    """

    # --- Key Generation (Static) ---
    @staticmethod
    def generate_keys(key_size=512):
        # Generate two large primes p, q where p, q = 3 mod 4
        # (The 3 mod 4 condition is handled inside generate_prime)
        p = generate_prime(key_size)
        q = generate_prime(key_size)
        
        # Public key n = p * q
        n = p * q
        
        # Return public key (n) and private key (tuple p, q)
        return n, (p, q)

    # --- Helper: Hash Data (Static) ---
    # Creates a numeric hash of the input message using SHA-256
    @staticmethod
    def _hash_data(data):
        if isinstance(data, str):
            data = data.encode()
        
        sha = hashlib.sha256()
        sha.update(data)
        # Convert hex digest to integer
        return int(sha.hexdigest(), 16)

    # --- Sign Message (Static) ---
    @staticmethod
    def sign(message, private_key):
        if not private_key:
            raise Exception("Private key is required!")
            
        p, q = private_key
        n = p * q
        
        # Step 1: Hash the message
        base_h = RabinSignature._hash_data(message)
        
        # Step 2: Find a square root
        # In Rabin, only 1/4 of numbers are quadratic residues (have a root).
        # We append a counter 'i' (padding) until we find a hash that has a root.
        i = 0
        while True:
            # Create candidate hash by appending i
            # Shift left by 64 bits to make room for the counter
            h_candidate = (base_h << 64) | i 
            h_val = h_candidate % n
            
            # Calculate roots modulo p and q
            # Using formula: root = val ^ ((p+1)/4) mod p
            # (This works because we chose p = 3 mod 4)
            mp = pow(h_val, (p + 1) // 4, p)
            mq = pow(h_val, (q + 1) // 4, q)
            
            # Verify that we actually found roots (check if squaring gives back the value)
            if pow(mp, 2, p) == (h_val % p) and pow(mq, 2, q) == (h_val % q):
                # Roots found! Now combine them using Chinese Remainder Theorem (CRT)
                # Find coefficients using Extended Euclidean Algorithm
                gcd, yp, yq = extended_gcd(p, q)
                
                # CRT Formula to find x (the signature)
                x = (yp * p * mq + yq * q * mp) % n
                
                # Return the signature (x) and the padding counter (i)
                # Both are needed for verification.
                return x, i
            
            i += 1
            if i > 1000000: # Safety break
                raise Exception("Failed to find signature root")

    # --- Verify Signature (Static) ---
    @staticmethod
    def verify(message, signature, padding_i, public_key_n):
        s = signature
        n = public_key_n
        
        # 1. Square the signature: s^2 mod n
        # This should result in the padded hash
        decrypted_hash = pow(s, 2, n)
        
        # 2. Reconstruct the expected hash from the message and padding
        base_h = RabinSignature._hash_data(message)
        expected_hash = ((base_h << 64) | padding_i) % n
        
        # 3. Compare
        # Note: Rabin has 4 possible roots. In this simplified scheme,
        # squaring yields the deterministic value, so direct comparison works.
        return decrypted_hash == expected_hash

# --- Test Block ---
if __name__ == "__main__":
    print("Generating Rabin keys (Static)...")
    # Call static method directly without creating an instance
    public_key, private_key = RabinSignature.generate_keys(key_size=256)
    print(f"Public Key (n): {public_key}")
    
    msg = "This is a secure message for the project."
    print(f"\nSigning message: '{msg}'")
    
    # Sign using the static method, passing the private key explicitly
    signature, pad = RabinSignature.sign(msg, private_key)
    print(f"Signature: {signature}")
    print(f"Padding used: {pad}")
    
    # Verify using the static method
    print("\nVerifying...")
    is_valid = RabinSignature.verify(msg, signature, pad, public_key)
    print(f"Is Valid? {is_valid}")
    
    # Tamper Test
    print("\nVerifying tampered message...")
    is_valid_fake = RabinSignature.verify("Hacked message", signature, pad, public_key)
    print(f"Is Valid? {is_valid_fake}")