import hashlib
import random
# Import helper for modular inverse from our toolkit
from crypto_math import mod_inverse

# --- Elliptic Curve Parameters (secp256k1) ---
# Standard parameters used in Bitcoin/Crypto.
# Curve Equation: y^2 = x^3 + 7 (mod p)
P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Base Point (Generator) G
G_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

class ECElGamalSystem:
    """
    Static implementation of Elliptic Curve ElGamal.
    Uses secp256k1 parameters (Bitcoin curve).
    No instance instantiation is required.
    """

    # --- EC Point Addition (Static) ---
    # Adds two points P and Q on the curve
    @staticmethod
    def _point_add(p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        # Case 1: P + (-P) = 0 (Point at Infinity)
        # If x coordinates are the same but y coordinates differ (Vertical line)
        if x1 == x2 and y1 != y2:
            return None

        # Case 2: P + P (Point Doubling)
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None
            
            # Calculate tangent slope: m = (3x^2 + a) / 2y
            # For secp256k1, a = 0, so numerator is just 3*x^2
            numerator = (3 * x1 * x1) % P_CURVE
            denominator = (2 * y1) % P_CURVE
            
            inv = mod_inverse(denominator, P_CURVE)
            if inv is None: return None # Safety check
            
            m = (numerator * inv) % P_CURVE

        # Case 3: P + Q (General Point Addition)
        else:
            # Calculate slope: m = (y1 - y2) / (x1 - x2)
            # Ensure modulo is applied to handle negative results properly
            numerator = (y1 - y2) % P_CURVE
            denominator = (x1 - x2) % P_CURVE
            
            inv = mod_inverse(denominator, P_CURVE)
            if inv is None: return None # Safety check
            
            m = (numerator * inv) % P_CURVE

        # Calculate new coordinates (x3, y3)
        x3 = (m * m - x1 - x2) % P_CURVE
        y3 = (m * (x1 - x3) - y1) % P_CURVE

        return (x3, y3)

    # --- Scalar Multiplication (Static) ---
    # Computes k * P using "Double and Add" algorithm
    # This is the basis of ECC security.
    @staticmethod
    def _scalar_mult(k, P):
        current = P
        result = None
        
        while k > 0:
            if k % 2 == 1:
                result = ECElGamalSystem._point_add(result, current)
            current = ECElGamalSystem._point_add(current, current) # Double
            k //= 2
            
        return result

    # --- Key Generation (Static) ---
    @staticmethod
    def generate_keys():
        # Private key: random integer d < n
        private_key = random.randrange(1, N_ORDER)
        
        # Public key: Point Q = d * G
        public_key = ECElGamalSystem._scalar_mult(private_key, G_POINT)
        
        return private_key, public_key

    # --- Encrypt Symmetric Key (Static) ---
    # Encrypts the Blowfish key using EC-ElGamal scheme
    @staticmethod
    def encrypt_key(public_key_Q, symmetric_key_bytes):
        # 1. Choose random k (ephemeral key)
        k = random.randrange(1, N_ORDER)
        
        # 2. Compute R = k * G (this is sent publicly)
        R = ECElGamalSystem._scalar_mult(k, G_POINT)
        
        # 3. Compute Shared Secret S = k * Q
        S = ECElGamalSystem._scalar_mult(k, public_key_Q)
        
        # 4. Derive a masking key from S (using SHA256 of the x-coordinate)
        # We use this mask to XOR the symmetric key (simulating One-Time Pad)
        shared_secret_bytes = str(S[0]).encode()
        masking_key = hashlib.sha256(shared_secret_bytes).digest()
        
        # 5. XOR the symmetric key with the mask
        encrypted_key_data = bytearray()
        # Ensure mask is long enough (repeat if necessary)
        for i in range(len(symmetric_key_bytes)):
            encrypted_key_data.append(symmetric_key_bytes[i] ^ masking_key[i % len(masking_key)])
            
        # Return tuple: (R_point, encrypted_bytes)
        return R, bytes(encrypted_key_data)

    # --- Decrypt Symmetric Key (Static) ---
    @staticmethod
    def decrypt_key(private_key_d, R_point, encrypted_key_bytes):
        # 1. Recover Shared Secret S = d * R
        # (Proof: d*R = d*(k*G) = k*(d*G) = k*Q = S)
        S = ECElGamalSystem._scalar_mult(private_key_d, R_point)
        
        # 2. Derive the same masking key
        shared_secret_bytes = str(S[0]).encode()
        masking_key = hashlib.sha256(shared_secret_bytes).digest()
        
        # 3. XOR again to decrypt
        decrypted_key = bytearray()
        for i in range(len(encrypted_key_bytes)):
            decrypted_key.append(encrypted_key_bytes[i] ^ masking_key[i % len(masking_key)])
            
        return bytes(decrypted_key)

# --- Test Block ---
if __name__ == "__main__":
    print("Initializing EC-ElGamal (Static)...")
    
    # 1. Receiver generates keys
    print("Generating keys...")
    # Direct static call
    privateKey, publicKey = ECElGamalSystem.generate_keys()
    print(f"Public Key (Q): {publicKey}")
    
    # 2. Sender encrypts a symmetric key (e.g., for Blowfish)
    original_key = b"SecretKey123" # This is the Blowfish key
    print(f"\nOriginal Key to send: {original_key}")
    
    # Direct static call
    R_point, enc_data = ECElGamalSystem.encrypt_key(publicKey, original_key)
    print(f"Encrypted Data: {enc_data.hex()}")
    
    # 3. Receiver decrypts
    # Direct static call
    decrypted_key = ECElGamalSystem.decrypt_key(privateKey, R_point, enc_data)
    print(f"Decrypted Key: {decrypted_key}")
    
    # Validation
    if original_key == decrypted_key:
        print("\nSUCCESS: Keys match!")
    else:
        print("\nERROR: Keys do not match.")