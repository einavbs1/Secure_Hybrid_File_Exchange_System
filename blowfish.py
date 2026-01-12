import struct
# Import constants from the created file
from blowfish_constants import P_ARRAY, S_BOXES

class Blowfish:
    def __init__(self, key):
        # Copy constants to the current instance (to avoid modifying the source)
        self.p_array = list(P_ARRAY)
        self.s_boxes = [list(box) for box in S_BOXES]
        self._key_expansion(key)

    # --- Mathematical Core Function (F-Function) ---
    def _f(self, x):
        # Split x into four 8-bit parts
        h = (x >> 24) & 0xFF
        i = (x >> 16) & 0xFF
        j = (x >> 8) & 0xFF
        k = x & 0xFF
        
        # Calculate according to Blowfish formula with 32-bit limit
        y = (self.s_boxes[0][h] + self.s_boxes[1][i]) % 2**32
        y = (y ^ self.s_boxes[2][j])
        y = (y + self.s_boxes[3][k]) % 2**32
        return y

    # --- Encrypt a single block (64 bits) ---
    def _encrypt_block(self, left, right):
        # Feistel 16 rounds
        for i in range(16):
            left = left ^ self.p_array[i]
            right = right ^ self._f(left)
            # Swap sides
            left, right = right, left
        
        # Undo last swap
        left, right = right, left
        
        right = right ^ self.p_array[16]
        left = left ^ self.p_array[17]
        
        return left, right


    # --- Key Initialization (mixing with Pi digits) ---
    def _key_expansion(self, key):
        if isinstance(key, str):
            key = key.encode()
            
        key_len = len(key)
        data = 0
        j = 0
        
        # Step 1: XOR the key with the P-array
        for i in range(18):
            data = 0
            for k in range(4):
                data = ((data << 8) | key[j]) 
                j = (j + 1) % key_len
            self.p_array[i] = self.p_array[i] ^ data

        # Step 2: Encrypt P and S arrays using the mixed key
        left, right = 0, 0
        for i in range(0, 18, 2):
            left, right = self._encrypt_block(left, right)
            self.p_array[i] = left
            self.p_array[i + 1] = right

        for i in range(4):
            for k in range(0, 256, 2):
                left, right = self._encrypt_block(left, right)
                self.s_boxes[i][k] = left
                self.s_boxes[i][k + 1] = right

    # --- Helper functions for direct number encryption ---
    def encrypt_ecb(self, data_bytes):
        # Split 8 bytes into two 32-bit integers
        left = int.from_bytes(data_bytes[:4], 'big')
        right = int.from_bytes(data_bytes[4:], 'big')
        
        l, r = self._encrypt_block(left, right)
        
        return l.to_bytes(4, 'big') + r.to_bytes(4, 'big')




# --- CFB Mode Implementation (as required by the project) ---
class BlowfishCFB:
    def __init__(self, key, iv):
        self.bf = Blowfish(key) # Create Blowfish instance
        self.iv = iv  # Initialization Vector (8 bytes)

    def encrypt(self, plaintext):
        # Ensure plaintext is bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
            
        ciphertext = bytearray()
        # Start with the IV
        prev_block = self.iv
        
        # Iterate byte by byte
        for byte in plaintext:
            # Encrypt the previous block (starts with the IV)
            enc_block = self.bf.encrypt_ecb(prev_block)
            
            # Take only the first byte of the result and XOR with the data
            cipher_byte = byte ^ enc_block[0]
            ciphertext.append(cipher_byte)

            # CFB Feedback: Output (ciphertext) goes to next block
            # Shift the window: drop the first byte, add the encrypted byte to the end
            # This creates the "Stream"
            prev_block = prev_block[1:] + bytes([cipher_byte])
            
        return bytes(ciphertext)


    def decrypt(self, ciphertext):
        plaintext = bytearray()
        prev_block = self.iv
        
        for byte in ciphertext:
            # In CFB decryption, we *encrypt* the previous block to recover the key
            enc_block = self.bf.encrypt_ecb(prev_block)
            
            # XOR to recover original data
            plain_byte = byte ^ enc_block[0]
            plaintext.append(plain_byte)
            
            # CFB Feedback: Input (ciphertext) goes to next block
            # Update the next block using the ciphertext (exactly like in encryption)
            prev_block = prev_block[1:] + bytes([byte])
            
        return bytes(plaintext)

# --- Quick Test ---
if __name__ == "__main__":
    # Secret Key
    key = b"SecretKey123"
    # Initialization Vector (must be 8 characters/bytes)
    iv = b"12345678" 
    
    cipher = BlowfishCFB(key, iv)
    
    msg = "Hello World! This is a secure message."
    print(f"Original: {msg}")
    
    encrypted = cipher.encrypt(msg)
    print(f"Encrypted (Hex): {encrypted.hex()}")
    
    decrypted_cipher = BlowfishCFB(key, iv)
    decrypted = decrypted_cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")