import os
import json
import pickle
import hashlib
import time
from datetime import datetime

# --- Import our cryptographic modules ---
# Ensure ec_elgamal.py, blowfish.py, and rabin.py are in the same folder
from ec_elgamal import ECElGamalSystem
from blowfish import BlowfishCFB 
from rabin import RabinSignature

# --- Configuration ---
#Pepper for password hashing (additional security layer)
SYSTEM_PEPPER = "MySuperSecretPepper_DoNotShare_!@#2026"

# --- Constants for file storage ---
USERS_DB_FILE = "users_db.json"       # Simulates the public server database
#JSON Structure (Dictionary mapped by Username):
# {
#   "alice": {
#       "password_hash": "sha256_hex_string...",
#       "salt": "16_byte_hex_string...",
#       "public_keys": {
#           "rabin_n": int,       # Rabin Public Key (Large Integer n). Used to verify signatures.
#           "elgamal_q": [int_x, int_y]    # EC-ElGamal Public Key (Point Q). Used to encrypt session keys.
#       }

MESSAGES_DB_FILE = "messages_db.json" # Simulates the cloud/network message storage
# JSON Structure (List of Message Objects):
# [
#   {
#       "from": "alice",                         # Sender username
#       "to": "bob",                             # Recipient username
#       "filename": "secret_plans.pdf",          # Original filename
#       "timestamp": "2023-10-27 10:30:00",      # Time sent
#       "data": {
#           # Cryptographic components needed for decryption by the recipient:
#           "iv": "8_byte_hex_string",           # Initialization Vector used for Blowfish CFB
#
#           # The main content encrypted with Blowfish key.
#           # Contains: [File Data] + [64-byte Signature] + [4-byte Padding]
#           "encrypted_payload": "long_hex_string...",
#
#           # The symmetric session key (16 bytes), encrypted using Bob's ElGamal Public Key
#           "encrypted_session_key": "hex_string...",
#
#           # The ephemeral point R (k*G) generated during ElGamal encryption.
#           # Needed by Bob to derive the shared secret.
#           "elgamal_R_point": [int_x, int_y]
#       }

KEYS_DIR = "user_keys"                # Local secure storage for private keys
# Stores local, encrypted private key files for each user (e.g., "alice_keys.enc").

# WHAT is stored inside (once decrypted in RAM):
# [8-byte IV] + [Blowfish Encrypted Payload]
#
# A serialized Python dictionary containing the sensitive private keys:
# {
#   "rabin_priv": (int_p, int_q), # The two primes needed for signing.
#   "elgamal_priv": int_d         # The private scalar needed for decryption.
# }

DOWNLOADS_DIR = "downloads"           # Directory for received files

# ==========================================
#         System Management Class
# ==========================================
class SecureSystem:
    def __init__(self):
        self._init_storage()
        self.current_user = None
        self.current_user_keys = None # Holds private keys in memory after login

    def _init_storage(self):
        """Create files and directories if they don't exist"""
        if not os.path.exists(KEYS_DIR): os.makedirs(KEYS_DIR)
        if not os.path.exists(DOWNLOADS_DIR): os.makedirs(DOWNLOADS_DIR)
        
        if not os.path.exists(USERS_DB_FILE):
            with open(USERS_DB_FILE, 'w') as f: json.dump({}, f)
            
        if not os.path.exists(MESSAGES_DB_FILE):
            with open(MESSAGES_DB_FILE, 'w') as f: json.dump([], f)

    # --- Password Encryption (Hash + Salt) ---
    def _hash_password(self, password, salt=None):
        """Standard Hashing for authentication verification"""
        if not salt:
            salt = os.urandom(16).hex()
        # Using SHA256 with salt for secure storage
        combined = password + salt + SYSTEM_PEPPER
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return hashed, salt

    # --- Derive Key from Password ---
    # Used to encrypt the local private key file (Blowfish)
    def _derive_key_from_password(self, password, salt):
        # Create a 16-byte key for Blowfish from the password
        # We use SHA256 (32 bytes) and take the first 16 bytes
        combined = SYSTEM_PEPPER + password + salt
        return hashlib.sha256(combined.encode()).digest()[:16]

    # --- Registration ---
    def register(self):
        print("\n--- NEW USER REGISTRATION ---")
        username = input("Choose Username: ").strip()
        
        with open(USERS_DB_FILE, 'r') as f:
            users_db = json.load(f)
        
        if username in users_db:
            print("[ERROR] Username already taken.")
            return

        password = input("Choose Password: ").strip()
        
        print("Generating Cryptographic Keys (This may take a moment)...")
        # Generate Rabin Keys (Signing)
        rabin_pub, rabin_priv = RabinSignature.generate_keys(key_size=256)
        # Generate ElGamal Keys (Encryption)
        elgamal_priv, elgamal_pub = ECElGamalSystem.generate_keys()

        # Prepare keys dictionary for storage
        private_keys_dict = {
            "rabin_priv": rabin_priv,
            "elgamal_priv": elgamal_priv
        }
        
        # --- SECURITY STEP: Encrypt Private Keys before saving ---
        # 1. Serialize data to bytes using Pickle
        serialized_keys = pickle.dumps(private_keys_dict)

        pass_hash, salt = self._hash_password(password)
        # 2. Derive encryption key from the user's password
        encryption_key = self._derive_key_from_password(password, salt)
        iv = os.urandom(8)
        
        # 3. Encrypt the serialized keys using Blowfish
        cipher = BlowfishCFB(encryption_key, iv)
        encrypted_keys_blob = cipher.encrypt(serialized_keys)
        
        # 4. Save IV + Encrypted Data to disk
        final_blob = iv + encrypted_keys_blob
        
        key_path = os.path.join(KEYS_DIR, f"{username}_keys.enc") 
        with open(key_path, "wb") as f:
            f.write(final_blob)

        # --- Save public info to DB ---
        users_db[username] = {
            "password_hash": pass_hash,
            "salt": salt,
            "public_keys": {
                "rabin_n": rabin_pub,     # Rabin Public Key
                "elgamal_q": elgamal_pub  # ElGamal Public Key
            }
        }
        
        with open(USERS_DB_FILE, 'w') as f:
            json.dump(users_db, f, indent=4) 

        print(f"[SUCCESS] User '{username}' registered and keys secured on disk!")

    # --- Login ---
    def login(self):
        print("\n--- LOGIN ---")
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        with open(USERS_DB_FILE, 'r') as f:
            users_db = json.load(f)

        if username not in users_db:
            print("[ERROR] User not found.")
            return False

        # 1. Verify Identity (Hash check)
        user_record = users_db[username]
        input_hash, _ = self._hash_password(password, user_record['salt'])
        
        if input_hash != user_record['password_hash']:
            print("[ERROR] Invalid password.")
            return False
            
        print(f"Welcome back, {username}! Decrypting your keychain...")
        
        # 2. Decrypt Private Keys using the Password
        key_path = os.path.join(KEYS_DIR, f"{username}_keys.enc")
        if not os.path.exists(key_path):
             print("[ERROR] Key file missing!")
             return False

        try:
            with open(key_path, "rb") as f:
                file_content = f.read()
            
            # Extract IV (first 8 bytes) and Encrypted Data
            iv = file_content[:8]
            encrypted_data = file_content[8:]
            
            # Derive the key again from the input password
            decryption_key = self._derive_key_from_password(password, user_record['salt'])
            
            # Decrypt
            cipher = BlowfishCFB(decryption_key, iv)
            decrypted_serialized_data = cipher.decrypt(encrypted_data)
            
            # Unpickle (Convert bytes back to Dictionary)
            self.current_user_keys = pickle.loads(decrypted_serialized_data)
            self.current_user = username
            return True

        except Exception as e:
            print(f"[CRITICAL ERROR] Failed to decrypt keys. Password correct but decryption failed? {e}")
            return False

    def logout(self):
        self.current_user = None
        self.current_user_keys = None
        print("Logged out successfully.")

    # ==========================================
    #         Send File Logic
    # ==========================================
    def send_file(self):
        if not self.current_user: return

        # --- Step 1: Select Recipient from List ---
        with open(USERS_DB_FILE, 'r') as f:
            users_db = json.load(f)

        # Get all users except myself
        potential_recipients = [u for u in users_db.keys() if u != self.current_user]

        if not potential_recipients:
            print("[ERROR] No other users registered in the system.")
            return

        print("\n--- Select Recipient ---")
        for i, u in enumerate(potential_recipients):
            print(f"{i + 1}. {u}")
        
        choice = input("Enter user number: ")
        if not choice.isdigit():
            print("Invalid input.")
            return
        
        idx = int(choice) - 1
        if idx < 0 or idx >= len(potential_recipients):
            print("Invalid selection.")
            return
            
        recipient = potential_recipients[idx]
        
        # Retrieve Recipient's Public Key
        recipient_elgamal_pub = users_db[recipient]["public_keys"]["elgamal_q"]
        if isinstance(recipient_elgamal_pub, list):
            recipient_elgamal_pub = tuple(recipient_elgamal_pub)

        # --- Step 2: Select File ---
        # .strip('"') fixes issue where Windows "Copy as path" includes quotes
        file_path = input("Enter file path to send: ").strip().strip('"')
        
        if not os.path.exists(file_path):
            print("[ERROR] File does not exist.")
            return

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            file_data = f.read()

        print("\n[PROCESS] Starting Hybrid Encryption...")

        # A. Sign (Rabin)
        print(" -> Signing file...")
        my_priv_key = self.current_user_keys["rabin_priv"]
        signature, pad = RabinSignature.sign(file_data, my_priv_key)
        
        # FIX: Changed from 32 to 64 bytes because Rabin 512-bit key produces large signatures
        sig_bytes = signature.to_bytes(64, 'big') 
        pad_bytes = pad.to_bytes(4, 'big')
        
        # B. Encapsulate
        combined_data = file_data + sig_bytes + pad_bytes

        # C. Encrypt Data (Blowfish)
        print(" -> Encrypting content (Blowfish)...")
        session_key = os.urandom(16)
        iv = os.urandom(8)
        
        cipher_bf = BlowfishCFB(session_key, iv) 
        encrypted_payload = cipher_bf.encrypt(combined_data)

        # D. Encrypt Session Key (ElGamal)
        print(" -> Encrypting session key (ElGamal)...")
        R_point, encrypted_session_key = ECElGamalSystem.encrypt_key(recipient_elgamal_pub, session_key)

        # E. Save to JSON (Send)
        message_packet = {
            "from": self.current_user,
            "to": recipient,
            "filename": filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data": {
                "iv": iv.hex(),
                "encrypted_payload": encrypted_payload.hex(),
                "encrypted_session_key": encrypted_session_key.hex(),
                "elgamal_R_point": R_point 
            }
        }

        with open(MESSAGES_DB_FILE, 'r') as f:
            messages = json.load(f)
        messages.append(message_packet)
        with open(MESSAGES_DB_FILE, 'w') as f:
            json.dump(messages, f, indent=4)

        print(f"[SUCCESS] Message sent to {recipient}!")

    # --- Check Inbox ---
    def check_inbox(self):
        if not self.current_user: return

        with open(MESSAGES_DB_FILE, 'r') as f:
            all_messages = json.load(f)

        my_messages = [m for m in all_messages if m["to"] == self.current_user]

        if not my_messages:
            print("\n[INBOX] No messages found.")
            return

        print(f"\n[INBOX] You have {len(my_messages)} messages:")
        for idx, msg in enumerate(my_messages):
            print(f" {idx+1}. From: {msg['from']} | File: {msg['filename']} | Time: {msg['timestamp']}")

        choice = input("\nEnter message number to download & decrypt (or '0' to cancel): ")
        if not choice.isdigit() or int(choice) == 0: return
        
        idx = int(choice) - 1
        if idx < 0 or idx >= len(my_messages):
            print("Invalid choice.")
            return

        target_msg = my_messages[idx]
        self._process_incoming_message(target_msg)

    def _process_incoming_message(self, msg):
        sender = msg["from"]
        print(f"\n[PROCESS] Decrypting message from {sender}...")

        with open(USERS_DB_FILE, 'r') as f:
            users_db = json.load(f)
        sender_rabin_pub = users_db[sender]["public_keys"]["rabin_n"]

        data = msg["data"]
        
        iv = bytes.fromhex(data["iv"])
        encrypted_payload = bytes.fromhex(data["encrypted_payload"])
        encrypted_session_key = bytes.fromhex(data["encrypted_session_key"])
        R_point = tuple(data["elgamal_R_point"])

        # 1. Decrypt Session Key
        try:
            my_elgamal_priv = self.current_user_keys["elgamal_priv"]
            session_key = ECElGamalSystem.decrypt_key(my_elgamal_priv, R_point, encrypted_session_key)
            print(" -> Session Key decrypted.")
        except Exception as e:
            print(f"[ERROR] ElGamal Decryption failed: {e}")
            return

        # 2. Decrypt Payload
        try:
            cipher_bf = BlowfishCFB(session_key, iv)
            decrypted_combined = cipher_bf.decrypt(encrypted_payload)
            print(" -> Payload decrypted.")
        except Exception as e:
            print(f"[ERROR] Blowfish Decryption failed: {e}")
            return

        # 3. Extract & Verify
        # FIX: Adjusted slicing for 64-byte signature
        # Structure: [File]...[Signature 64 bytes][Pad 4 bytes]
        pad_bytes = decrypted_combined[-4:]
        sig_bytes = decrypted_combined[-68:-4]
        file_content = decrypted_combined[:-68]

        padding_int = int.from_bytes(pad_bytes, 'big')
        signature_int = int.from_bytes(sig_bytes, 'big')

        is_valid = RabinSignature.verify(file_content, signature_int, padding_int, sender_rabin_pub)

        if is_valid:
            print("[SUCCESS] Signature Verified! File is authentic.")
            out_path = os.path.join(DOWNLOADS_DIR, f"received_{msg['filename']}")
            with open(out_path, "wb") as f:
                f.write(file_content)
            print(f"[SAVED] File saved to: {out_path}")
        else:
            print("[CRITICAL WARNING] Signature Verification Failed!")

# ==========================================
#              MAIN MENU LOOP
# ==========================================
def main_menu():
    system = SecureSystem()
    while True:
        if not system.current_user:
            print("\n=== SECURE FILE SYSTEM ===")
            print("1. Login")
            print("2. Register")
            print("3. Exit")
            choice = input("Select: ")

            if choice == "1": system.login()
            elif choice == "2": system.register()
            elif choice == "3": break
        else:
            print(f"\n--- Menu ({system.current_user}) ---")
            print("1. Send Secure File")
            print("2. Check Inbox")
            print("3. Logout")
            choice = input("Select: ")

            if choice == "1": system.send_file()
            elif choice == "2": system.check_inbox()
            elif choice == "3": system.logout()

if __name__ == "__main__":
    main_menu()