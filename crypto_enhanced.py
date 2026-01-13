import os
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    """Handles encryption, decryption, and password hashing with enhanced security"""

    def __init__(self):
        self.ph = PasswordHasher()
        self.db_key = self._load_or_create_db_key()

    def _load_or_create_db_key(self):
        """Load or create the database encryption key"""
        key_path = '.db_key'

        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            # Generate a new 256-bit key for AES-256
            key = AESGCM.generate_key(bit_length=256)

            # Save with restrictive permissions
            with open(key_path, 'wb') as f:
                f.write(key)
            os.chmod(key_path, 0o600)

            return key

    def hash_master_password(self, password):
        """Hash master password using Argon2"""
        password_hash = self.ph.hash(password)
        # Generate a salt for encryption key derivation
        salt = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        return password_hash, salt

    def verify_master_password(self, password, password_hash):
        """Verify master password against hash"""
        try:
            self.ph.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False

    def derive_encryption_key(self, password, salt):
        """Derive encryption key from master password and salt"""
        salt_bytes = base64.urlsafe_b64decode(salt.encode('utf-8'))

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=480000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key

    def encrypt_password(self, password, master_password, salt):
        """Encrypt a password using the master password"""
        key = self.derive_encryption_key(master_password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(password.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt_password(self, encrypted_password, master_password, salt):
        """Decrypt a password using the master password"""
        try:
            key = self.derive_encryption_key(master_password, salt)
            f = Fernet(key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode('utf-8'))
            decrypted = f.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception:
            return None

    def encrypt_field(self, plaintext):
        """
        Encrypt a database field using AES-256-GCM
        This is used for encrypting username, URL, and notes fields
        """
        if plaintext is None or plaintext == '':
            return None

        try:
            aesgcm = AESGCM(self.db_key)
            nonce = os.urandom(12)  # 96-bit nonce for GCM

            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

            # Combine nonce + ciphertext and encode
            encrypted_data = nonce + ciphertext
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            print(f"Field encryption error: {e}")
            return None

    def decrypt_field(self, encrypted_data):
        """
        Decrypt a database field using AES-256-GCM
        """
        if encrypted_data is None or encrypted_data == '':
            return None

        try:
            # Decode from base64
            data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))

            # Extract nonce (first 12 bytes) and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self.db_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext.decode('utf-8')
        except Exception as e:
            # If decryption fails, might be legacy unencrypted data
            # Return as-is for backward compatibility
            return encrypted_data
