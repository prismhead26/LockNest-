import os
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoManager:
    """Handles encryption, decryption, and password hashing"""

    def __init__(self):
        self.ph = PasswordHasher()

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
