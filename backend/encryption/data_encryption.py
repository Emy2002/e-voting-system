# backend/encryption/data_encryption.py

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# SR-04: AES-256 encryption for votes

class DataEncryptionService:
    def __init__(self, master_key=None):
        if master_key is None:
            # Use environment variable or default (change in production)
            master_key = os.environ.get('ENCRYPTION_MASTER_KEY', 'default-32-byte-key!!!!!1234567890abcd')
        # Key must be 32 bytes
        self.master_key = master_key.encode()[:32]

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key), salt

    def encrypt_vote(self, vote_data: dict, voter_id: str) -> str:
        """Encrypt vote data"""
        vote_key = os.urandom(32)
        iv = os.urandom(12)  # GCM standard nonce length

        vote_json = json.dumps(vote_data, sort_keys=True).encode()

        cipher = Cipher(
            algorithms.AES(vote_key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(vote_json) + encryptor.finalize()

        # Encrypt vote_key with master key using Fernet for key envelope
        f = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_vote_key = f.encrypt(vote_key)

        encrypted_package = {
            'encrypted_vote': base64.b64encode(ciphertext).decode(),
            'encrypted_key': base64.b64encode(encrypted_vote_key).decode(),
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'voter_id_hash': self._hash_voter_id(voter_id),
        }

        return base64.b64encode(json.dumps(encrypted_package).encode()).decode()

    def decrypt_vote(self, encrypted_vote: str) -> dict:
        """Decrypt vote data"""
        try:
            package = json.loads(base64.b64decode(encrypted_vote).decode())
            f = Fernet(base64.urlsafe_b64encode(self.master_key))
            vote_key = f.decrypt(base64.b64decode(package['encrypted_key']))

            cipher = Cipher(
                algorithms.AES(vote_key),
                modes.GCM(
                    base64.b64decode(package['iv']),
                    base64.b64decode(package['tag'])
                )
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(base64.b64decode(package['encrypted_vote'])) + decryptor.finalize()
            return json.loads(decrypted.decode())
        except Exception as e:
            raise ValueError(f"Failed to decrypt vote: {str(e)}")

    def _hash_voter_id(self, voter_id: str):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((voter_id + "some_salt").encode())
        return base64.b64encode(digest.finalize()).decode()
