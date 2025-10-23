# backend/encryption/data_encryption.py
"""Vote encryption and decryption service using AES-256-GCM with key envelope.

This module implements secure vote encryption using a two-layer approach:
1. Vote data is encrypted using AES-256-GCM with a random key
2. The random key is encrypted using Fernet (key envelope) with a master key

Key features:
- AES-256-GCM provides confidentiality and integrity protection
- Key envelope pattern allows master key rotation without re-encrypting votes
- Voter ID hashing for voter anonymity while preventing duplicate votes
- PBKDF2 key derivation for password-based operations

Exception hierarchy:
- DecryptionError: Base class for all decryption failures
  - InvalidPackageError: Malformed input (base64/JSON decode failures)
  - KeyDecryptionError: Master key cannot decrypt the vote key (wrong key)
  - IntegrityError: Ciphertext/tag verification failed (tampering detected)

Usage:
    svc = DataEncryptionService(master_key='32-byte-master-key')
    
    # Encrypt a vote
    encrypted = svc.encrypt_vote(
        {'candidate': 'Alice'},
        voter_id='voter123'
    )
    
    # Decrypt a vote (may raise DecryptionError subclasses)
    try:
        vote = svc.decrypt_vote(encrypted)
    except InvalidPackageError:
        # Handle malformed input
    except KeyDecryptionError:
        # Handle wrong master key
    except IntegrityError:
        # Handle tampering detected
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
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
        # Step 1: decode package from base64 and JSON
        try:
            package = json.loads(base64.b64decode(encrypted_vote).decode())
        except Exception as e:
            raise InvalidPackageError(f"Invalid encrypted package: {e}")

        # Step 2: verify package structure and decrypt envelope key
        required_fields = ['encrypted_key', 'encrypted_vote', 'iv', 'tag']
        missing_fields = [f for f in required_fields if f not in package]
        if missing_fields:
            raise InvalidPackageError(f"Missing required fields: {', '.join(missing_fields)}")

        try:
            f = Fernet(base64.urlsafe_b64encode(self.master_key))
            vote_key = f.decrypt(base64.b64decode(package['encrypted_key']))
        except InvalidToken as e:
            raise KeyDecryptionError(f"Failed to decrypt envelope key: {e}")
        except Exception as e:
            raise KeyDecryptionError(f"Unexpected key decryption error: {e}")

        # Step 3: decrypt AES-GCM ciphertext (verify tag)
        try:
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
        except InvalidTag as e:
            # GCM tag verification failed
            raise IntegrityError(f"GCM authentication failed: {e}")
        except Exception as e:
            # Could be JSON errors or integrity errors surfaced differently
            raise IntegrityError(f"Failed to decrypt or verify ciphertext: {e}")

    def _hash_voter_id(self, voter_id: str):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((voter_id + "some_salt").encode())
        return base64.b64encode(digest.finalize()).decode()


class DecryptionError(Exception):
    """Base exception for decryption-related failures."""
    pass


class InvalidPackageError(DecryptionError):
    """Raised when the encrypted package is malformed (bad base64/JSON)."""
    pass


class KeyDecryptionError(DecryptionError):
    """Raised when the envelope key cannot be decrypted with the master key."""
    pass


class IntegrityError(DecryptionError):
    """Raised when ciphertext/tag integrity/authentication fails (GCM tag mismatch)."""
    pass
