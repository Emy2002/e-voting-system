# backend/encryption/password_hashing.py

import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError

# SR-06: Password hashing and verification using Argon2id

class PasswordHashingService:
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
        )

    def hash_password(self, password: str) -> str:
        if not self.is_strong_password(password):
            raise ValueError("Password does not meet security requirements")
        try:
            return self.ph.hash(password)
        except HashingError as e:
            raise ValueError(f"Password hashing failed: {str(e)}")

    def verify_password(self, password: str, hash_value: str) -> bool:
        try:
            self.ph.verify(hash_value, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def needs_rehash(self, hash_value: str) -> bool:
        return self.ph.check_needs_rehash(hash_value)

    def is_strong_password(self, password: str) -> bool:
        if len(password) < 12:
            return False
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        return sum([has_upper, has_lower, has_digit, has_special]) >= 3

    def generate_secure_password(self, length=16) -> str:
        if length < 12:
            length = 12
        charset = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(),.?\":{}|<>"
        )
        while True:
            password = ''.join(secrets.choice(charset) for _ in range(length))
            if self.is_strong_password(password):
                return password
