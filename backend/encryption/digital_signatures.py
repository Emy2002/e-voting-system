# backend/encryption/digital_signatures.py

import base64
import json
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# SR-05: Ed25519 digital signature for vote signing and verification

class DigitalSignatureService:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.get_public_key_pem()

    def load_private_key(self, pem_str: str):
        self.private_key = serialization.load_pem_private_key(pem_str.encode(), password=None)
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> str:
        if not self.public_key:
            raise ValueError("No public key available")
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem.decode()

    def get_private_key_pem(self) -> str:
        if not self.private_key:
            raise ValueError("No private key available")
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return pem.decode()

    def sign_vote(self, vote_data: dict) -> dict:
        if not self.private_key:
            raise ValueError("No private key available")
        vote_json = json.dumps(vote_data, sort_keys=True).encode()
        vote_hash = hashlib.sha256(vote_json).digest()
        signature = self.private_key.sign(vote_hash)
        signed_vote = {
            "vote_data": vote_data,
            "signature": base64.b64encode(signature).decode(),
            "timestamp": datetime.utcnow().isoformat(),
            "vote_hash": base64.b64encode(vote_hash).decode()
        }
        return signed_vote

    def verify_vote_signature(self, signed_vote: dict, public_key_pem: str = None) -> bool:
        try:
            public_key = self.public_key
            if public_key_pem:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
            if not public_key:
                raise ValueError("No public key available")

            vote_json = json.dumps(signed_vote["vote_data"], sort_keys=True).encode()
            computed_hash = hashlib.sha256(vote_json).digest()

            if computed_hash != base64.b64decode(signed_vote["vote_hash"]):
                return False

            signature = base64.b64decode(signed_vote["signature"])
            public_key.verify(signature, computed_hash)
            return True
        except Exception:
            return False

    def create_vote_receipt(self, signed_vote: dict) -> str:
        receipt_data = {
            "vote_hash": signed_vote["vote_hash"],
            "timestamp": signed_vote["timestamp"],
            "receipt_id": hashlib.sha256(
                (signed_vote["vote_hash"] + signed_vote["timestamp"]).encode()
            ).hexdigest()[:16],
        }
        return base64.b64encode(json.dumps(receipt_data).encode()).decode()
