# backend/audit/audit_logger.py

import os
import json
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# SR-08: Immutable audit logging with hash chaining and Ed25519 signatures

class AuditLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, 'audit.log')
        self.previous_hash = None

        os.makedirs(log_dir, exist_ok=True)

        self.signing_key = Ed25519PrivateKey.generate()
        self._load_previous_hash()

    def _load_previous_hash(self):
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    try:
                        last_entry = json.loads(lines[-1])
                        self.previous_hash = last_entry.get('hash')
                    except Exception:
                        self.previous_hash = None

    def log_security_event(self, event_type, data, user_id=None):
        try:
            timestamp = datetime.utcnow().isoformat()
            log_entry = {
                "timestamp": timestamp,
                "event_type": event_type,
                "data": data,
                "user_id": user_id,
                "previous_hash": self.previous_hash,
            }
            entry_json = json.dumps(log_entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
            log_entry['hash'] = entry_hash

            signature = self.signing_key.sign(entry_json.encode())
            log_entry['signature'] = base64.b64encode(signature).decode()

            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")

            self.previous_hash = entry_hash
        except Exception as e:
            print(f"Audit log error: {str(e)}")

    def verify_log_integrity(self):
        try:
            if not os.path.exists(self.log_file):
                return True
            previous_hash = None
            with open(self.log_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    log_entry = json.loads(line)
                    if log_entry.get('previous_hash') != previous_hash:
                        return False
                    signature = base64.b64decode(log_entry['signature'])
                    entry_copy = dict(log_entry)
                    entry_copy.pop('signature')
                    entry_json = json.dumps(entry_copy, sort_keys=True).encode()
                    public_key = self.signing_key.public_key()
                    public_key.verify(signature, entry_json)
                    previous_hash = log_entry['hash']
            return True
        except Exception:
            return False
