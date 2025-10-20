# backend/security/token_manager.py

import secrets

# SR-18: API token creation and validation

class TokenManager:
    def __init__(self):
        self.tokens = {}

    def generate_token(self, user_id):
        token = secrets.token_urlsafe(32)
        self.tokens[token] = user_id
        return token

    def validate_token(self, token):
        return self.tokens.get(token)
