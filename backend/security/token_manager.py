# backend/security/token_manager.py

from datetime import timedelta
from flask_jwt_extended import (
    create_access_token,
    decode_token,
    get_jwt_identity,
)
from flask import current_app

# SR-18: Secure JWT-based API token creation and validation using Flask-JWT-Extended

class TokenManager:
    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault("JWT_SECRET_KEY", "change_this_secret_key")
        app.config.setdefault("JWT_ACCESS_TOKEN_EXPIRES", timedelta(hours=1))

    def generate_token(self, user_id: str, expires_in: int = 3600) -> str:
        # Override default expiry if custom value is given
        expires_delta = timedelta(seconds=expires_in)
        token = create_access_token(identity=user_id, expires_delta=expires_delta)
        return token

    def validate_token(self, token: str):
        try:
            decoded = decode_token(token)
            return decoded.get("sub")  # "sub" is the identity field in Flask-JWT-Extended
        except Exception as e:
            current_app.logger.warning(f"Token validation failed: {str(e)}")
            return None

    def get_identity(self):
        try:
            return get_jwt_identity()
        except Exception:
            return None
