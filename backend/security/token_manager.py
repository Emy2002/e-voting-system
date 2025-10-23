# backend/security/token_manager.py
from datetime import timedelta
from flask_jwt_extended import create_access_token, decode_token, get_jwt_identity
from flask import current_app, Flask

# SR-18: Secure JWT-based API token creation and validation using Flask-JWT-Extended
class TokenManager:
    def __init__(self, app: Flask = None):
        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        app.config.setdefault("JWT_SECRET_KEY", "change_this_secret_key")
        app.config.setdefault("JWT_ACCESS_TOKEN_EXPIRES", timedelta(hours=1))

    def generate_token(self, user_id: str, expires_in: int = 3600) -> str:
        # Create a JWT token with user_id as identity.
        expires_delta = timedelta(seconds=expires_in)
        token = create_access_token(identity=user_id, expires_delta=expires_delta)
        return token

    def validate_token(self, token: str):
        # Return the user_id if token is valid, else None.
        try:
            decoded = decode_token(token, allow_expired=False)
            return decoded.get("sub")  # 'sub' is the identity field
        except Exception as e:
            current_app.logger.warning(f"Token validation failed: {str(e)}")
            return None

    def get_identity(self):
        # Return the current user identity from JWT in request context.
        try:
            return get_jwt_identity()
        except Exception:
            return None