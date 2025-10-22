# tests/test_token_manager.py
import pytest
import time
from flask import Flask
from flask_jwt_extended import JWTManager, set_access_cookies, unset_jwt_cookies
from backend.security.token_manager import TokenManager

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = "test_secret"
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1  # 1 second expiry for testing
    JWTManager(app)
    return app

@pytest.fixture
def client(app):
    with app.test_client() as client:
        yield client

@pytest.fixture
def token_manager(app):
    tm = TokenManager(app)
    return tm

def test_generate_and_validate_token(token_manager):
    user_id = "user1"
    token = token_manager.generate_token(user_id, expires_in=5)
    assert isinstance(token, str)
    validated_id = token_manager.validate_token(token)
    assert validated_id == user_id

def test_token_expiry(token_manager):
    user_id = "user2"
    token = token_manager.generate_token(user_id, expires_in=1)  # 1 sec expiry
    # Immediately valid
    assert token_manager.validate_token(token) == user_id
    # Wait for expiry
    time.sleep(2)
    assert token_manager.validate_token(token) is None

def test_get_identity(token_manager, app, client):
    from flask_jwt_extended import jwt_required

    user_id = "user3"
    token = token_manager.generate_token(user_id, expires_in=60)

    @app.route("/dashboard")
    @jwt_required()  # Requires JWT in request
    def dashboard():
        identity = token_manager.get_identity()
        return identity or "No identity", 200

    # Send token in Authorization header
    rv = client.get("/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert rv.data.decode() == user_id

def test_unset_jwt_cookies(client, token_manager):
    user_id = "user4"
    token = token_manager.generate_token(user_id, expires_in=60)

    response = client.get('/')
    set_access_cookies(response, token)
    assert 'access_token_cookie' in response.headers.get('Set-Cookie', '')

    # Simulate logout
    logout_response = client.get('/logout')
    unset_jwt_cookies(logout_response)
    cookies = logout_response.headers.getlist('Set-Cookie')
    assert any('access_token_cookie=;' in c for c in cookies)
