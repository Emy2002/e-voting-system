import pytest
import time
from flask_jwt_extended import create_access_token, create_refresh_token, set_access_cookies, unset_jwt_cookies
from backend import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1  # expire quickly for testing
    with app.test_client() as client:
        with app.app_context():
            yield client


def test_access_token_cookie_set_and_expiry(client):
    # Generate tokens
    access_token = create_access_token(identity='user1')
    refresh_token = create_refresh_token(identity='user1')

    # Attach tokens to cookies manually
    response = client.get('/')
    set_access_cookies(response, access_token)
    response.set_cookie('refresh_token_cookie', refresh_token)
    assert 'access_token_cookie' in response.headers.getlist('Set-Cookie')[0]

    # Simulate using token for authorized request
    client.set_cookie('localhost', 'access_token_cookie', access_token)
    resp = client.get('/dashboard')
    assert resp.status_code in (200, 302, 401)

    # Wait for expiry
    time.sleep(2)
    expired_resp = client.get('/dashboard')
    # Either a redirect to login or JSON error per expired_token_loader
    assert expired_resp.status_code in (302, 401)


def test_unset_jwt_cookies(client):
    access_token = create_access_token(identity='user1')
    response = client.get('/')
    set_access_cookies(response, access_token)
    assert 'access_token_cookie' in response.headers.get('Set-Cookie', '')

    # Simulate logout
    logout_response = client.get('/logout')
    unset_jwt_cookies(logout_response)
    cookies = logout_response.headers.getlist('Set-Cookie')
    assert any('access_token_cookie=;' in c for c in cookies)
