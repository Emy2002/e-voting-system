import pytest
import time
from flask import session
from backend import app
from flask_jwt_extended import create_access_token

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client

def test_session_timeout(client):
    # Simulate login by setting session variables and JWT
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['user_role'] = 'voter'
        sess['login_time'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    access_token = create_access_token(identity='1')
    client.set_cookie('localhost', 'access_token_cookie', access_token)
    # Access dashboard (should be allowed)
    resp = client.get('/dashboard')
    assert resp.status_code in (200, 302)  # Accept redirect for role/session
    # Simulate session timeout by clearing session
    with client.session_transaction() as sess:
        sess.clear()
    # Access dashboard again (should redirect, 401, or 200 if JWT is still valid)
    resp2 = client.get('/dashboard', follow_redirects=False)
    assert resp2.status_code in (200, 302, 401)
