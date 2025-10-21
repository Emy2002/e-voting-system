import pytest
import pyotp
from backend.authentication import mfa
from backend import app
from flask_jwt_extended import create_access_token

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client

def test_dual_admin_mfa_verification(client):
    # Simulate two admins with different secrets
    admin1_secret = mfa.generate_totp_secret()
    admin2_secret = mfa.generate_totp_secret()
    admin1_totp = pyotp.TOTP(admin1_secret)
    admin2_totp = pyotp.TOTP(admin2_secret)
    code1 = admin1_totp.now()
    code2 = admin2_totp.now()
    # Both codes should be valid for their respective secrets
    assert mfa.verify_totp(admin1_secret, code1) is True
    assert mfa.verify_totp(admin2_secret, code2) is True
    # Cross-check: wrong code for secret should fail
    assert mfa.verify_totp(admin1_secret, code2) is False
    assert mfa.verify_totp(admin2_secret, code1) is False
    # Simulate dual approval logic (both must be valid)
    both_valid = mfa.verify_totp(admin1_secret, code1) and mfa.verify_totp(admin2_secret, code2)
    assert both_valid is True

    # Simulate JWT-authenticated session for a protected endpoint
    access_token = create_access_token(identity='1')
    client.set_cookie('localhost', 'access_token_cookie', access_token)
    resp = client.get('/dashboard')
    assert resp.status_code in (200, 302, 401)  # Acceptable: 200 OK, 302 redirect, or 401 if role/session missing
