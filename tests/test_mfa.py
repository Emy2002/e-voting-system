import pytest
import pyotp
import time
from backend.authentication import mfa

# Example secret for testing (do not use in production)
TEST_SECRET = 'JBSWY3DPEHPK3PXP'


def test_generate_totp_secret():
    secret = mfa.generate_totp_secret()
    assert isinstance(secret, str)
    assert len(secret) >= 16  # Typical base32 length


def test_get_totp_uri():
    username = 'testuser'
    secret = TEST_SECRET
    uri = mfa.get_totp_uri(username, secret)
    assert uri.startswith('otpauth://totp/')
    assert username in uri
    assert secret in uri


def test_verify_totp_valid():
    secret = TEST_SECRET
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert mfa.verify_totp(secret, code) is True


def test_verify_totp_invalid():
    secret = TEST_SECRET
    invalid_code = '123456'
    assert mfa.verify_totp(secret, invalid_code) is False


def test_verify_totp_expired(monkeypatch):
    secret = TEST_SECRET
    totp = pyotp.TOTP(secret)
    code = totp.now()
    # Simulate time after code expiry (default step=30s)
    future_time = time.time() + 60
    # Instead of monkeypatching, use for_time param to control time
    assert totp.verify(code, for_time=future_time, valid_window=0) is False


def test_verify_totp_window(monkeypatch):
    secret = TEST_SECRET
    totp = pyotp.TOTP(secret)
    code = totp.at(int(time.time()) - 30)  # Previous time step
    # By default, window=0, so this should fail
    assert mfa.verify_totp(secret, code) is False
    # Patch verify_totp to allow window=1
    assert mfa.verify_totp(secret, code, window=1) is True
