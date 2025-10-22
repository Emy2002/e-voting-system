import pytest
from backend.encryption.password_hashing import PasswordHashingService

@pytest.fixture
def password_service():
    return PasswordHashingService()


def test_hash_and_verify_password(password_service):
    password = "StrongPass123!"
    hashed = password_service.hash_password(password)

    # Verify the original password works
    assert password_service.verify_password(password, hashed) is True

    # Wrong password should fail
    assert password_service.verify_password("WrongPass456!", hashed) is False

    # Check if hash needs rehash (should be False immediately)
    assert password_service.needs_rehash(hashed) is False


def test_is_strong_password(password_service):
    # Strong password
    strong = "MyStrongPass123!"
    assert password_service.is_strong_password(strong) is True

    # Too short
    assert password_service.is_strong_password("short1!") is False

    # Missing uppercase but still meets 3/4 → should be True
    assert password_service.is_strong_password("lowercase123!") is True

    # Missing number, uppercase and special → False
    assert password_service.is_strong_password("onlylowercaseletters") is False

    # Missing special, has uppercase, lowercase, digit → True
    assert password_service.is_strong_password("NoSpecial123") is True

def test_generate_secure_password(password_service):
    password = password_service.generate_secure_password(16)
    assert len(password) >= 12
    assert password_service.is_strong_password(password) is True
