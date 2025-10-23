import base64
import json
import pytest
from backend.encryption.data_encryption import (
    DataEncryptionService,
    DecryptionError,
    InvalidPackageError,
    KeyDecryptionError,
    IntegrityError,
)
from cryptography.fernet import Fernet


def test_encrypt_decrypt_roundtrip():
    svc = DataEncryptionService(master_key='0'*32)
    vote = {'candidate': 'Alice', 'timestamp': '2025-01-01T12:00:00Z'}
    encrypted = svc.encrypt_vote(vote, voter_id='voter123')
    assert isinstance(encrypted, str)

    decrypted = svc.decrypt_vote(encrypted)
    assert decrypted == vote


def test_decrypt_with_wrong_master_key_fails():
    svc1 = DataEncryptionService(master_key='a'*32)
    vote = {'candidate': 'Bob'}
    encrypted = svc1.encrypt_vote(vote, voter_id='voterX')

    svc2 = DataEncryptionService(master_key='b'*32)
    with pytest.raises(KeyDecryptionError):
        svc2.decrypt_vote(encrypted)


def test_tampered_ciphertext_fails():
    svc = DataEncryptionService(master_key='1'*32)
    vote = {'candidate': 'Carol'}
    encrypted = svc.encrypt_vote(vote, voter_id='voterY')

    # decode package, tamper with ciphertext
    package = json.loads(base64.b64decode(encrypted).decode())
    ciphertext = base64.b64decode(package['encrypted_vote'])
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    package['encrypted_vote'] = base64.b64encode(bytes(tampered)).decode()
    tampered_b64 = base64.b64encode(json.dumps(package).encode()).decode()

    with pytest.raises(IntegrityError):
        svc.decrypt_vote(tampered_b64)


def test_voter_id_hash_is_consistent():
    svc = DataEncryptionService(master_key='2'*32)
    e1 = svc.encrypt_vote({'candidate':'D'}, voter_id='vid')
    e2 = svc.encrypt_vote({'candidate':'E'}, voter_id='vid')
    p1 = json.loads(base64.b64decode(e1).decode())
    p2 = json.loads(base64.b64decode(e2).decode())
    assert p1['voter_id_hash'] == p2['voter_id_hash']


def test_malformed_package_raises():
    svc = DataEncryptionService(master_key='3'*32)
    # not base64
    with pytest.raises(InvalidPackageError):
        svc.decrypt_vote('not-a-valid-base64')


def test_tag_tampering_fails():
    svc = DataEncryptionService(master_key='4'*32)
    vote = {'candidate': 'Eve'}
    encrypted = svc.encrypt_vote(vote, voter_id='voterZ')

    package = json.loads(base64.b64decode(encrypted).decode())
    tag = bytearray(base64.b64decode(package['tag']))
    tag[0] ^= 0xFF
    package['tag'] = base64.b64encode(bytes(tag)).decode()
    tampered_b64 = base64.b64encode(json.dumps(package).encode()).decode()

    with pytest.raises(IntegrityError):
        svc.decrypt_vote(tampered_b64)


def test_derive_key_consistency_and_fernet_usage():
    svc = DataEncryptionService(master_key='9'*32)
    password = 'strong-password'
    key_b64, salt = svc.derive_key(password)

    # derive again with same salt should yield same key
    key2_b64, salt2 = svc.derive_key(password, salt=salt)
    assert key_b64 == key2_b64
    assert salt == salt2

    # different salt yields different key
    key3_b64, salt3 = svc.derive_key(password)
    assert key3_b64 != key_b64

    # derived key should be usable with Fernet
    f = Fernet(key_b64)
    token = f.encrypt(b"hello")
    assert f.decrypt(token) == b"hello"


def test_missing_package_fields():
    svc = DataEncryptionService(master_key='5'*32)
    vote = {'candidate': 'Frank'}
    encrypted = svc.encrypt_vote(vote, voter_id='voterW')

    # Remove encrypted_key from package
    package = json.loads(base64.b64decode(encrypted).decode())
    del package['encrypted_key']
    tampered = base64.b64encode(json.dumps(package).encode()).decode()

    with pytest.raises(InvalidPackageError):
        svc.decrypt_vote(tampered)


def test_empty_vote():
    svc = DataEncryptionService(master_key='6'*32)
    vote = {}
    encrypted = svc.encrypt_vote(vote, voter_id='voterEmpty')
    decrypted = svc.decrypt_vote(encrypted)
    assert decrypted == vote


def test_invalid_json_in_vote():
    svc = DataEncryptionService(master_key='7'*32)
    vote = {'candidate': 'Grace'}
    encrypted = svc.encrypt_vote(vote, voter_id='voterY')

    # Make the decrypted JSON invalid by corrupting the ciphertext
    package = json.loads(base64.b64decode(encrypted).decode())
    ciphertext = bytearray(base64.b64decode(package['encrypted_vote']))
    # Corrupt the JSON structure but keep the length the same
    ciphertext[-2] ^= 0xFF
    package['encrypted_vote'] = base64.b64encode(bytes(ciphertext)).decode()
    tampered = base64.b64encode(json.dumps(package).encode()).decode()

    with pytest.raises(IntegrityError):
        svc.decrypt_vote(tampered)
