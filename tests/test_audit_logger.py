import os
import json
import base64
import pytest
from datetime import datetime
from backend.audit.audit_logger import AuditLogger
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

@pytest.fixture
def temp_log_dir(tmp_path):
    """Create a temporary directory for test logs."""
    log_dir = tmp_path / "test_logs"
    log_dir.mkdir()
    return str(log_dir)

@pytest.fixture
def audit_logger(temp_log_dir):
    """Create an AuditLogger instance with a temporary log directory."""
    return AuditLogger(log_dir=temp_log_dir)

def test_init_creates_log_directory(temp_log_dir):
    """Test that initializing AuditLogger creates the log directory."""
    # Delete directory to test creation
    os.rmdir(temp_log_dir)
    AuditLogger(log_dir=temp_log_dir)
    assert os.path.exists(temp_log_dir)

def test_log_security_event_basic(audit_logger, temp_log_dir):
    """Test basic security event logging functionality."""
    event_type = "LOGIN_ATTEMPT"
    data = {"username": "test_user", "success": True}
    user_id = "user123"
    
    audit_logger.log_security_event(event_type, data, user_id)
    
    log_file = os.path.join(temp_log_dir, 'audit.log')
    assert os.path.exists(log_file)
    
    with open(log_file, 'r') as f:
        log_entry = json.loads(f.readline())
    
    assert log_entry['event_type'] == event_type
    assert log_entry['data'] == data
    assert log_entry['user_id'] == user_id
    assert 'timestamp' in log_entry
    assert 'hash' in log_entry
    assert 'signature' in log_entry
    assert log_entry['previous_hash'] is None  # First entry

def test_hash_chaining(audit_logger):
    """Test that hash chaining works correctly between consecutive log entries."""
    # Log first event
    audit_logger.log_security_event("EVENT1", {"data": "first"})
    first_hash = audit_logger.previous_hash
    
    # Log second event
    audit_logger.log_security_event("EVENT2", {"data": "second"})
    
    with open(audit_logger.log_file, 'r') as f:
        lines = f.readlines()
        second_entry = json.loads(lines[1])
        
    assert second_entry['previous_hash'] == first_hash

def test_signature_verification(audit_logger):
    """Test that log entries have valid signatures."""
    audit_logger.log_security_event("TEST_EVENT", {"data": "test"})
    
    with open(audit_logger.log_file, 'r') as f:
        log_entry = json.loads(f.readline())
    
    # Verify signature
    entry_copy = dict(log_entry)
    signature = entry_copy.pop('signature')
    hash_value = entry_copy.pop('hash')
    entry_json = json.dumps(entry_copy, sort_keys=True).encode()
    
    # This should not raise an exception if signature is valid
    public_key = audit_logger.signing_key.public_key()
    public_key.verify(
        base64.b64decode(signature),
        entry_json
    )

def test_verify_log_integrity_valid(audit_logger):
    """Test log integrity verification with valid logs."""
    # Create multiple log entries
    audit_logger.log_security_event("EVENT1", {"data": "first"})
    first_hash = audit_logger.previous_hash
    
    audit_logger.log_security_event("EVENT2", {"data": "second"})
    
    # Verify entries exist and have correct chain
    with open(audit_logger.log_file, 'r') as f:
        lines = f.readlines()
        assert len(lines) == 2
        
        first_entry = json.loads(lines[0])
        second_entry = json.loads(lines[1])
        
        assert first_entry['hash'] == first_hash
        assert second_entry['previous_hash'] == first_hash
        
    # Verify overall integrity
    assert audit_logger.verify_log_integrity() is True

def test_verify_log_integrity_tampered(audit_logger):
    """Test log integrity verification with tampered logs."""
    # Create a log entry
    audit_logger.log_security_event("EVENT1", {"data": "first"})
    
    # Tamper with the log file
    with open(audit_logger.log_file, 'a') as f:
        f.write('{"tampered": true}\n')
    
    assert audit_logger.verify_log_integrity() is False

def test_load_previous_hash(temp_log_dir):
    """Test that previous hash is correctly loaded from existing log file."""
    # Create first logger and log an event
    logger1 = AuditLogger(log_dir=temp_log_dir)
    logger1.log_security_event("EVENT1", {"data": "first"})
    first_hash = logger1.previous_hash
    
    # Create new logger instance that should load the previous hash
    logger2 = AuditLogger(log_dir=temp_log_dir)
    assert logger2.previous_hash == first_hash

def test_error_handling(audit_logger, monkeypatch):
    """Test error handling during logging."""
    def mock_open(*args, **kwargs):
        raise PermissionError("Access denied")
    
    # Mock the open function to raise an error
    monkeypatch.setattr("builtins.open", mock_open)
    
    # This should not raise an exception, but handle it gracefully
    audit_logger.log_security_event("ERROR_TEST", {"data": "test"})