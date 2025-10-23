from backend import app
from backend.audit.audit_logger import AuditLogger
import json
import os
from datetime import datetime

def test_audit_logger():
    # Initialize audit logger with test log directory
    test_log_dir = 'logs/test_audit'
    audit_logger = AuditLogger(log_dir=test_log_dir)
    
    print("\n=== Testing Audit Logger System ===\n")
    
    # Test 1: Basic Event Logging
    print("Test 1: Basic Event Logging")
    test_events = [
        {
            'event_type': 'user_login',
            'data': {'user_id': 123, 'role': 'voter'},
            'user_id': 123
        },
        {
            'event_type': 'vote_cast',
            'data': {'election_id': 'election_2025', 'timestamp': datetime.utcnow().isoformat()},
            'user_id': 123
        },
        {
            'event_type': 'configuration_change',
            'data': {'changed_by': 'admin', 'setting': 'security_level', 'new_value': 'high'},
            'user_id': 1
        }
    ]
    
    for event in test_events:
        print(f"\nLogging event: {event['event_type']}")
        audit_logger.log_security_event(
            event['event_type'],
            event['data'],
            event['user_id']
        )
        print("✓ Event logged successfully")
    
    print("\n✓ Test 1 completed\n")
    
    # Test 2: Verify Log Integrity
    print("Test 2: Verify Log Integrity")
    integrity_check = audit_logger.verify_log_integrity()
    print(f"Log integrity check result: {'PASSED' if integrity_check else 'FAILED'}")
    print("✓ Test 2 completed\n")
    
    # Test 3: Read and Parse Logs
    print("Test 3: Read and Parse Logs")
    print("Reading logged events:")
    try:
        with open(audit_logger.log_file, 'r') as f:
            for line in f:
                entry = json.loads(line)
                print("\nLog Entry:")
                print(f"  Timestamp: {entry['timestamp']}")
                print(f"  Event Type: {entry['event_type']}")
                print(f"  User ID: {entry['user_id']}")
                print(f"  Data: {json.dumps(entry['data'], indent=2)}")
                print(f"  Previous Hash: {entry['previous_hash']}")
                print(f"  Current Hash: {entry['hash']}")
                print("  Signature: " + entry['signature'][:50] + "...")
    except Exception as e:
        print(f"Error reading logs: {str(e)}")
    
    print("\n✓ Test 3 completed\n")
    
    # Test 4: Hash Chain Verification
    print("Test 4: Hash Chain Verification")
    previous_hash = None
    chain_valid = True
    try:
        with open(audit_logger.log_file, 'r') as f:
            for line in f:
                entry = json.loads(line)
                if entry['previous_hash'] != previous_hash:
                    print(f"Hash chain broken at event: {entry['event_type']}")
                    chain_valid = False
                previous_hash = entry['hash']
    except Exception as e:
        print(f"Error verifying hash chain: {str(e)}")
        chain_valid = False
    
    print(f"Hash chain verification: {'PASSED' if chain_valid else 'FAILED'}")
    print("✓ Test 4 completed\n")
    
    # Test 5: Malicious Modification Detection
    print("Test 5: Malicious Modification Detection")
    # Log a test event
    test_event = {
        'event_type': 'test_event',
        'data': {'test': 'data'},
        'user_id': 999
    }
    audit_logger.log_security_event(test_event['event_type'], test_event['data'], test_event['user_id'])
    
    # Verify integrity
    integrity_before = audit_logger.verify_log_integrity()
    print(f"Integrity before modification: {'PASSED' if integrity_before else 'FAILED'}")
    
    # Try to modify the log file (simulation)
    print("\nAttempting to detect tampering...")
    modified = False
    temp_file = audit_logger.log_file + '.tmp'
    try:
        with open(audit_logger.log_file, 'r') as original, open(temp_file, 'w') as temp:
            for line in original:
                entry = json.loads(line)
                if entry['event_type'] == 'test_event':
                    # Simulate tampering by modifying the data
                    entry['data']['test'] = 'tampered_data'
                temp.write(json.dumps(entry) + '\n')
                modified = True
        
        # Replace original with modified file
        os.replace(temp_file, audit_logger.log_file)
        
        # Verify integrity after modification
        integrity_after = audit_logger.verify_log_integrity()
        print(f"Integrity after modification: {'PASSED' if integrity_after else 'FAILED'}")
        print(f"Tampering {'was' if not integrity_after else 'was not'} detected")
        
    except Exception as e:
        print(f"Error during tampering test: {str(e)}")
    finally:
        # Clean up temp file if it exists
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print("✓ Test 5 completed\n")
    
    print("=== Test Summary ===")
    print("1. Event Logging: COMPLETED")
    print("2. Log Integrity Check: COMPLETED")
    print("3. Log Reading and Parsing: COMPLETED")
    print("4. Hash Chain Verification: COMPLETED")
    print("5. Tampering Detection: COMPLETED")

if __name__ == '__main__':
    with app.app_context():
        test_audit_logger()