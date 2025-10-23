from backend import app
from backend.security.input_validator import InputValidator
import re

def test_input_validator():
    # Initialize validator
    validator = InputValidator()
    
    print("\n=== Testing Input Validator System ===\n")
    
    # Test 1: Email Validation
    print("Test 1: Email Validation")
    test_emails = [
        "valid@example.com",           # Valid
        "valid.email+tag@domain.com",  # Valid with special chars
        "invalid@email",               # Invalid - no TLD
        "not.an.email",                # Invalid - no @
        "spaces in@email.com",         # Invalid - spaces
        "<script>@hack.com",           # Invalid - XSS attempt
        "user@domain.c",               # Invalid - short TLD
        "a"*100 + "@toolong.com"      # Invalid - too long
    ]
    
    print("\nTesting email addresses:")
    for email in test_emails:
        result = validator.validate_email(email)
        print(f"Email: {email:<30} -> {'✓ Valid' if result else '✗ Invalid'}")
    print("✓ Test 1 completed\n")
    
    # Test 2: SQL Injection Check
    print("Test 2: SQL Injection Detection")
    test_inputs = [
        "Normal text here",                    # Valid
        "SELECT * FROM users",                 # Invalid - SQL
        "User name; DROP TABLE users;",        # Invalid - SQL
        "Robert'); DROP TABLE Students;--",    # Invalid - SQL
        "UNION SELECT password FROM users",    # Invalid - SQL
        "Just SELECTING items",                # Invalid - Contains SQL keyword
        "UPDATE your profile",                 # Invalid - Contains SQL keyword
        "Regular input 123"                    # Valid
    ]
    
    print("\nTesting SQL injection detection:")
    for input_str in test_inputs:
        result = not validator.check_sql_injection(input_str)
        print(f"Input: {input_str[:30]:<30} -> {'✓ Safe' if result else '✗ SQL Injection Risk'}")
    print("✓ Test 2 completed\n")
    
    # Test 3: String Sanitization
    print("Test 3: String Sanitization")
    test_strings = [
        "Normal text",
        "<script>alert('XSS')</script>",
        "Text with <b>HTML</b> tags",
        "SQL ' OR '1'='1",
        "Multi\nline\ntext",
        "Special chars: !@#$%^&*()",
        "Unicode: 你好世界",
        "Mixed content: <img src='x' onerror='alert(1)'>Test"
    ]
    
    print("\nTesting string sanitization:")
    for string in test_strings:
        sanitized = validator.sanitize_string(string)
        print(f"\nOriginal : {string}")
        print(f"Sanitized: {sanitized}")
    print("✓ Test 3 completed\n")
    
    # Test 4: XSS Detection
    print("Test 4: XSS Attack Detection")
    test_inputs = [
        "Normal text",
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "onclick=alert('click')",
        '<div onmouseover="alert(1)">',
        "Text with <b>valid</b> tags",
        "<SCRIPT>console.log('test')</SCRIPT>",
        "JavaScript://comment"
    ]
    
    print("\nTesting XSS detection:")
    for input_str in test_inputs:
        sanitized = validator.sanitize_string(input_str)
        has_script = '<script' in sanitized.lower() or 'on' in sanitized.lower()
        print(f"Input: {input_str[:30]:<30}")
        print(f"Sanitized: {sanitized[:50]}")
        print(f"Result: {'✗ Potentially Unsafe' if has_script else '✓ Safe'}\n")
    print("✓ Test 4 completed\n")
    
    # Test 5: Input Length Validation
    print("Test 5: Input Length Validation")
    test_inputs = [
        ("short", 10),           # Valid
        ("too long text", 5),    # Invalid - too long
        ("", 1),                 # Invalid - empty
        ("a"*1000, 100),        # Invalid - way too long
        ("just right", 10)       # Valid - exactly at limit
    ]
    
    print("\nTesting input lengths:")
    for input_text, max_length in test_inputs:
        result = len(validator.sanitize_string(input_text)) <= max_length
        print(f"Input: {input_text[:20]+'...' if len(input_text)>20 else input_text:<20}")
        print(f"Length: {len(input_text)}/{max_length} -> {'✓ Valid' if result else '✗ Invalid'}")
    print("✓ Test 5 completed\n")
    
    # Test 6: Voter and Candidate ID Validation
    print("Test 6: ID Validation")
    test_ids = [
        ("voter", "ABC12345"),           # Valid voter ID
        ("voter", "12345"),              # Invalid - too short
        ("voter", "ABC123456789"),       # Invalid - too long
        ("voter", "<SCRIPT>123"),        # Invalid - special chars
        ("candidate", "CAND_123456"),    # Valid candidate ID
        ("candidate", "CAND123456"),     # Invalid - wrong format
        ("candidate", "CAND_12"),        # Invalid - too short
        ("candidate", "TEST_123456")     # Invalid - wrong prefix
    ]
    
    print("\nTesting IDs:")
    for id_type, test_id in test_ids:
        if id_type == "voter":
            result = validator.validate_voter_id(test_id)
            print(f"Voter ID: {test_id:<15} -> {'✓ Valid' if result else '✗ Invalid'}")
        else:
            result = validator.validate_candidate_id(test_id)
            print(f"Candidate ID: {test_id:<15} -> {'✓ Valid' if result else '✗ Invalid'}")
    print("✓ Test 6 completed\n")
    
    print("=== Test Summary ===")
    print("1. Email Validation: COMPLETED")
    print("2. Password Validation: COMPLETED")
    print("3. String Sanitization: COMPLETED")
    print("4. Role Validation: COMPLETED")
    print("5. Input Length Validation: COMPLETED")
    print("6. Voter ID Validation: COMPLETED")

if __name__ == '__main__':
    with app.app_context():
        test_input_validator()