from backend import app, db
from backend.database.models import User
from backend.encryption.data_encryption import DataEncryptionService
import json
from datetime import datetime

def test_encryption_with_stored_users():
    # Create encryption service with a test key
    test_key = 'x' * 32  # 32-byte test key
    svc = DataEncryptionService(master_key=test_key)
    
    print("\n=== Testing Encryption with Stored Users ===\n")
    
    # Get all users from database
    users = User.query.all()
    
    if not users:
        print("No users found in the database!")
        return
        
    print(f"Found {len(users)} users in database.")
    
    for user in users:
        print(f"\n--- Testing with user: {user.email} (Role: {user.role}) ---")
        
        # Create test vote data for this user
        vote_data = {
            'voter_email': user.email,
            'candidate': 'Test Candidate',
            'timestamp': datetime.utcnow().isoformat(),
            'election_id': 'test_election_2025'
        }
        
        try:
            # Encrypt vote using user's ID
            encrypted = svc.encrypt_vote(vote_data, voter_id=str(user.id))
            print(f"\nEncrypted vote data (first 50 chars):")
            print(f"{encrypted[:50]}...")
            
            # Decrypt and verify
            decrypted = svc.decrypt_vote(encrypted)
            print(f"\nDecrypted vote data:")
            print(json.dumps(decrypted, indent=2))
            
            # Verify voter anonymity (show hashed voter ID)
            print(f"\nVoter hash (for anonymity verification): {decrypted.get('voter_hash')}")
            
        except Exception as e:
            print(f"\nError processing user {user.email}: {str(e)}")
            continue
            
        print("\n✓ Encryption/decryption successful for this user")

if __name__ == '__main__':
    with app.app_context():
        test_encryption_with_stored_users()