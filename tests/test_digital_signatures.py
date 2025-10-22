# import pytest
# from backend.encryption.digital_signatures import DigitalSignatureService

# @pytest.fixture
# def ds_service():
#     service = DigitalSignatureService()
#     service.generate_keypair()
#     return service


# def test_sign_and_verify_vote(ds_service):
#     vote_data = {"candidate": "Alice", "voter_id": "12345"}
    
#     signed_vote = ds_service.sign_vote(vote_data)
    
#     # Verify signature with service's public key
#     assert ds_service.verify_vote_signature(signed_vote) is True
    
#     # Tampered vote fails verification
#     tampered_vote = signed_vote.copy()
#     tampered_vote["vote_data"]["candidate"] = "Bob"
#     assert ds_service.verify_vote_signature(tampered_vote) is False


# def test_create_vote_receipt(ds_service):
#     vote_data = {"candidate": "Alice", "voter_id": "12345"}
#     signed_vote = ds_service.sign_vote(vote_data)
    
#     receipt = ds_service.create_vote_receipt(signed_vote)
#     assert isinstance(receipt, str)
    
#     # Decoding the receipt back should contain expected keys
#     import json, base64
#     decoded = json.loads(base64.b64decode(receipt).decode())
#     assert "vote_hash" in decoded
#     assert "timestamp" in decoded
#     assert "receipt_id" in decoded


# def test_load_private_key_and_generate(ds_service):
#     # Export and re-import private key
#     private_pem = ds_service.get_private_key_pem()
#     new_service = DigitalSignatureService()
#     new_service.load_private_key(private_pem)

#     vote_data = {"candidate": "Alice", "voter_id": "12345"}
#     signed_vote = new_service.sign_vote(vote_data)
    
#     # Verification works with public key
#     public_pem = new_service.get_public_key_pem()
#     assert new_service.verify_vote_signature(signed_vote, public_pem) is True
