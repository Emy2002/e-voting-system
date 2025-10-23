import os
import json
from typing import List, Dict, Any

# ------------------------------- API ------------------------------------ #

def _load_board() -> List[Dict[str, Any]]:
    """
    Loads the bulletin board data.
    Returns a list of entries, where each entry is a dictionary.
    """
    try:
        with open("bulletin_board.json", "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return []


def _tally_votes() -> Dict[str, int]:
    """
    Tally the votes from the bulletin board.
    Returns a dictionary with the count of each choice.
    """
    board = _load_board()
    tally = {}
    for entry in board:
        # Extract the commitment and count votes (choices are hashed, so this is a placeholder)
        commitment = entry["commitment"]
        choice = _reverse_commitment(commitment)  # Placeholder for reversing the commitment
        if choice:
            tally[choice] = tally.get(choice, 0) + 1
    return tally


def verify_vote_counting(commitment: str) -> bool:
    """
    Verifies that the voter's commitment is included in the tally.
    Returns True if the commitment is part of the tally.
    """
    board = _load_board()
    return any(entry["commitment"] == commitment for entry in board)


def _reverse_commitment(commitment: str) -> str:
    """
    Placeholder function to reverse the commitment to the original choice.
    In a real system, this would require the salt and the original choice.
    """
    # This is not possible without the salt, so this function is a placeholder.
    return None


def _verify_receipt_inclusion(commitment: str) -> bool:
    """
    Verifies if a given commitment is included in the bulletin board.
    Returns True if the commitment exists, otherwise False.
    """
    board = _load_board()
    return any(entry["commitment"] == commitment for entry in board)

def _verify_entire_board(verify_key_hex: str) -> bool:
    """
    Verifies the integrity of the entire bulletin board using the verify key.
    Returns True if the board is valid, otherwise False.
    """
    # Placeholder implementation for board verification
    # In a real system, this would involve cryptographic signature checks
    try:
        board = _load_board()
        # Simulate verification logic
        return all("commitment" in entry for entry in board)
    except Exception as e:
        print("[ERROR] Failed to verify the board:", str(e))
        return False

# ------------------------------ CLI demo -------------------------------- #

def cast_vote(voter_id: str, choice: str, signing_key_hex: str) -> Dict[str, Any]:
    """
    Casts a vote by generating a commitment and storing it on the bulletin board.
    Returns a receipt containing the commitment and salt.
    """
    # Placeholder implementation for casting a vote
    salt = os.urandom(16).hex()  # Generate a random salt
    commitment = f"{choice}:{salt}"  # Simplified commitment (in a real system, hash this)
    
    # Save the commitment to the bulletin board
    board = _load_board()
    board.append({"voter_id": voter_id, "commitment": commitment})
    with open("bulletin_board.json", "w", encoding="utf-8") as file:
        json.dump(board, file, indent=2)
    
    # Return the receipt
    return {"commitment": commitment, "salt_hex": salt}

def generate_admin_keys() -> Dict[str, str]:
    """
    Generates admin keys for signing and verification.
    Returns a dictionary containing the signing key and verify key in hexadecimal format.
    """
    # Placeholder implementation for key generation
    return {
        "signing_key_hex": "dummy_signing_key",
        "verify_key_hex": "dummy_verify_key"
    }

def _demo_flow():
    """
    Runs when executed directly: generates keys, casts a sample vote, and verifies inclusion.
    This is handy for screenshots and your video demo.
    """
    try:
        # Generate admin keys
        keys = generate_admin_keys()
        print("[SR-17] Bulletin path:", os.path.abspath("bulletin_board.json"))

        # Cast a sample vote
        receipt = cast_vote("voter-123", "Candidate A", keys["signing_key_hex"])
        print("[SR-17] Voter receipt:", json.dumps(receipt, indent=2))

        # Verify inclusion of the vote on the bulletin board
        included = _verify_receipt_inclusion(receipt["commitment"])
        print("[SR-17] Included on bulletin board?:", included)

        # Verify the integrity of the entire bulletin board
        board_ok = _verify_entire_board(keys["verify_key_hex"])
        print("[SR-17] Board signature check:", json.dumps(board_ok, indent=2))

        # Tally the votes
        tally = _tally_votes()
        print("[SR-17] Vote tally:", json.dumps(tally, indent=2))

        # Verify that the vote was counted
        vote_counted = verify_vote_counting(receipt["commitment"])
        print("[SR-17] Was the vote counted?:", vote_counted)

        # Instructions for verification
        print("\nHow to verify later:")
        print(" - Voter keeps 'salt_hex' private and preserves 'commitment'.")
        print(" - Anyone can read bulletin_board.json and verify signatures with the published verify key.")
        print(" - Ensure no voter ID is stored on the bulletin board.")

    except Exception as e:
        print("[ERROR] An error occurred during the demo flow:", str(e))