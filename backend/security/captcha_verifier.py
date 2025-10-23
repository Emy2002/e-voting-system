# backend/security/captcha_verifier.py

# System Requirement: Implement CAPTCHA mechanisms to mitigate automated bot-based attacks
# during registration or login processes.

import random
import string
import time
import hashlib
import hmac
from typing import Tuple, Dict, List
from datetime import datetime, timedelta


class CaptchaVerifier:
    def __init__(self):
        """
        Initialize the CAPTCHA verifier with security settings optimized for
        login/registration protection.
        """
        # Secure in-memory storage for CAPTCHA challenges (replace with a KV store if needed)
        self.captcha_store: Dict[str, Dict] = {}

        # Security controls
        self.captcha_timeout: int = 180        # 3 minutes timeout
        self.max_attempts: int = 3             # Max attempts per CAPTCHA before blocking
        self.min_captcha_length: int = 6       # Minimum length of CAPTCHA text

        # Track attempts per IP to rate-limit brute force (keeps timestamps of failures)
        self.ip_attempt_tracking: Dict[str, List[datetime]] = {}

    def generate_captcha(self, ip_address: str) -> Tuple[str, str, bool]:
        """
        Generate a new CAPTCHA challenge for registration/login protection.

        Args:
            ip_address: The IP address of the requesting client

        Returns:
            Tuple[str, str, bool]: (captcha_id, captcha_text, is_allowed)
        """
        # Check if IP is not rate limited
        if not self._check_ip_allowed(ip_address):
            return "", "", False

        # Generate a cryptographically strong captcha ID
        captcha_id = hashlib.sha256(
            (str(time.time()) + ip_address).encode("utf-8")
        ).hexdigest()[:32]

        # Generate complex CAPTCHA text with mixed case and limited specials
        chars = string.ascii_letters + string.digits + "@#$%"
        captcha_text = "".join(random.SystemRandom().choices(chars, k=self.min_captcha_length))

        # Store the captcha with security metadata
        self.captcha_store[captcha_id] = {
            "text": captcha_text,
            "timestamp": datetime.utcnow(),
            "attempts": 0,
            "ip_address": ip_address,
            "is_used": False,
        }

        return captcha_id, captcha_text, True

    def verify_captcha(self, captcha_id: str, user_input: str, ip_address: str) -> bool:
        """
        Verify a CAPTCHA response for login/registration protection.

        Args:
            captcha_id: The ID of the CAPTCHA to verify
            user_input: The user's CAPTCHA response
            ip_address: The IP address of the requesting client

        Returns:
            bool: True if verification successful, False otherwise
        """
        # Basic validation
        if not captcha_id or not user_input or not ip_address:
            return False

        # Check if captcha exists
        if captcha_id not in self.captcha_store:
            self._track_failed_attempt(ip_address)
            return False

        captcha_data = self.captcha_store[captcha_id]
        current_time = datetime.utcnow()

        # Security checks
        if (
            captcha_data["is_used"]  # Prevent replay
            or captcha_data["ip_address"] != ip_address  # Prevent sharing
            or current_time - captcha_data["timestamp"] > timedelta(seconds=self.captcha_timeout)  # Expired
            or captcha_data["attempts"] >= self.max_attempts  # Too many tries
        ):
            self._track_failed_attempt(ip_address)
            del self.captcha_store[captcha_id]
            return False

        # Increment attempt counter
        captcha_data["attempts"] += 1

        # Constant-time, case-insensitive comparison to reduce timing side-channels
        is_valid = self._constant_time_compare(user_input, captcha_data["text"])

        if is_valid:
            # Mark as used to prevent replay attacks and clear IP failures
            captcha_data["is_used"] = True
            self._clear_ip_attempts(ip_address)
        else:
            self._track_failed_attempt(ip_address)

        return is_valid

    def _check_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP is allowed to generate new CAPTCHA based on previous attempts."""
        attempts = self.ip_attempt_tracking.get(ip_address, [])
        if len(attempts) >= 10:
            # If oldest of the last 10 failures is within the last hour -> block
            if datetime.utcnow() - attempts[0] < timedelta(hours=1):
                return False
            # Otherwise, clear old attempts
            self.ip_attempt_tracking[ip_address] = []
        return True

    def _track_failed_attempt(self, ip_address: str):
        """Track failed attempts by IP address."""
        lst = self.ip_attempt_tracking.setdefault(ip_address, [])
        lst.append(datetime.utcnow())
        # Keep only last 10 attempts
        self.ip_attempt_tracking[ip_address] = lst[-10:]

    def _clear_ip_attempts(self, ip_address: str):
        """Clear tracked attempts for an IP after successful verification."""
        if ip_address in self.ip_attempt_tracking:
            del self.ip_attempt_tracking[ip_address]

    def _constant_time_compare(self, val1: str, val2: str) -> bool:
        """
        Perform constant-time comparison to mitigate timing attacks.
        Comparison is case-insensitive (CAPTCHAs are often shown case-insensitively).
        """
        # Normalize case to compare without leaking length/position info
        return hmac.compare_digest(val1.lower(), val2.lower())

    def cleanup_expired_captchas(self):
        """Remove expired CAPTCHAs and clean up old IP tracking entries."""
        current_time = datetime.utcnow()

        # Cleanup expired CAPTCHAs
        expired_ids = [
            cid for cid, data in self.captcha_store.items()
            if current_time - data["timestamp"] > timedelta(seconds=self.captcha_timeout)
        ]
        for cid in expired_ids:
            del self.captcha_store[cid]

        # Cleanup stale IP failure timestamps (> 1 hour)
        for ip in list(self.ip_attempt_tracking.keys()):
            recent = [
                ts for ts in self.ip_attempt_tracking[ip]
                if current_time - ts < timedelta(hours=1)
            ]
            if recent:
                self.ip_attempt_tracking[ip] = recent
            else:
                del self.ip_attempt_tracking[ip]


# Example usage demonstrating login protection
def main():
    verifier = CaptchaVerifier()

    # Simulate login attempt
    def simulate_login_attempt(ip_address: str, simulate_correct: bool = True):
        # Generate a CAPTCHA for login
        captcha_id, captcha_text, is_allowed = verifier.generate_captcha(ip_address)

        if not is_allowed:
            print(f"Login blocked - too many attempts from IP: {ip_address}")
            return

        print(f"Login CAPTCHA Challenge: {captcha_text}")

        # Simulate user input (correct or incorrect based on parameter)
        user_input = captcha_text if simulate_correct else "WRONG"
        print(f"User entered: {user_input}")

        # Verify the CAPTCHA
        if verifier.verify_captcha(captcha_id, user_input, ip_address):
            print("CAPTCHA verified - proceeding with login!")
        else:
            print("CAPTCHA verification failed - login blocked!")

    # Simulate legitimate login attempt
    print("\nSimulating legitimate login attempt...")
    simulate_login_attempt("192.168.1.100", True)

    # Simulate bot attack with multiple wrong attempts
    print("\nSimulating bot attack...")
    attack_ip = "10.0.0.1"
    for _ in range(12):  # Try more than allowed attempts
        simulate_login_attempt(attack_ip, False)
        time.sleep(0.1)  # Small delay between attempts


if __name__ == "__main__":
    main()