# backend/security/input_validator.py

import re
import html
import bleach
from datetime import datetime
import ipaddress

# SR-07: Input validation and sanitization to prevent XSS, SQL injection etc.

class InputValidator:
    def __init__(self):
        self.allowed_html_tags = ['b', 'i', 'em', 'strong', 'p', 'br']
        self.allowed_html_attributes = {}

        self.patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'voter_id': re.compile(r'^[A-Z0-9]{8,12}$'),
            'candidate_id': re.compile(r'^CAND_[A-Z0-9]{6}$'),
            'sql_injection': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b', re.IGNORECASE),
            'xss_script': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            'xss_event': re.compile(r'\bon\w+\s*=', re.IGNORECASE)
        }

    def sanitize_string(self, input_str, max_length=255):
        if not isinstance(input_str, str):
            raise ValueError("Input must be a string")
        if len(input_str) > max_length:
            input_str = input_str[:max_length]

        sanitized = html.escape(input_str)
        sanitized = re.sub(self.patterns['xss_script'], '', sanitized)
        sanitized = re.sub(self.patterns['xss_event'], '', sanitized)

        sanitized = bleach.clean(sanitized, tags=self.allowed_html_tags, attributes=self.allowed_html_attributes, strip=True)
        return sanitized.strip()

    def validate_email(self, email):
        return isinstance(email, str) and bool(self.patterns['email'].match(email))

    def validate_voter_id(self, voter_id):
        return isinstance(voter_id, str) and bool(self.patterns['voter_id'].match(voter_id))

    def validate_candidate_id(self, candidate_id):
        return isinstance(candidate_id, str) and bool(self.patterns['candidate_id'].match(candidate_id))

    def check_sql_injection(self, input_str):
        if not isinstance(input_str, str):
            return False
        if self.patterns['sql_injection'].search(input_str):
            return True
        return False

    def validate_vote_data(self, vote_data):
        if not isinstance(vote_data, dict):
            raise ValueError("Vote data must be a dictionary")

        required_fields = ['voter_id', 'candidate_id', 'timestamp']
        for field in required_fields:
            if field not in vote_data:
                raise ValueError(f"Missing required vote field: {field}")

        voter_id = str(vote_data['voter_id'])
        if not self.validate_voter_id(voter_id) or self.check_sql_injection(voter_id):
            raise ValueError("Invalid or potentially dangerous voter_id")

        candidate_id = str(vote_data['candidate_id'])
        if not self.validate_candidate_id(candidate_id) or self.check_sql_injection(candidate_id):
            raise ValueError("Invalid or potentially dangerous candidate_id")

        try:
            datetime.fromisoformat(str(vote_data['timestamp']))
        except Exception:
            raise ValueError("Invalid timestamp format")

        # Optional preferences list validation
        if 'preferences' in vote_data:
            preferences = vote_data['preferences']
            if not isinstance(preferences, list) or len(preferences) > 20:
                raise ValueError("Invalid preferences list")
            for p in preferences:
                if not self.validate_candidate_id(str(p)):
                    raise ValueError(f"Invalid candidate_id in preferences: {p}")

        return vote_data
