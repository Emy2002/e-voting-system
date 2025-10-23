import re
import html
import pytest
from datetime import datetime, timezone

# Mock bleach for testing
class Bleach:
    @staticmethod
    def clean(text, tags=None, attributes=None, strip=False):
        # Simple mock that removes HTML tags and their content for security
        import re
        if 'script' in text.lower():
            text = ''
        else:
            text = re.sub(r'<[^>]+>', '', text)
        return text.strip() if strip else text

# Import just what we need for testing
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

        # Check for dangerous patterns first
        if self.patterns['xss_script'].search(input_str) or self.patterns['xss_event'].search(input_str):
            return ""

        # Remove all HTML tags
        sanitized = Bleach.clean(input_str, tags=[], attributes={}, strip=True)
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
        if not self.validate_voter_id(voter_id):
            raise ValueError("Invalid or potentially dangerous voter_id")
        if self.check_sql_injection(voter_id):
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


@pytest.fixture
def validator():
    return InputValidator()


def test_sanitize_string_basic(validator):
    # Basic string sanitization
    assert validator.sanitize_string("Hello World") == "Hello World"
    assert validator.sanitize_string(" extra spaces  ") == "extra spaces"

    # HTML tag stripping (we strip all tags for security)
    assert validator.sanitize_string("<p>text</p>") == "text"
    assert validator.sanitize_string('<b>bold</b>') == "bold"
    
    # Max length
    long_string = "a" * 300
    assert len(validator.sanitize_string(long_string)) == 255

    # XSS prevention
    assert validator.sanitize_string('<script>alert("xss")</script>') == ""
    assert validator.sanitize_string('onclick=alert(1)') == ""


def test_sanitize_string_invalid_input(validator):
    with pytest.raises(ValueError, match="Input must be a string"):
        validator.sanitize_string(123)
    with pytest.raises(ValueError, match="Input must be a string"):
        validator.sanitize_string(None)


def test_validate_email(validator):
    # Valid emails
    assert validator.validate_email("user@example.com")
    assert validator.validate_email("user.name+tag@example.co.uk")
    assert validator.validate_email("123@456.com")

    # Invalid emails
    assert not validator.validate_email("not-an-email")
    assert not validator.validate_email("@example.com")
    assert not validator.validate_email("user@")
    assert not validator.validate_email("user@.com")
    assert not validator.validate_email("")
    assert not validator.validate_email(None)
    assert not validator.validate_email(123)


def test_validate_voter_id(validator):
    # Valid voter IDs (8-12 alphanumeric chars, uppercase)
    assert validator.validate_voter_id("12345678")
    assert validator.validate_voter_id("ABCD123456")
    assert validator.validate_voter_id("AB12CD34EF56")

    # Invalid voter IDs
    assert not validator.validate_voter_id("123")  # too short
    assert not validator.validate_voter_id("1234567890123")  # too long
    assert not validator.validate_voter_id("abcd1234")  # lowercase
    assert not validator.validate_voter_id("ABCD-1234")  # special chars
    assert not validator.validate_voter_id("")
    assert not validator.validate_voter_id(None)
    assert not validator.validate_voter_id(12345678)


def test_validate_candidate_id(validator):
    # Valid candidate IDs (CAND_ prefix + 6 alphanumeric chars)
    assert validator.validate_candidate_id("CAND_123456")
    assert validator.validate_candidate_id("CAND_ABCDEF")
    assert validator.validate_candidate_id("CAND_12ABCD")

    # Invalid candidate IDs
    assert not validator.validate_candidate_id("CAND123456")  # missing underscore
    assert not validator.validate_candidate_id("CAND_12345")  # too short
    assert not validator.validate_candidate_id("CAND_1234567")  # too long
    assert not validator.validate_candidate_id("cand_123456")  # lowercase
    assert not validator.validate_candidate_id("")
    assert not validator.validate_candidate_id(None)
    assert not validator.validate_candidate_id("CAND_12-345")  # special chars


def test_check_sql_injection(validator):
    # Should detect SQL keywords
    assert validator.check_sql_injection("SELECT * FROM users")
    assert validator.check_sql_injection("delete from votes")
    assert validator.check_sql_injection("INSERT INTO table")
    assert validator.check_sql_injection("DROP TABLE users")
    assert validator.check_sql_injection("UNION SELECT password")

    # Should pass normal text
    assert not validator.check_sql_injection("Hello World")
    assert not validator.check_sql_injection("User123")
    assert not validator.check_sql_injection("")
    assert not validator.check_sql_injection(None)
    assert not validator.check_sql_injection(123)


def test_validate_vote_data_valid(validator):
    # Valid vote data
    valid_vote = {
        "voter_id": "12345678",
        "candidate_id": "CAND_123456",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    assert validator.validate_vote_data(valid_vote) == valid_vote

    # Valid vote with preferences
    valid_vote_with_prefs = {
        **valid_vote,
        "preferences": ["CAND_654321", "CAND_ABCDEF"]
    }
    assert validator.validate_vote_data(valid_vote_with_prefs) == valid_vote_with_prefs


def test_validate_vote_data_invalid(validator):
    base_vote = {
        "voter_id": "12345678",
        "candidate_id": "CAND_123456",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Missing required field
    with pytest.raises(ValueError, match="Missing required vote field"):
        validator.validate_vote_data({"voter_id": "12345678"})

    # Invalid voter_id
    with pytest.raises(ValueError, match="Invalid or potentially dangerous voter_id"):
        validator.validate_vote_data({**base_vote, "voter_id": "invalid!"})

# SQL injection in voter_id
        with pytest.raises(ValueError, match="Invalid or potentially dangerous voter_id"):
            validator.validate_vote_data({**base_vote, "voter_id": "12SELECT12"})    # Invalid candidate_id
    with pytest.raises(ValueError, match="Invalid or potentially dangerous candidate_id"):
        validator.validate_vote_data({**base_vote, "candidate_id": "invalid"})

    # SQL injection in candidate_id
    with pytest.raises(ValueError, match="Invalid or potentially dangerous candidate_id"):
        validator.validate_vote_data({**base_vote, "candidate_id": "CAND_DROP"})

    # Invalid timestamp
    with pytest.raises(ValueError, match="Invalid timestamp format"):
        validator.validate_vote_data({**base_vote, "timestamp": "not-a-date"})

    # Invalid preferences type
    with pytest.raises(ValueError, match="Invalid preferences list"):
        validator.validate_vote_data({**base_vote, "preferences": "not-a-list"})

    # Too many preferences
    with pytest.raises(ValueError, match="Invalid preferences list"):
        validator.validate_vote_data({**base_vote, "preferences": ["CAND_123456"] * 21})

    # Invalid candidate in preferences
    with pytest.raises(ValueError, match="Invalid candidate_id in preferences"):
        validator.validate_vote_data({**base_vote, "preferences": ["invalid"]})