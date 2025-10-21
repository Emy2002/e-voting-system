# backend/authentication/mfa.py

import pyotp
import qrcode
from io import BytesIO
import base64
import secrets

# SR-01: Multi-Factor Authentication (MFA) using TOTP and QR codes

class MFAService:
    def __init__(self):
        self.issuer_name = "Electronic Voting Platform"

    def generate_secret_key(self, user_id):
        """Generate a base32 secret key for TOTP"""
        secret = pyotp.random_base32()
        return secret

    def generate_totp_secret(self):
        """Generate a base32 secret key for TOTP (alias for generate_secret_key)"""
        return self.generate_secret_key('user')

    def generate_qr_code(self, secret, user_email):
        """Generate base64 encoded QR code image for authenticator app"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user_email, issuer_name=self.issuer_name)

        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_bytes = buffered.getvalue()
        img_base64 = base64.b64encode(img_bytes).decode()

        return img_base64

    def get_totp_uri(self, username, secret):
        """Return the otpauth URI for TOTP setup"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=self.issuer_name)

    def verify_totp(self, secret, token, window=0):
        """Verify TOTP token; allow custom window (default 0 for strict)"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)

    def generate_backup_codes(self, count=10):
        """Generate backup recovery codes"""
        codes = []
        for _ in range(count):
            code = '-'.join([secrets.token_hex(4) for _ in range(2)])
            codes.append(code)
        return codes


# Add module-level functions for test compatibility

def generate_totp_secret():
    """Module-level function for test compatibility"""
    return MFAService().generate_totp_secret()

def get_totp_uri(username, secret):
    """Module-level function for test compatibility"""
    return MFAService().get_totp_uri(username, secret)

def verify_totp(secret, token, window=0):
    """Module-level function for test compatibility"""
    return MFAService().verify_totp(secret, token, window=window)


# Usage example (for internal tests)
if __name__ == "__main__":
    mfa_service = MFAService()
    secret = mfa_service.generate_secret_key('user123')
    print("Secret:", secret)
    qr = mfa_service.generate_qr_code(secret, 'user@example.com')
    print("QR Code (base64):", qr)
    valid = mfa_service.verify_totp(secret, input("Enter TOTP code: "))
    print("Valid TOTP:", valid)
