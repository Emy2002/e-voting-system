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

    def verify_totp(self, secret, token):
        """Verify TOTP token; allow 30 seconds window"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)

    def generate_backup_codes(self, count=10):
        """Generate backup recovery codes"""
        codes = []
        for _ in range(count):
            code = '-'.join([secrets.token_hex(4) for _ in range(2)])
            codes.append(code)
        return codes


# Usage example (for internal tests)
if __name__ == "__main__":
    mfa_service = MFAService()
    secret = mfa_service.generate_secret_key('user123')
    print("Secret:", secret)
    qr = mfa_service.generate_qr_code(secret, 'user@example.com')
    print("QR Code (base64):", qr)
    valid = mfa_service.verify_totp(secret, input("Enter TOTP code: "))
    print("Valid TOTP:", valid)
