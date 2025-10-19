from backend import db, app
from backend.database.models import User
from backend.authentication.mfa import MFAService
from backend.encryption.password_hashing import PasswordHashingService

with app.app_context():
    mfa = MFAService()
    pwhash = PasswordHashingService()
    email = "aecemployee@example.com"
    password = "TestUser1234!"
    role = "aec_employee" # Use "administrator" for admin
    mfa_secret = mfa.generate_secret_key(email)
    print(f"User email: {email}")
    print(f"Plaintext password: {password}")
    print(f"MFA secret (for Google Authenticator): {mfa_secret}")
    mfa_qr = mfa.generate_qr_code(mfa_secret, email)
    print(f"QR code (base64): {mfa_qr[:30]}... (scan using Google Authenticator)")
    hashpw = pwhash.hash_password(password)
    user = User(email=email, password_hash=hashpw, role=role, mfa_secret=mfa_secret)
    db.session.add(user)
    db.session.commit()
    print("User created successfully.")