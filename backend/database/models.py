# backend/database/models.py

from backend import db
from datetime import datetime

# SR-XX: Database schema for main entities

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)  # SR-06 Argon2 hashed passwords
    role = db.Column(db.String(20), nullable=False)
    mfa_secret = db.Column(db.String(64), nullable=False)  # SR-01 MFA secret key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    votes = db.relationship('Vote', backref='voter', lazy=True)

class Candidate(db.Model):
    __tablename__ = 'candidates'
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(50), nullable=True)

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    vote_data = db.Column(db.Text, nullable=False)  # Encrypted + signed vote package
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Vote {self.id} by User {self.voter_id}>'
