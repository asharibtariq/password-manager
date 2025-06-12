from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Boolean, DateTime
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    mfa_secret = db.Column(db.String(50), nullable=True)
    encrypted_vault = db.Column(db.Text, nullable=True)
    password_last_changed = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(Boolean, default=False)
    verification_token = db.Column(String(120), nullable=True)
    token_expiry = db.Column(DateTime, nullable=True)

    def __repr__(self): 
        return f"<User {self.email}>"
    

class PasswordVault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Should be encrypted
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('vault_entries', lazy=True))
