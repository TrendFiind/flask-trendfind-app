
from db import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(120), nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False, index=True)
    pw_hash  = db.Column(db.String(256), nullable=False)
    joined   = db.Column(db.DateTime, default=datetime.utcnow)

    stripe_customer_id = db.Column(db.String(120))
    # add more profile fields as needed

    def set_password(self, raw):
        self.pw_hash = generate_password_hash(raw, method="argon2")

    def check_password(self, raw):
        return check_password_hash(self.pw_hash, raw)
