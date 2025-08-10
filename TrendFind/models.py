# models.py
from db import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timedelta
import enum, json, secrets, hashlib

# --- Enums for verification flow ---
class Channel(enum.Enum):
    email = "email"
    phone = "phone"
    both = "both"

class Purpose(enum.Enum):
    change_email = "change_email"
    change_phone = "change_phone"
    change_password = "change_password"

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(120), nullable=False)                 # keep as you had it
    email    = db.Column(db.String(120), unique=True, nullable=False, index=True)
    pw_hash  = db.Column(db.String(256), nullable=False)
    joined   = db.Column(db.DateTime, default=datetime.utcnow)

    # NEW: profile data that must persist
    phone             = db.Column(db.String(32), unique=True, nullable=True, index=True)
    profile_pic_url   = db.Column(db.String(512), nullable=True)

    # NEW: verification flags
    email_verified    = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified    = db.Column(db.Boolean, default=False, nullable=False)

    # NEW: keep track of updates
    updated_at        = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    stripe_customer_id = db.Column(db.String(120))

    def set_password(self, raw: str):
        # keep argon2 if your environment supports it; otherwise switch to pbkdf2:sha256
        self.pw_hash = generate_password_hash(raw, method="argon2")

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.pw_hash, raw)

# NEW: one-time codes for sensitive changes (email/phone/password)
class VerificationCode(db.Model):
    __tablename__ = "verification_codes"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    user        = db.relationship("User", backref=db.backref("verification_codes", lazy="dynamic", cascade="all, delete-orphan"))

    purpose     = db.Column(db.Enum(Purpose), nullable=False)
    channel     = db.Column(db.Enum(Channel), nullable=False)

    code_hash   = db.Column(db.String(128), nullable=False)     # store hash, never plaintext
    expires_at  = db.Column(db.DateTime, nullable=False)
    attempts_left = db.Column(db.Integer, default=5, nullable=False)

    # JSON payload of pending changes to apply if verification succeeds
    pending_json = db.Column(db.Text, nullable=False)

    consumed    = db.Column(db.Boolean, default=False, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # --- helpers ---
    @staticmethod
    def _hash(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, user, purpose: Purpose, channel: Channel, pending: dict, ttl_minutes: int = 10):
        # generate a 6-digit code, leading zeros allowed
        code = f"{secrets.randbelow(1_000_000):06d}"
        obj = cls(
            user=user,
            purpose=purpose,
            channel=channel,
            code_hash=cls._hash(code),
            expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
            pending_json=json.dumps(pending),
        )
        db.session.add(obj)
        db.session.commit()
        return code, obj

    def verify(self, code_input: str) -> bool:
        if self.consumed or datetime.utcnow() > self.expires_at or self.attempts_left <= 0:
            return False
        ok = (self.code_hash == self._hash(code_input))
        if not ok:
            self.attempts_left -= 1
            db.session.commit()
        return ok

    def consume(self):
        self.consumed = True
        db.session.commit()
