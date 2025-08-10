# models.py
from db import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timedelta
import enum, json, secrets, hashlib

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
    name     = db.Column(db.String(120), nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False, index=True)
    pw_hash  = db.Column(db.String(256), nullable=False)
    joined   = db.Column(db.DateTime, default=datetime.utcnow)

    phone             = db.Column(db.String(32), unique=True, nullable=True, index=True)
    profile_pic_url   = db.Column(db.String(512), nullable=True)
    email_verified    = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified    = db.Column(db.Boolean, default=False, nullable=False)
    address           = db.Column(db.String(255))
    preferences       = db.Column(db.Text, default="{}")
    notify_email      = db.Column(db.Boolean, default=True, nullable=False)
    notify_sms        = db.Column(db.Boolean, default=True, nullable=False)
    updated_at        = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    stripe_customer_id = db.Column(db.String(120))

    def set_password(self, raw: str):
        # keep argon2 if your env has it; otherwise switch to pbkdf2:sha256
        self.pw_hash = generate_password_hash(raw, method="argon2")

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.pw_hash, raw)

class VerificationCode(db.Model):
    __tablename__ = "verification_codes"

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    user          = db.relationship("User", backref=db.backref("verification_codes", lazy="dynamic", cascade="all, delete-orphan"))
    purpose       = db.Column(db.Enum(Purpose), nullable=False)
    channel       = db.Column(db.Enum(Channel), nullable=False)

    code_hash     = db.Column(db.String(128), nullable=False)
    salt          = db.Column(db.String(16), nullable=False)
    expires_at    = db.Column(db.DateTime, nullable=False)
    attempts_left = db.Column(db.Integer, default=5, nullable=False)
    pending_json  = db.Column(db.Text, nullable=False)
    consumed      = db.Column(db.Boolean, default=False, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @staticmethod
    def _hash(code: str, salt: str) -> str:
        return hashlib.sha256((salt + code).encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, user, purpose: Purpose, channel: Channel, pending: dict, ttl_minutes: int = 10):
        # Invalidate older unconsumed codes of same purpose/channel
        db.session.query(cls).filter_by(
            user_id=user.id,
            purpose=purpose,
            channel=channel,
            consumed=False
        ).update({"consumed": True})
        db.session.commit()
        # 6-digit code
        code = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(8)
        obj = cls(
            user=user,
            purpose=purpose,
            channel=channel,
            code_hash=cls._hash(code, salt),
            salt=salt,
            expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
            pending_json=json.dumps(pending),
        )
        db.session.add(obj)
        db.session.commit()
        return code, obj

    def verify(self, code_input: str) -> bool:
        if self.consumed or datetime.utcnow() > self.expires_at or self.attempts_left <= 0:
            return False
        ok = (self.code_hash == self._hash(code_input, self.salt))
        if not ok:
            self.attempts_left -= 1
            db.session.commit()
        return ok

    def consume(self):
        self.consumed = True
        db.session.commit()
