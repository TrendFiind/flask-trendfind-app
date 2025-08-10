# config.py
import os
from datetime import timedelta
from pathlib import Path

get = os.getenv

def _bool(val, default=False):
    if val is None:
        return default
    return str(val).lower() in {"1", "true", "yes", "on"}

class Base:
    # --- Core ---
    SECRET_KEY = get("FLASK_SECRET_KEY") or "CHANGE_ME_SUPER_RANDOM"  # set in prod
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///app.db"  # overridden per-env

    # --- Sessions & cookies ---
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_SECURE = True          # https only
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = True

    # --- CSRF ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600            # 1 hour default (override in dev if needed)

    # --- ReCAPTCHA (if you use WTForms recaptcha somewhere) ---
    RECAPTCHA_PUBLIC_KEY  = get("RECAPTCHA_SITE_KEY")
    RECAPTCHA_PRIVATE_KEY = get("RECAPTCHA_SECRET_KEY")

    # --- 3rd-party creds (existing) ---
    EBAY_APP_ID          = get("EBAY_APP_ID")
    RAPIDAPI_KEY         = get("RAPIDAPI_KEY")
    GOOGLE_CLIENT_ID     = get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = get("GOOGLE_CLIENT_SECRET")
    STRIPE_SK            = get("STRIPE_SK_LIVE") or get("STRIPE_SK")  # fallback

    # --- Email: SMTP (your current setup) ---
    MAIL_SERVER   = get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT     = int(get("MAIL_PORT", "587"))
    MAIL_USE_TLS  = _bool(get("MAIL_USE_TLS", "1"), True)
    MAIL_USE_SSL  = _bool(get("MAIL_USE_SSL", "0"), False)
    MAIL_USERNAME = get("MAIL_USERNAME")
    MAIL_PASSWORD = get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = get("EMAIL_FROM", get("MAIL_DEFAULT_SENDER", "no-reply@yourdomain.com"))

    # --- Optional: SendGrid/Twilio (only used if you wire them) ---
    SENDGRID_API_KEY = get("SENDGRID_API_KEY")
    TWILIO_ACCOUNT_SID = get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN  = get("TWILIO_AUTH_TOKEN")
    TWILIO_FROM        = get("TWILIO_FROM")  # E.164, e.g. +614xxxxxxxx

    # --- Rate limiting (Flask-Limiter) ---
    # Use Redis in prod if REDIS_URL is set; otherwise falls back to in-memory
    RATELIMIT_STORAGE_URI = get("RATELIMIT_STORAGE_URI") or get("REDIS_URL") or "memory://"
    # Default limits across the app; per-endpoint can override
    DEFAULT_RATELIMITS = [
        "200 per hour",
        "50 per 10 minute",
    ]

    # --- Uploads (avatars) ---
    AVATAR_MAX_MB = int(get("AVATAR_MAX_MB", "5"))
    AVATAR_DIR = get("AVATAR_DIR") or os.path.join("static", "uploads", "avatars")
    Path(AVATAR_DIR).mkdir(parents=True, exist_ok=True)

    # --- App meta ---
    APP_NAME = get("APP_NAME", "TrendFind")
    PREFERRED_URL_SCHEME = get("PREFERRED_URL_SCHEME", "https")

    # --- Talisman / Security headers (used by app factory) ---
    # Adjust CSP if you load assets from a CDN (add that domain to default-src/img-src/style-src/script-src).
    TALISMAN_FORCE_HTTPS = _bool(get("TALISMAN_FORCE_HTTPS", "1"), True)
    TALISMAN_CSP = {
        "default-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "script-src": ["'self'"],
    }

    # --- Misc flags ---
    JSON_SORT_KEYS = False

class Development(Base):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///dev.db"
    WTF_CSRF_TIME_LIMIT = None  # DEV ONLY (no expiry to make testing easier)
    TALISMAN_FORCE_HTTPS = False

class Production(Base):
    DEBUG = False
    # Heroku-style DATABASE_URL fix
    _db_url = get("DATABASE_URL")
    if _db_url and _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url or "sqlite:///prod.db"

    # Stronger defaults in prod
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    WTF_CSRF_TIME_LIMIT = 3600
    TALISMAN_FORCE_HTTPS = True

    # Optional: tell Flask about your domain (helps with URL building and cookies)
    # SERVER_NAME = get("SERVER_NAME")  # e.g. "app.trendfind.com"
