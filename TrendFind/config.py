# If this file is TrendFind/config.py then import path is TrendFind.config.Production etc.
import os
from datetime import timedelta

get = os.getenv

def _pg_url():
    """
    Robustly read Heroku DATABASE_URL and normalize scheme for SQLAlchemy.
    Returns None if not set.
    """
    url = get("DATABASE_URL")
    if not url:
        return None
    # Heroku can still hand out legacy 'postgres://'
    return url.replace("postgres://", "postgresql://", 1)

class Base:
    # SECURITY
    SECRET_KEY = get("FLASK_SECRET_KEY") or "dev-override-change-this"
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # override in Dev if needed
    SESSION_COOKIE_SECURE = get("SESSION_COOKIE_SECURE", "1") == "1"  # default secure in prod
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Optional: pre-ping to avoid "server closed the connection unexpectedly" after idling
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }

    # Mail
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = get("MAIL_USERNAME")
    MAIL_PASSWORD = get("MAIL_PASSWORD")

    # 3rd-party creds (used conditionally in your code)
    EBAY_APP_ID = get("EBAY_APP_ID")
    RAPIDAPI_KEY = get("RAPIDAPI_KEY")
    GOOGLE_CLIENT_ID = get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = get("GOOGLE_CLIENT_SECRET")
    STRIPE_SK = get("STRIPE_SK_LIVE") or get("STRIPE_SK_TEST")

class Development(Base):
    DEBUG = True
    WTF_CSRF_TIME_LIMIT = None  # DEV ONLY
    # Local sqlite file in repo root (works everywhere)
    SQLALCHEMY_DATABASE_URI = "sqlite:///dev.db"
    # Dev over http? make cookies work
    SESSION_COOKIE_SECURE = False

class Production(Base):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = _pg_url() or "sqlite:///fallback.db"
    # If you *really* want to hard-fail when DB is missing, do:
    # if not _pg_url():
    #     raise RuntimeError("DATABASE_URL is not set")
