import os
from datetime import timedelta
get = os.getenv

class Base:
    SECRET_KEY            = get("FLASK_SECRET_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_SECURE  = True          # https only
    WTF_CSRF_ENABLED       = False         # DEV ONLY
    RECAPTCHA_PUBLIC_KEY   = get("RECAPTCHA_SITE_KEY")
    RECAPTCHA_PRIVATE_KEY  = get("RECAPTCHA_SECRET_KEY")

    # 3ʳᵈ-party creds
    EBAY_APP_ID            = get("EBAY_APP_ID")
    RAPIDAPI_KEY           = get("RAPIDAPI_KEY")
    GOOGLE_CLIENT_ID       = get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET   = get("GOOGLE_CLIENT_SECRET")
    STRIPE_SK              = get("STRIPE_SK_LIVE")
    MAIL_SERVER            = "smtp.gmail.com"
    MAIL_PORT              = 587
    MAIL_USE_TLS           = True
    MAIL_USERNAME          = get("MAIL_USERNAME")
    MAIL_PASSWORD          = get("MAIL_PASSWORD")

class Development(Base):
    SQLALCHEMY_DATABASE_URI = "sqlite:///dev.db"
    WTF_CSRF_TIME_LIMIT     = None        # no timeout while coding
    DEBUG                   = True

class Production(Base):
    SQLALCHEMY_DATABASE_URI = get("DATABASE_URL").replace("postgres://", "postgresql://", 1)
    WTF_CSRF_TIME_LIMIT     = 3600        # 1-hour CSRF lifespan
