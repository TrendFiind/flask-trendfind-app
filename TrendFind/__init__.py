import os
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from celery import Celery

from .celery_app import make_celery
from .google_oauth import google_bp, init_oauth

# ───── Base paths ─────────────────────────────
BASE_DIR = Path(__file__).resolve().parent  # .../TrendFind

# ───── Extension instances ───────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ───── REDIS_URL with TLS on Heroku ──────────
_raw = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
# If Heroku provides redis:// but TLS is required, flip to rediss://
if _raw.startswith("redis://") and os.environ.get("REDIS_TLS", "1") == "1":
    redis_url = _raw.replace("redis://", "rediss://", 1)
else:
    redis_url = _raw

# Redis client (allow self-signed on Heroku)
redis_client = (Redis.from_url(redis_url, ssl_cert_reqs=None)
                if redis_url.startswith("rediss://")
                else Redis.from_url(redis_url))

# Flask-Limiter storage in Redis
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri=redis_url
)

# Celery single instance (configured in make_celery)
celery = Celery(__name__, broker=redis_url)

# ───── Application Factory ───────────────────
def create_app(config="config.Development"):
    app = Flask(
        __name__,
        static_folder=str(BASE_DIR / "static"),
        template_folder=str(BASE_DIR / "templates")
    )
    app.config.from_object(config)

    # ─── Initialise extensions ───
    db.init_app(app)
    migrate.init_app(app, db)
    login_m.init_app(app)
    app.login_manager = login_m
    login_m.login_view = "auth.login"

    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    # Bind Celery to this app (no import needed; celery is defined above)
    make_celery(app, celery)

    # ─── Register Blueprints ───
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    # OAuth (Google)
    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)

    # ─── Logging ───
    if os.environ.get("DYNO"):  # Heroku: log to stdout
        stream = logging.StreamHandler()
        stream.setLevel(logging.INFO)
        app.logger.addHandler(stream)
    else:
        log_path = BASE_DIR / "trendfind.log"
        fh = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=10)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(module)s:%(lineno)d]"
        ))
        app.logger.addHandler(fh)

    app.logger.setLevel(logging.INFO)
    app.logger.info("App booted. CWD=%s ROOT=%s", os.getcwd(), app.root_path)
    return app
