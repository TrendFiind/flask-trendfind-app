import os
import logging
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

# ───── Extension instances ─────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ───── Handle REDIS_URL safely with SSL cert override ──────────────
raw_redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
if "ssl_cert_reqs=none" not in raw_redis_url:
    redis_url = raw_redis_url + ("?ssl_cert_reqs=none" if "?" not in raw_redis_url else "&ssl_cert_reqs=none")
else:
    redis_url = raw_redis_url

# Use Redis object (e.g. if you want to use Redis directly)
redis_client = Redis.from_url(redis_url)

# Flask-Limiter setup
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri=redis_url  # Needs the modified URL string
)

# Create celery base instance
celery = Celery(__name__, broker=redis_url)

# ───── Application Factory ─────────────────────────────
def create_app(config="config.Development"):
    app = Flask(
        __name__,
        static_folder="../static",
        template_folder="templates"
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
    make_celery(app)

    # ─── Register Blueprints ───
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)
    # ─── Logging ───
    log_handler = RotatingFileHandler("trendfind.log", maxBytes=1_000_000, backupCount=10)
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s [in %(module)s:%(lineno)d]"
    ))
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)

    return app
