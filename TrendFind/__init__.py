# TrendFind/__init__.py
from __future__ import annotations

import os
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from celery import Celery

# ───── Extensions (singletons; do NOT duplicate elsewhere) ─────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ───── Redis URL (Heroku TLS + cert quirks) ────────────────────────
_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
if "ssl_cert_reqs=none" not in _raw:
    redis_url = _raw + ("?ssl_cert_reqs=none" if "?" not in _raw else "&ssl_cert_reqs=none")
else:
    redis_url = _raw

redis_client = Redis.from_url(redis_url)

# Flask-Limiter (backed by Redis)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_url,
    default_limits=["200 per minute"],
)

# Celery base (the real binding happens in make_celery(app))
celery = Celery(__name__, broker=redis_url)

# Import these AFTER defining extensions
from .celery_app import make_celery
from .google_oauth import google_bp, init_oauth, register_custom_routes


def create_app(config_path: str | None = None):
    """
    Gunicorn entrypoint uses:  gunicorn "TrendFind:create_app()"
    """
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Prefer explicit path or FLASK_CONFIG env; default to package Production config
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")                 # e.g. "TrendFind.config.Production"
        or "TrendFind.config.Production"
    )
    try:
        app.config.from_object(config_dotted)
    except Exception as e:
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

    # Honor X-Forwarded-* on Heroku
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # ───── Init extensions ───────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_m.init_app(app)
    app.login_manager = login_m
    login_m.login_view = "auth.login"

    # Bind Celery to Flask context
    make_celery(app)

    # ───── Blueprints ────────────────────────────────────────────────
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    # Google OAuth blueprint + routes
    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)         # if your OAuth callback posts without CSRF
    register_custom_routes(app)

    # ───── Flask-Login user loader (import models AFTER db exists) ──
    from .models import User

    @login_m.user_loader
    def load_user(user_id: str):
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

    # ───── Health & basic error handling ────────────────────────────
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify(error="Not Found"), 404

    return app
