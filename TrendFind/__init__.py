# TrendFind/__init__.py
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

from .celery_app import make_celery
from .google_oauth import google_bp, init_oauth, register_custom_routes

# ── Extensions ──────────────────────────────────────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ── Redis URL (prefer TLS on Heroku) ────────────────────────────────────────
_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
if "ssl_cert_reqs=none" not in _raw:
    redis_url = _raw + ("?ssl_cert_reqs=none" if "?" not in _raw else "&ssl_cert_reqs=none")
else:
    redis_url = _raw

redis_client = Redis.from_url(redis_url)

# Flask-Limiter (backed by Redis)
limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url, default_limits=["200 per minute"])

# Celery base (binds to Flask app in make_celery)
celery = Celery(__name__, broker=redis_url)

# ── Application Factory ─────────────────────────────────────────────────────
def create_app(config_path: str | None = None):
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # honor explicit arg, then env var, else safe default
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")              # e.g. "TrendFind.config.Production"
        or "TrendFind.config.Production"          # ← your config.py lives inside TrendFind/
    )
    try:
        app.config.from_object(config_dotted)
    except Exception as e:
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

    # Heroku proxy headers (scheme, IP, etc.)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # ── Init extensions ────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)

    login_m.init_app(app)
    app.login_manager = login_m
    login_m.login_view = "auth.login"

    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    # Celery bound to Flask app/context
    make_celery(app)

    # ── Blueprints / OAuth ────────────────────────────────────────────────
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)
    register_custom_routes(app)

    # ── Healthcheck & basic errors ───────────────────────────────────────
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="Not Found"), 404

    return app
