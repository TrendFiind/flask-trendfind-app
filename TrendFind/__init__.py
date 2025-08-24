# TrendFind/__init__.py

import os
import logging
from logging.config import dictConfig

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

# ---- Local modules ----
from .celery_app import make_celery
from .google_oauth import google_bp, init_oauth, register_custom_routes

# ───────────────── Extensions (singletons) ─────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ---- Redis URL (Heroku Redis often uses rediss:// + requires ssl_cert_reqs=none) ----
_raw_redis = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
if "ssl_cert_reqs=none" not in _raw_redis:
    REDIS_URL = _raw_redis + ("?ssl_cert_reqs=none" if "?" not in _raw_redis else "&ssl_cert_reqs=none")
else:
    REDIS_URL = _raw_redis

redis_client = Redis.from_url(REDIS_URL)

# Flask-Limiter (store in Redis)
limiter = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL, default_limits=["200 per minute"])

# Celery base (actual binding happens inside create_app via make_celery)
celery = Celery(__name__, broker=REDIS_URL)


def _setup_logging():
    # Gunicorn provides its own handlers in prod; align levels + add a fallback for local/dev.
    dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {"format": "[%(asctime)s] %(levelname)s in %(name)s: %(message)s"},
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            },
        },
        "root": {"level": os.getenv("LOG_LEVEL", "INFO"), "handlers": ["wsgi"]},
    })


# ─────────────── Application Factory ───────────────
def create_app(config_path: str | None = None):
    _setup_logging()

    app = Flask(
        __name__,
        static_folder="static",     # keep inside package for Heroku
        template_folder="templates"
    )

    # Honor explicit arg, then env var, else safe prod default (adjust if config.py is at repo root)
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")                # e.g. "TrendFind.config.Production"
        or "TrendFind.config.Production"
    )

    try:
        app.config.from_object(config_dotted)
    except Exception as e:
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

    # Trust proxy headers (Heroku router / load balancers)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Jinja & JSON niceties
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.jinja_env.auto_reload = bool(app.config.get("DEBUG"))

    # ─── Init extensions ───
    db.init_app(app)
    migrate.init_app(app, db)

    login_m.init_app(app)
    app.login_manager = login_m
    login_m.login_view = "auth.login"

    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    # Bind Celery app context & config
    make_celery(app)

    # ─── Blueprints / OAuth ───
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)
    register_custom_routes(app)

    # ─── Health & error handlers ───
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify(error="Not Found"), 404

    @app.errorhandler(500)
    def _server_error(e):
        app.logger.exception("Unhandled exception")
        return jsonify(error="Internal Server Error"), 500

    return app
