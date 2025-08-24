# TrendFind/__init__.py
import os
from flask import Flask, jsonify, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

# Celery lives in its own module to avoid circular imports
from .celery_app import celery, make_celery

# ---------- Flask extensions (singletons) ----------
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ---------- Redis / Limiter ----------
_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
if "ssl_cert_reqs=none" not in _raw:
    redis_url = _raw + ("?ssl_cert_reqs=none" if "?" not in _raw else "&ssl_cert_reqs=none")
else:
    redis_url = _raw

redis_client = Redis.from_url(redis_url)
limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url, default_limits=["200 per minute"])


def create_app(config_path: str | None = None) -> Flask:
    """
    Factory to create the Flask app. Use in Procfile:
    gunicorn "TrendFind:create_app()"
    """
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Config: env override or default to package config
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")          # e.g. "TrendFind.config.Production"
        or "TrendFind.config.Production"
    )
    try:
        app.config.from_object(config_dotted)
    except Exception as e:
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

    # Heroku / reverse proxy safety
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_m.init_app(app)
    login_m.login_view = "auth.login"

    # Bind Celery to this Flask app
    make_celery(app)

    # User loader (avoids circulars by importing inside factory)
    from .models import User  # noqa: WPS433

    @login_m.user_loader
    def load_user(uid: str):
        return db.session.get(User, int(uid))

    # Blueprints
    from .blueprints.auth import bp as auth_bp  # noqa: WPS433
    app.register_blueprint(auth_bp)

    # Optional: Google OAuth blueprint (if you have it)
    try:
        from .google_oauth import google_bp, init_oauth, register_custom_routes  # noqa: WPS433
        init_oauth(app, url_prefix="/tfauth")
        csrf.exempt(google_bp)
        register_custom_routes(app)
    except Exception:
        # Keep running even if OAuth isn't configured yet
        pass

    # Health & fallbacks
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.get("/")
    def _root():
        # Send people somewhere useful
        if hasattr(login_m, "login_view"):
            return redirect(url_for(login_m.login_view))
        return jsonify(message="TrendFind up"), 200

    @app.errorhandler(404)
    def _nf(e):  # noqa: ARG001
        return jsonify(error="Not Found"), 404

    return app


# Re-export commonly used singletons for easy importing:
__all__ = ["db", "mail", "celery", "login_m", "csrf", "limiter", "create_app"]
