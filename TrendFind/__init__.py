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

db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
redis_url = _raw + ("?ssl_cert_reqs=none" if "ssl_cert_reqs=none" not in _raw and "?" not in _raw else
                    "&ssl_cert_reqs=none" if "ssl_cert_reqs=none" not in _raw else "")
redis_client = Redis.from_url(redis_url)
limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url, default_limits=["200 per minute"])
celery = Celery(__name__, broker=redis_url)

def create_app(config_path: str | None = None):
    app = Flask(__name__, static_folder="static", template_folder="templates")

    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")          # e.g. "TrendFind.config.Productio33n"
        or "TrendFind.config.Production"      # because your config.py is inside TrendFind/
    )
    try:
        app.config.from_object(config_dotted)  # ← DO NOT call from_object('config.Development')
    except Exception as e:
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    db.init_app(app)
    migrate.init_app(app, db)
    login_m.init_app(app)
    app.login_manager = login_m
    login_m.login_view = "auth.login"
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    make_celery(app)

    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)
    register_custom_routes(app)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def _nf(e): return jsonify(error="Not Found"), 404

    return app
