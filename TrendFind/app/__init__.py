# app/__init__.py

import os
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
from .google_oauth import google_bp, init_oauth, register_custom_routes

# ───── Extension instances ─────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# ✅ Use a Redis client with SSL cert validation disabled (Heroku-compatible)
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_client = Redis.from_url(redis_url, ssl_cert_reqs=None)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri=redis_client
)

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
    register_custom_routes(app)

    return app
