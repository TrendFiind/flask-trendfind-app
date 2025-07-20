# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from celery import Celery
from .celery_app import make_celery

# ───── Extension instances ─────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

celery = Celery(__name__, broker='redis://localhost:6379/0')

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/minute"]
)

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
    app.login_manager = login_m             # ✅ fix for Flask-Login
    login_m.login_view = "auth.login"
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    make_celery(app)

    # ─── Blueprints ───
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    # ─── Google OAuth ───
    from .google_oauth import google_bp
    csrf.exempt(google_bp)
    app.register_blueprint(google_bp, url_prefix="/login")

    return app

