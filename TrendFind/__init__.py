# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate   import Migrate
from flask_login     import LoginManager
from flask_mail      import Mail
from flask_wtf.csrf  import CSRFProtect
from flask_limiter   import Limiter
from flask_limiter.util import get_remote_address

from .celery_app import make_celery   # celery helper (see earlier code)

# ───── Extension instances (created once) ──────────────────────────
db       = SQLAlchemy()
migrate  = Migrate()
login_m  = LoginManager()
mail     = Mail()
csrf     = CSRFProtect()

# NOTE:  Limiter 3.x expects *key_func* as first arg.
# Do NOT pass `app` positionally or you’ll get the TypeError.
limiter  = Limiter(
    key_func=get_remote_address,           # one source of truth
    default_limits=["200/minute"]          # tweak as needed
)

# ───── Application factory ─────────────────────────────────────────
def create_app(config="config.Development"):
    """Create and configure a Flask application instance."""
    app = Flask(
        __name__,
        static_folder="../static",          # adjust if your static path differs
        template_folder="templates"
    )
    app.config.from_object(config)

    # ── initialise extensions with the app context
    db.init_app(app)
    migrate.init_app(app, db)
    login_m.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)                  # attach limiter *after* config is loaded
    make_celery(app)                       # give Celery the app context

    # login settings
    login_m.login_view = "auth.login"

    # Blueprint registration  ──────────────────────────────────────────────
    from .auth.routes import auth_bp
    app.register_blueprint(auth_bp
    from .blueprints.auth import bp as auth_bp
    from .blueprints.main import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

        # Google OAuth (Flask-Dance or your custom blueprint)
    from .google_oauth import google_bp
    csrf.exempt(google_bp)      # ③ let OAuth callback bypass Flask-WTF CSRF
    app.register_blueprint(google_bp, url_prefix="/login")


    return app
