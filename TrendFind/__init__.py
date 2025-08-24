# TrendFind/__init__.py
import os
from flask import Flask, jsonify, render_template, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from celery import Celery

from .celery_app import make_celery
from .google_oauth import google_bp, init_oauth, register_custom_routes

# ─── Shared extensions ──────────────────────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
login_m = LoginManager()
mail = Mail()
csrf = CSRFProtect()

_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
redis_url = (
    _raw
    if "ssl_cert_reqs=none" in _raw
    else (_raw + ("?ssl_cert_reqs=none" if "?" not in _raw else "&ssl_cert_reqs=none"))
)
redis_client = Redis.from_url(redis_url)
limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url, default_limits=["200 per minute"])
celery = Celery(__name__, broker=redis_url)

def create_app(config_path: str | None = None):
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Config (keep your existing class; just make sure the dotted path is correct)
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")
        or "TrendFind.config.Production"
    )
    app.config.from_object(config_dotted)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_m.init_app(app)
    app.login_manager = login_m
    # 👇 keep the old endpoint name for redirects like /login?next=...
    login_m.login_view = "login"
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    make_celery(app)

    # Blueprints
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    # Google OAuth (your module handles creating/attaching the blueprint)
    init_oauth(app, url_prefix="/tfauth")
    csrf.exempt(google_bp)
    register_custom_routes(app)

    # ────────────────────────────────────────────────────────────────
    # 1) Public pages defined directly (so templates can use url_for('faq') etc.)
    #    Create simple handlers ONLY if those endpoints don't already exist.
    #    This avoids changing templates or nav links.
    # ────────────────────────────────────────────────────────────────
    if "home" not in app.view_functions:
        @app.get("/", endpoint="home")
        def home():
            if current_user.is_authenticated:
                return redirect(url_for("profile"))  # old endpoint name preserved below
            return redirect(url_for("login"))

    if "faq" not in app.view_functions:
        @app.get("/faq", endpoint="faq")
        def faq():
            return render_template("faq.html")

    if "plan_details" not in app.view_functions:
        @app.get("/plan-details", endpoint="plan_details")
        def plan_details():
            return render_template("plan-details.html")

    if "contact_us" not in app.view_functions:
        @app.get("/contact-us", endpoint="contact_us")
        def contact_us():
            return render_template("contact-us.html")

    if "saved_products" not in app.view_functions:
        @app.get("/saved-products", endpoint="saved_products")
        def saved_products():
            # Fill with real data later if needed
            return render_template("saved-products.html", products=[])

    # ────────────────────────────────────────────────────────────────
    # 2) Alias endpoints so old names keep working (no template changes)
    #    These map plain names -> auth blueprint views.
    # ────────────────────────────────────────────────────────────────
    def _alias(path: str, alias_endpoint: str, target_endpoint: str, methods: tuple[str, ...]):
        """Safely add an alias if it isn't already registered."""
        if alias_endpoint not in app.view_functions and target_endpoint in app.view_functions:
            app.add_url_rule(path, endpoint=alias_endpoint,
                             view_func=app.view_functions[target_endpoint],
                             methods=list(methods))

    # auth routes (adjust paths if your auth blueprint uses different ones)
    _alias("/login",    "login",    "auth.login",    ("GET", "POST"))
    _alias("/register", "register", "auth.register", ("GET", "POST"))
    _alias("/logout",   "logout",   "auth.logout",   ("GET",))
    _alias("/profile",  "profile",  "auth.profile",  ("GET",))

    # If your templates call `url_for('tfauth.login')`, ensure that alias exists.
    # Try to map it to whatever the Google blueprint registered as its login view.
    # Common names are 'google.login' or already 'tfauth.login'.
    if "tfauth.login" not in app.view_functions:
        for cand in ("google.login", "oauth.login", "google_bp.login"):
            if cand in app.view_functions:
                # make sure the route exists too
                app.add_url_rule("/tfauth/login", endpoint="tfauth.login",
                                 view_func=app.view_functions[cand], methods=["GET"])
                break

    # Health + 404
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def _nf(e):  # minimal JSON 404 to aid debugging
        return jsonify(error="Not Found"), 404

    return app
