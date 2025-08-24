# ───── Application Factory ─────────────────────────────
def create_app(config_path=None):
    app = Flask(
        __name__,
        static_folder="static",      # don't walk up a dir on Heroku
        template_folder="templates"
    )

    # Prefer explicit path from arg or FLASK_CONFIG; otherwise default to Production
    config_dotted = (
        config_path
        or os.getenv("FLASK_CONFIG")           # e.g. "TrendFind.config.Production" or "config.Production"
        or "TrendFind.config.Production"       # safest default if your config.py is inside TrendFind/
    )

    try:
        app.config.from_object(config_dotted)
    except Exception as e:
        # Give a clear error in logs if import path is wrong
        raise RuntimeError(f"Failed to import config '{config_dotted}': {e}")

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
