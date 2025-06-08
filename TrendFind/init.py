from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate   import Migrate
from flask_login     import LoginManager
from flask_mail      import Mail
from flask_wtf.csrf  import CSRFProtect
from flask_limiter   import Limiter
from flask_limiter.util import get_remote_address
from .celery_app import make_celery

db       = SQLAlchemy()
migrate  = Migrate()
login_m  = LoginManager()
mail     = Mail()
csrf     = CSRFProtect()
limiter  = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

def create_app(config="config.Development"):
    app = Flask(__name__, static_folder="../static", template_folder="templates")
    app.config.from_object(config)

    # init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_m.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    make_celery(app)

    login_m.login_view = "auth.login"

    # blueprints
    from .blueprints.auth import bp as auth_bp
    from .blueprints.main import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    return app

