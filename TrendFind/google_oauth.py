import os
from flask_dance.contrib.google import make_google_blueprint

# Google OAuth blueprint used by Flask-Dance.
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_url="/login/google",
)


def init_oauth(app, url_prefix="/tfauth"):
    """Register the Google OAuth blueprint."""
    app.register_blueprint(google_bp, url_prefix=url_prefix)
