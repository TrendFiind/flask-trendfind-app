# app/google_oauth.py

import os
from flask import redirect, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import login_user

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_url="/tfauth/google/authorized"
)

def init_oauth(app, url_prefix="/tfauth"):
    app.register_blueprint(google_bp, url_prefix=url_prefix)

def register_custom_routes(app):
    @app.route("/login/google/custom")
    def google_custom_login():
        if not google.authorized:
            return redirect(url_for("google.login"))

        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            return "Failed to fetch user info", 400

        user_info = resp.json()
        email = user_info.get("email")
        if not email:
            return "No email found", 400

        # 🔁 Import inside the function to avoid circular import
        from .models import User
        from . import db

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        return redirect(url_for("main.dashboard"))
