# app/google_oauth.py
import os
from flask import Blueprint, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import login_user
from .models import User  # adjust if your model is elsewhere
from . import db

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_url="/tfauth/google/authorized",  # match url_prefix
    name="tfauth"  # avoid 'google_auth.login' collision
)

def init_oauth(app, url_prefix="/tfauth"):
    app.register_blueprint(google_bp, url_prefix=url_prefix)

@google_bp.route("/login/google")
def login():
    if not google.authorized:
        return redirect(url_for("google_auth.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Failed to fetch user info", 400

    user_info = resp.json()
    email = user_info["email"]
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("main.dashboard"))  # adjust as needed
