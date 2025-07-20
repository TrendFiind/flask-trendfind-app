# app/google_oauth.py
from flask import Blueprint, redirect, session, url_for, flash
from authlib.integrations.flask_client import OAuth
import os

oauth = OAuth()
google_bp = Blueprint("google_oauth", __name__)

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"}
    )

@google_bp.route("/login/google")
def google_login():
    redirect_uri = url_for("google_oauth.google_authorize", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@google_bp.route("/login/google/authorize")
def google_authorize():
    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.parse_id_token(token)

    if not userinfo:
        flash("Google login failed.", "error")
        return redirect(url_for("auth.login"))

    email = userinfo["email"].lower()
    name = userinfo.get("name", "User")

    from app.db import get_db  # adjust based on your structure
    db = get_db()
    user = db.fetchone("SELECT * FROM users WHERE email = ?", (email,))

    if not user:
        db.execute("INSERT INTO users (email, name) VALUES (?, ?)", (email, name))
        db.commit()
        user = db.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        db.execute("INSERT INTO user_stats (user_id) VALUES (?)", (user["id"],))
        db.commit()

    session.update(user_id=user["id"], user_name=name, user_email=email)
    db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
    db.commit()

    return redirect(url_for("profile"))
