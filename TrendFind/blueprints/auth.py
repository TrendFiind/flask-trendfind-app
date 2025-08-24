import logging
import secrets

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_dance.contrib.google import google

from forms import RegisterForm, LoginForm
from models import User, db
from email_utils import send_welcome_email

# 🔐 Firebase Admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

import os
import json

firebase_key = os.environ.get("FIREBASE_KEY")
cred_dict = json.loads(firebase_key)

# 🔥 FIX the private_key to convert '\\n' into real newlines
if "\\n" in cred_dict.get("private_key", ""):
    cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")

cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

bp = Blueprint("auth", __name__, url_prefix="/")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email already registered", "warning")
            return redirect(url_for("auth.register"))

        user = User(name=form.name.data, email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        session.update(user_id=user.id, user_name=user.name, user_email=user.email)
        current_app.logger.info("new user registered: %s", user.email)
        send_welcome_email.delay(user.email, user.name)
        flash("Account created!", "success")
        return redirect(url_for("profile"))

    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            session.update(user_id=user.id, user_name=user.name, user_email=user.email)
            current_app.logger.info("user login via password: %s", user.email)
            flash("Logged in", "success")
            return redirect(url_for("profile"))
        current_app.logger.warning("failed login attempt for %s", form.email.data.lower())
        flash("Invalid credentials", "danger")

    return render_template("login.html", form=form)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    current_app.logger.info("user logged out: %s", current_user.email)
    flash("Logged out", "info")
    return redirect(url_for("auth.login"))


@bp.route("/login/google")
def login_google():
    """Handle Google OAuth login."""
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info", "danger")
        return redirect(url_for("auth.login"))

    info = resp.json()
    email = info.get("email")
    name = info.get("name", "Google User")
    if not email:
        flash("Email not available", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email)
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
        db.session.commit()
        current_app.logger.info("new user created via google oauth: %s", email)

    login_user(user)
    session.update(user_id=user.id, user_name=user.name, user_email=user.email)
    current_app.logger.info("user login via google: %s", email)
    return redirect(url_for("profile"))


# ✅ Firebase-based login endpoint
@bp.route("/firebase-login", methods=["POST"])
def firebase_login():
    token = request.json.get("token")

    if not token:
        return jsonify({"status": "error", "message": "No token provided"}), 400

    try:
        # Verify token using Firebase Admin SDK
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token.get("uid")
        email = decoded_token.get("email")
        name = decoded_token.get("name", "User")

        if not email:
            return jsonify({"status": "error", "message": "Invalid token - no email"}), 400

        # Optional: Store or fetch user from your database
        user = User.query.filter_by(email=email).first()
        if not user:
            # Auto-create user for Firebase login
            user = User(name=name, email=email)
            db.session.add(user)
            db.session.commit()

        # Use Flask-Login to set login session
        login_user(user)
        session.update(user_id=user.id, user_name=user.name, user_email=user.email)

        current_app.logger.info("user login via firebase: %s", email)

        # Optional: Store in Flask session (redundant if using Flask-Login)
        session['uid'] = uid
        session['email'] = email

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        current_app.logger.warning("firebase login error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 401

