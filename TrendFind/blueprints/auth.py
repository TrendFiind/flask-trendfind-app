## TrendFind/blueprints/auth.py
from __future__ import annotations

import os
import json
from jinja2 import TemplateNotFound
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, jsonify, session, current_app
)
from flask_login import login_user, logout_user, login_required, current_user

# ✅ use package-relative imports (your files live inside TrendFind/)
from ..forms import RegisterForm, LoginForm
from ..models import User
from .. import db, csrf
from ..email_utils import send_welcome_email  # best-effort; wrapped with try/except

# ─── Firebase Admin (optional) ────────────────────────────────────────────────
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

bp = Blueprint("auth", __name__)  # no url_prefix so "/" is handled here

def _ensure_firebase():
    """Initialize Firebase Admin once, if FIREBASE_KEY is set."""
    if firebase_admin._apps:
        return
    key_json = os.environ.get("FIREBASE_KEY")
    if not key_json:
        return
    try:
        cred_dict = json.loads(key_json)
        pk = cred_dict.get("private_key")
        if isinstance(pk, str) and "\\n" in pk:
            cred_dict["private_key"] = pk.replace("\\n", "\n")
        firebase_admin.initialize_app(credentials.Certificate(cred_dict))
    except Exception as e:
        # Don't take the app down if Firebase isn't configured right
        current_app.logger.warning("Firebase init skipped: %s", e)

# ─── Routes ───────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    """Fixes your 404 at root by redirecting somewhere real."""
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))
    return redirect(url_for("auth.login"))

@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = RegisterForm()
    if form.validate_on_submit():
        email = (form.email.data or "").strip().lower()
        if not email:
            flash("Email is required.", "warning")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("auth.register"))

        user = User(name=form.name.data.strip(), email=email)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        # Best-effort welcome email (async if Celery works, else sync, else skip)
        try:
            send_welcome_email.delay(user.email, user.name)  # type: ignore[attr-defined]
        except Exception:
            try:
                send_welcome_email(user.email, user.name)
            except Exception as e:
                current_app.logger.warning("Welcome email failed: %s", e)

        flash("Account created!", "success")
        return redirect(url_for("auth.profile"))

    try:
        return render_template("register.html", form=form)
    except TemplateNotFound:
        return jsonify(message="register page", errors=form.errors), 200

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = LoginForm()
    if form.validate_on_submit():
        email = (form.email.data or "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            flash("Logged in.", "success")
            return redirect(url_for("auth.profile"))
        flash("Invalid email or password.", "danger")

    try:
        return render_template("login.html", form=form)
    except TemplateNotFound:
        return jsonify(message="login page", errors=form.errors), 200

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("uid", None)
    session.pop("email", None)
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))

@bp.route("/profile")
@login_required
def profile():
    """Simple profile; won’t 500 if you don’t have a template yet."""
    try:
        return render_template("profile.html", user=current_user)
    except TemplateNotFound:
        return jsonify(message=f"Welcome, {current_user.name}"), 200

# JSON endpoint for Firebase auth; must be CSRF-exempt when CSRFProtect is enabled
@bp.route("/firebase-login", methods=["POST"])
@csrf.exempt
def firebase_login():
    _ensure_firebase()

    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify(status="error", message="No token provided"), 400

    try:
        decoded = firebase_auth.verify_id_token(token)
        uid = decoded.get("uid")
        email = (decoded.get("email") or "").lower()
        name = decoded.get("name") or "User"

        if not email:
            return jsonify(status="error", message="Invalid token: no email"), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        session["uid"] = uid
        session["email"] = email
        return jsonify(status="ok"), 200
    except Exception as e:
        return jsonify(status="error", message=str(e)), 401
