# TrendFind/blueprints/auth.py

from __future__ import annotations

import os
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user

# Package-aware imports (avoid "ModuleNotFoundError")
from ..forms import RegisterForm, LoginForm
from ..models import User          # your models module should bind to the shared db from TrendFind
from .. import db, csrf            # reuse the one SQLAlchemy/CSRF instance created in TrendFind/__init__.py

# Celery task (adjust path if your task lives elsewhere)
# e.g. if you actually defined it in TrendFind/tasks/email.py, import that instead.
try:
    from ..email_utils import send_welcome_email  # must exist inside TrendFind/
except Exception:  # fall back: no async mail
    send_welcome_email = None

# ───────── Firebase Admin (init once, and only if key is present) ─────────
FIREBASE_ENABLED = False
try:
    import firebase_admin
    from firebase_admin import credentials, auth as firebase_auth

    firebase_key = os.environ.get("FIREBASE_KEY")
    if firebase_key:
        cred_dict = json.loads(firebase_key)
        pk = cred_dict.get("private_key", "")
        if "\\n" in pk:
            cred_dict["private_key"] = pk.replace("\\n", "\n")

        try:
            # Only initialize if there is no existing default app
            firebase_admin.get_app()
        except ValueError:
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)

        FIREBASE_ENABLED = True
except Exception:
    # Leave disabled if import/env invalid
    FIREBASE_ENABLED = False

bp = Blueprint("auth", __name__, url_prefix="/")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.profile"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data.lower()).first()
        if existing:
            flash("Email already registered", "warning")
            return redirect(url_for("auth.register"))

        user = User(name=form.name.data, email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        # Send welcome email (async if celery task is available)
        try:
            if send_welcome_email:
                if hasattr(send_welcome_email, "delay"):
                    send_welcome_email.delay(user.email, user.name)
                else:
                    send_welcome_email(user.email, user.name)
        except Exception:
            # Don't crash registration if email fails
            pass

        flash("Account created!", "success")
        return redirect(url_for("main.profile"))

    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.profile"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for("main.profile"))
        flash("Invalid credentials", "danger")

    return render_template("login.html", form=form)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("uid", None)
    session.pop("email", None)
    flash("Logged out", "info")
    return redirect(url_for("auth.login"))


# If this endpoint is called from a frontend via fetch/XHR without CSRF token,
# exempt it from CSRF (or supply the token from the client).
@csrf.exempt
@bp.route("/firebase-login", methods=["POST"])
def firebase_login():
    if not FIREBASE_ENABLED:
        return jsonify({"status": "error", "message": "Firebase not configured"}), 503

    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify({"status": "error", "message": "No token provided"}), 400

    try:
        decoded = firebase_auth.verify_id_token(token)
        uid = decoded.get("uid")
        email = decoded.get("email")
        name = decoded.get("name") or "User"
        if not email:
            return jsonify({"status": "error", "message": "Invalid token (no email)"}), 400

        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            user = User(name=name, email=email.lower())
            db.session.add(user)
            db.session.commit()

        login_user(user)
        session["uid"] = uid
        session["email"] = email.lower()
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401
