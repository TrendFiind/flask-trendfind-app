# TrendFind/blueprints/auth.py
import os
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user

from TrendFind import db
from TrendFind.models import User
from TrendFind.forms import RegisterForm, LoginForm

# Optional email task
try:
    from TrendFind.email_utils import send_welcome_email
except Exception:  # keep the app running even if Celery isn't ready yet
    send_welcome_email = None

bp = Blueprint("auth", __name__, url_prefix="")

# ---------- (Optional) Firebase Admin ----------
FIREBASE_KEY = os.environ.get("FIREBASE_KEY")
firebase_ok = False
if FIREBASE_KEY:
    try:
        import firebase_admin
        from firebase_admin import credentials, auth as firebase_auth

        cred_dict = json.loads(FIREBASE_KEY)
        if "\\n" in cred_dict.get("private_key", ""):
            cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")

        cred = credentials.Certificate(cred_dict)
        if not firebase_admin._apps:  # type: ignore[attr-defined]
            firebase_admin.initialize_app(cred)
        firebase_ok = True
    except Exception:
        firebase_ok = False

# ---------- Routes ----------
@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "warning")
            return redirect(url_for("auth.register"))

        user = User(name=form.name.data.strip(), email=email)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        if send_welcome_email:
            try:
                send_welcome_email.delay(user.email, user.name)
            except Exception:
                pass

        flash("Account created!", "success")
        return redirect(url_for("auth.profile"))

    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.profile"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for("auth.profile"))
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


@bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html")  # make a simple template or change target


# Wrapper route to start Google OAuth (if configured)
@bp.route("/google-login")
def google_login():
    # If your OAuth blueprint is named "google" (common with authlib), this will work:
    try:
        return redirect(url_for("google.login"))
    except Exception:
        flash("Google login is not configured.", "warning")
        return redirect(url_for("auth.login"))


# Firebase-based login endpoint (optional)
@bp.route("/firebase-login", methods=["POST"])
def firebase_login():
    if not firebase_ok:
        return jsonify({"status": "error", "message": "Firebase not configured"}), 400

    token = request.json.get("token")
    if not token:
        return jsonify({"status": "error", "message": "No token provided"}), 400

    from firebase_admin import auth as firebase_auth  # safe: imported only if configured

    try:
        decoded = firebase_auth.verify_id_token(token)
        uid = decoded.get("uid")
        email = decoded.get("email")
        name = decoded.get("name", "User")

        if not email:
            return jsonify({"status": "error", "message": "Invalid token - no email"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        session["uid"] = uid
        session["email"] = email
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401
