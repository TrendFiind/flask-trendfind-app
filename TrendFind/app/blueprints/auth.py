from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from app.forms import RegisterForm, LoginForm
from app.models import User, db
from ..email_utils import send_welcome_email

# 🔐 Firebase Admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

# Init Firebase (ensure serviceAccountKey.json is in your root directory)
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

bp = Blueprint("auth", __name__, url_prefix="/")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.profile"))

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
        send_welcome_email.delay(user.email, user.name)
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
    session.pop('uid', None)
    session.pop('email', None)
    flash("Logged out", "info")
    return redirect(url_for("auth.login"))


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

        # Optional: Store in Flask session (redundant if using Flask-Login)
        session['uid'] = uid
        session['email'] = email

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401

