# profile.py
import json, os
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, User, VerificationCode, Purpose, Channel
from notifiers import send_email, send_sms

bp = Blueprint("profile", __name__, url_prefix="/profile")

UPLOAD_DIR = os.path.join("static", "uploads", "avatars")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}

def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def current_user():
    # Replace with your auth loader (Flask-Login or your own)
    from flask import g
    return getattr(g, "user", None)

@bp.get("/")
def profile_view():
    user = current_user()
    if not user:
        return redirect(url_for("auth.login"))
    return render_template("profile.html", user=user)

@bp.post("/save-basic")
def save_basic():
    """Save fields that do NOT require verification: name only (and other non-sensitive)."""
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "not_authenticated"}), 401

    name = (request.form.get("name") or "").strip()
    if len(name) > 120:
        return jsonify({"ok": False, "error": "name_too_long"}), 400

    user.name = name or None
    db.session.commit()
    return jsonify({"ok": True, "message": "Saved."})

@bp.post("/upload-avatar")
def upload_avatar():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "not_authenticated"}), 401

    file = request.files.get("avatar")
    if not file or file.filename == "":
        return jsonify({"ok": False, "error": "no_file"}), 400
    if not _allowed(file.filename):
        return jsonify({"ok": False, "error": "bad_extension"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filename = f"user_{user.id}_{int(datetime.utcnow().timestamp())}_{secure_filename(file.filename)}"
    path = os.path.join(UPLOAD_DIR, filename)
    file.save(path)

    user.profile_pic_url = "/" + path.replace("\\", "/")
    db.session.commit()
    return jsonify({"ok": True, "url": user.profile_pic_url})

@bp.post("/request-change")
def request_change():
    """
    Start a sensitive change:
      - change email: requires code to NEW email
      - change phone: requires code to NEW phone
      - change password: requires codes to BOTH current email and phone (if phone exists)
    """
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "not_authenticated"}), 401

    change_type = request.form.get("type")
    payload = {}

    if change_type == "email":
        new_email = (request.form.get("new_email") or "").strip().lower()
        if not new_email or "@" not in new_email:
            return jsonify({"ok": False, "error": "invalid_email"}), 400

        # Fail if email already taken
        if User.query.filter(User.email == new_email, User.id != user.id).first():
            return jsonify({"ok": False, "error": "email_in_use"}), 400

        payload = {"apply": {"email": new_email, "email_verified": True}}
        code, rec = VerificationCode.create(user, Purpose.change_email, Channel.email, payload)
        send_email(new_email, "Verify your new email", f"Your verification code is: {code} (valid 10 minutes)")
        return jsonify({"ok": True, "requires": "email_code"})

    elif change_type == "phone":
        new_phone = (request.form.get("new_phone") or "").strip()
        if not new_phone or len(new_phone) < 6:
            return jsonify({"ok": False, "error": "invalid_phone"}), 400

        if User.query.filter(User.phone == new_phone, User.id != user.id).first():
            return jsonify({"ok": False, "error": "phone_in_use"}), 400

        payload = {"apply": {"phone": new_phone, "phone_verified": True}}
        code, rec = VerificationCode.create(user, Purpose.change_phone, Channel.phone, payload)
        send_sms(new_phone, f"Your TrendFind verification code is: {code}. Valid 10 minutes.")
        return jsonify({"ok": True, "requires": "phone_code"})

    elif change_type == "password":
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        if not user.check_password(current_pw):
            return jsonify({"ok": False, "error": "wrong_current_password"}), 400
        if len(new_pw) < 8:
            return jsonify({"ok": False, "error": "weak_password"}), 400

        # Send codes to BOTH email and phone (if phone exists). If phone missing, email only.
        pending = {"apply": {"password_hash": user.password_hash}}  # placeholder; set after verify
        # We’ll stash the new password in-memory here for a moment:
        # Safer: don’t store raw; we’ll compute hash once codes are verified in /confirm-change
        # To keep it safe, we include the *intention* only; hash later.
        # Create one or two VerificationCode rows carrying the same intention.
        email_code, rec_email = VerificationCode.create(user, Purpose.change_password, Channel.email, pending)
        send_email(user.email, "Verify your password change", f"Your password code is: {email_code} (valid 10 minutes)")
        if user.phone:
            phone_code, rec_phone = VerificationCode.create(user, Purpose.change_password, Channel.phone, pending)
            send_sms(user.phone, f"Your TrendFind password code is: {phone_code}. Valid 10 minutes.")
            required = "both_codes"
        else:
            required = "email_code"
        # Temporarily stash the new password (hashed) on the session? Better: send it back as a token?
        # We’ll pass it again in confirm-change so we never store raw anywhere server-side.
        return jsonify({"ok": True, "requires": required})

    else:
        return jsonify({"ok": False, "error": "unknown_change_type"}), 400

@bp.post("/confirm-change")
def confirm_change():
    """
    Confirm a sensitive change by verifying codes.
    For email/phone: verify the single code sent to the new destination.
    For password: verify email code and (if exists) phone code, then set new password.
    """
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "not_authenticated"}), 401

    change_type = request.form.get("type")

    if change_type == "email":
        code = request.form.get("code") or ""
        # Find the most recent unconsumed email-code for this purpose
        rec = (VerificationCode.query
               .filter_by(user_id=user.id, purpose=Purpose.change_email, channel=Channel.email, consumed=False)
               .order_by(VerificationCode.created_at.desc())
               .first())
        if not rec or not rec.verify(code):
            return jsonify({"ok": False, "error": "wrong_code"}), 400
        if datetime.utcnow() > rec.expires_at:
            return jsonify({"ok": False, "error": "code_expired"}), 400

        data = json.loads(rec.pending_json)["apply"]
        # Apply change
        user.email = data["email"]
        user.email_verified = True
        db.session.commit()
        rec.consume()
        return jsonify({"ok": True, "message": "Email updated."})

    elif change_type == "phone":
        code = request.form.get("code") or ""
        rec = (VerificationCode.query
               .filter_by(user_id=user.id, purpose=Purpose.change_phone, channel=Channel.phone, consumed=False)
               .order_by(VerificationCode.created_at.desc())
               .first())
        if not rec or not rec.verify(code):
            return jsonify({"ok": False, "error": "wrong_code"}), 400
        if datetime.utcnow() > rec.expires_at:
            return jsonify({"ok": False, "error": "code_expired"}), 400

        data = json.loads(rec.pending_json)["apply"]
        user.phone = data["phone"]
        user.phone_verified = True
        db.session.commit()
        rec.consume()
        return jsonify({"ok": True, "message": "Phone updated."})

    elif change_type == "password":
        email_code = request.form.get("email_code") or ""
        phone_code = request.form.get("phone_code") or None
        new_password = request.form.get("new_password") or ""
        if len(new_password) < 8:
            return jsonify({"ok": False, "error": "weak_password"}), 400

        rec_email = (VerificationCode.query
                     .filter_by(user_id=user.id, purpose=Purpose.change_password, channel=Channel.email, consumed=False)
                     .order_by(VerificationCode.created_at.desc())
                     .first())
        if not rec_email or not rec_email.verify(email_code) or datetime.utcnow() > rec_email.expires_at:
            return jsonify({"ok": False, "error": "wrong_email_code"}), 400

        if user.phone:
            rec_phone = (VerificationCode.query
                         .filter_by(user_id=user.id, purpose=Purpose.change_password, channel=Channel.phone, consumed=False)
                         .order_by(VerificationCode.created_at.desc())
                         .first())
            if not rec_phone or not phone_code or not rec_phone.verify(phone_code) or datetime.utcnow() > rec_phone.expires_at:
                return jsonify({"ok": False, "error": "wrong_phone_code"}), 400

        # All good — set the new password now
        user.set_password(new_password)
        db.session.commit()
        rec_email.consume()
        if user.phone:
            rec_phone.consume()
        return jsonify({"ok": True, "message": "Password updated."})

    else:
        return jsonify({"ok": False, "error": "unknown_change_type"}), 400
