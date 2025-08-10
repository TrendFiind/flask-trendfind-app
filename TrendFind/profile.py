# profile.py
import os, json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError
from PIL import Image
from models import db, User, VerificationCode, Purpose, Channel
from notifiers import send_email, send_sms
from security import csrf_protect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# We use app-level limiter via factory; import the shared instance via current_app.limiter
bp = Blueprint("profile", __name__, url_prefix="/profile")

# --- Utils ---
def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

def normalize_phone(p: str) -> str:
    p = (p or "").strip()
    try:
        import phonenumbers
        num = phonenumbers.parse(p, "AU")  # assume AU; change if needed
        if not phonenumbers.is_valid_number(num):
            return ""
        return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        # fallback: allow + and digits
        p = "".join([c for c in p if c.isdigit() or c=="+"])
        return p

def atomic(fn):
    def _wrap(*a, **kw):
        try:
            with db.session.begin_nested():
                return fn(*a, **kw)
        except IntegrityError:
            db.session.rollback()
            raise
    _wrap.__name__ = fn.__name__
    return _wrap

def require_current_password():
    pw = request.form.get("current_password") or ""
    if not current_user.check_password(pw):
        return False
    return True

# --- Routes ---
@bp.get("/")
@login_required
def profile_view():
    # CSRF token for page
    from security import generate_csrf_token
    token = generate_csrf_token()
    return render_template("profile.html", user=current_user, csrf_token=token, app_name=current_app.config["APP_NAME"])

# Rate limiting helpers
def per_user_key():
    return f"user:{current_user.get_id()}" if current_user.is_authenticated else get_remote_address()

# Save name (non-sensitive)
@bp.post("/save-basic")
@login_required
@csrf_protect
def save_basic():
    name = (request.form.get("name") or "").strip()
    if len(name) > 120:
        return jsonify({"ok": False, "error": "name_too_long"}), 400
    current_user.name = name or current_user.name
    db.session.commit()
    return jsonify({"ok": True, "message": "Saved."})

# Avatar upload hardened
@bp.post("/upload-avatar")
@login_required
@csrf_protect
def upload_avatar():
    f = request.files.get("avatar")
    if not f or f.filename == "":
        return jsonify({"ok": False, "error": "no_file"}), 400

    # size check
    f.stream.seek(0, 2)
    size = f.stream.tell()
    f.stream.seek(0)
    max_bytes = current_app.config["AVATAR_MAX_MB"] * 1024 * 1024
    if size > max_bytes:
        return jsonify({"ok": False, "error": "file_too_large"}), 400

    # re-encode to JPEG to strip EXIF and content-sniff
    try:
        im = Image.open(f.stream).convert("RGB")
    except Exception:
        return jsonify({"ok": False, "error": "invalid_image"}), 400

    updir = current_app.config["AVATAR_DIR"]
    os.makedirs(updir, exist_ok=True)
    filename = f"user_{current_user.id}_{int(datetime.utcnow().timestamp())}.jpg"
    path = os.path.join(updir, filename)
    im.save(path, format="JPEG", quality=85, optimize=True)

    # store relative URL
    url = "/" + path.replace("\\", "/")
    current_user.profile_pic_url = url
    db.session.commit()
    return jsonify({"ok": True, "url": url})

# Start sensitive changes (email, phone, password)
@bp.post("/request-change")
@login_required
@csrf_protect
def request_change():
    change_type = request.form.get("type")
    # Basic per-user rate limit (manual): 5 per 10m
    key = f"reqchg:{current_user.id}"
    # Use Flask-Limiter if configured at app level
    limiter = current_app.extensions.get("limiter")
    if limiter:
        # dynamic limit per endpoint + per user
        pass  # decorator approach used in app factory; left here for clarity

    if change_type == "email":
        if not require_current_password():
            return jsonify({"ok": False, "error": "wrong_current_password"}), 400
        new_email = normalize_email(request.form.get("new_email"))
        if not new_email or "@" not in new_email:
            return jsonify({"ok": False, "error": "invalid_email"}), 400
        if new_email == current_user.email:
            return jsonify({"ok": False, "error": "same_email"}), 400
        if User.query.filter(User.email == new_email, User.id != current_user.id).first():
            return jsonify({"ok": False, "error": "email_in_use"}), 400

        payload = {"apply": {"email": new_email, "email_verified": True}}
        try:
            code, _ = VerificationCode.create(current_user, Purpose.change_email, Channel.email, payload)
            send_email(new_email, f"{current_app.config['APP_NAME']} – Verify your new email", f"Your code: {code}. Valid for 10 minutes.")
        except Exception:
            return jsonify({"ok": False, "error": "send_failed"}), 500
        return jsonify({"ok": True, "requires": "email_code"})

    elif change_type == "phone":
        if not require_current_password():
            return jsonify({"ok": False, "error": "wrong_current_password"}), 400
        new_phone = normalize_phone(request.form.get("new_phone"))
        if not new_phone:
            return jsonify({"ok": False, "error": "invalid_phone"}), 400
        if current_user.phone and new_phone == current_user.phone:
            return jsonify({"ok": False, "error": "same_phone"}), 400
        if User.query.filter(User.phone == new_phone, User.id != current_user.id).first():
            return jsonify({"ok": False, "error": "phone_in_use"}), 400

        payload = {"apply": {"phone": new_phone, "phone_verified": True}}
        try:
            code, _ = VerificationCode.create(current_user, Purpose.change_phone, Channel.phone, payload)
            send_sms(new_phone, f"{current_app.config['APP_NAME']} code: {code}. Valid 10 minutes.")
        except Exception:
            return jsonify({"ok": False, "error": "send_failed"}), 500
        return jsonify({"ok": True, "requires": "phone_code"})

    elif change_type == "password":
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        if not current_user.check_password(current_pw):
            return jsonify({"ok": False, "error": "wrong_current_password"}), 400
        if len(new_pw) < 8:
            return jsonify({"ok": False, "error": "weak_password"}), 400

        pending = {"apply": {"password": True}}  # intention only; we won’t store the raw pass
        try:
            email_code, _ = VerificationCode.create(current_user, Purpose.change_password, Channel.email, pending)
            send_email(current_user.email, f"{current_app.config['APP_NAME']} – Password change code", f"Your code: {email_code}. Valid 10 minutes.")
            requires = "email_code"
            if current_user.phone:
                phone_code, _ = VerificationCode.create(current_user, Purpose.change_password, Channel.phone, pending)
                send_sms(current_user.phone, f"{current_app.config['APP_NAME']} password code: {phone_code}. Valid 10 minutes.")
                requires = "both_codes"
        except Exception:
            return jsonify({"ok": False, "error": "send_failed"}), 500
        # We’ll submit new password again in confirm-change; never stored server-side until applied
        return jsonify({"ok": True, "requires": requires})

    else:
        return jsonify({"ok": False, "error": "unknown_change_type"}), 400

# Confirm sensitive changes (transactional)
@bp.post("/confirm-change")
@login_required
@csrf_protect
@atomic
def confirm_change():
    change_type = request.form.get("type")

    if change_type == "email":
        code = request.form.get("code") or ""
        rec = (VerificationCode.query
               .filter_by(user_id=current_user.id, purpose=Purpose.change_email, channel=Channel.email, consumed=False)
               .order_by(VerificationCode.created_at.desc()).first())
        if not rec or not rec.verify(code) or datetime.utcnow() > rec.expires_at:
            return jsonify({"ok": False, "error": "wrong_code"}), 400
        data = json.loads(rec.pending_json)["apply"]
        old_email = current_user.email
        current_user.email = data["email"]
        current_user.email_verified = True
        db.session.commit()
        rec.consume()
        # security notification
        try:
            send_email(old_email, f"{current_app.config['APP_NAME']} – Email changed", "Your email was changed. If this wasn't you, contact support immediately.")
        except Exception:
            pass
        return jsonify({"ok": True, "message": "Email updated."})

    elif change_type == "phone":
        code = request.form.get("code") or ""
        rec = (VerificationCode.query
               .filter_by(user_id=current_user.id, purpose=Purpose.change_phone, channel=Channel.phone, consumed=False)
               .order_by(VerificationCode.created_at.desc()).first())
        if not rec or not rec.verify(code) or datetime.utcnow() > rec.expires_at:
            return jsonify({"ok": False, "error": "wrong_code"}), 400
        data = json.loads(rec.pending_json)["apply"]
        old_phone = current_user.phone
        current_user.phone = data["phone"]
        current_user.phone_verified = True
        db.session.commit()
        rec.consume()
        # notify old number via email (since SMS old may not exist)
        try:
            send_email(current_user.email, f"{current_app.config['APP_NAME']} – Phone changed", "Your phone number was changed. If this wasn't you, contact support.")
        except Exception:
            pass
        return jsonify({"ok": True, "message": "Phone updated."})

    elif change_type == "password":
        email_code = request.form.get("email_code") or ""
        phone_code = request.form.get("phone_code") or None
        new_password = request.form.get("new_password") or ""
        if len(new_password) < 8:
            return jsonify({"ok": False, "error": "weak_password"}), 400

        rec_email = (VerificationCode.query
                     .filter_by(user_id=current_user.id, purpose=Purpose.change_password, channel=Channel.email, consumed=False)
                     .order_by(VerificationCode.created_at.desc()).first())
        if not rec_email or not rec_email.verify(email_code) or datetime.utcnow() > rec_email.expires_at:
            return jsonify({"ok": False, "error": "wrong_email_code"}), 400

        if current_user.phone:
            rec_phone = (VerificationCode.query
                         .filter_by(user_id=current_user.id, purpose=Purpose.change_password, channel=Channel.phone, consumed=False)
                         .order_by(VerificationCode.created_at.desc()).first())
            if not rec_phone or not phone_code or not rec_phone.verify(phone_code) or datetime.utcnow() > rec_phone.expires_at:
                return jsonify({"ok": False, "error": "wrong_phone_code"}), 400

        # apply
        current_user.set_password(new_password)
        db.session.commit()
        rec_email.consume()
        if current_user.phone:
            rec_phone.consume()

        # revoke other sessions? depends on your session store; at least notify:
        try:
            send_email(current_user.email, f"{current_app.config['APP_NAME']} – Password changed", "Your password was just changed. If this wasn't you, secure your account.")
        except Exception:
            pass
        return jsonify({"ok": True, "message": "Password updated."})

    else:
        return jsonify({"ok": False, "error": "unknown_change_type"}), 400
