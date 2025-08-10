# security.py
from flask import session, request, current_app, jsonify
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="csrf-salt")

def generate_csrf_token():
    token = _serializer().dumps({"sid": session.get("_id", "anon")})
    session["csrf_token"] = token
    return token

def csrf_protect(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token") or request.form.get("_csrf")
        if not token:
            return jsonify({"ok": False, "error": "missing_csrf"}), 400
        try:
            data = _serializer().loads(token, max_age=60*60)  # 1 hour
        except SignatureExpired:
            return jsonify({"ok": False, "error": "csrf_expired"}), 400
        except BadSignature:
            return jsonify({"ok": False, "error": "csrf_invalid"}), 400
        return fn(*args, **kwargs)
    return wrapper
