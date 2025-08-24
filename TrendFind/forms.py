# TrendFind/forms.py

import os
from flask_wtf import FlaskForm

# Recaptcha import that works across Flask-WTF versions, but degrades cleanly.
try:
    # Newer Flask-WTF (v1.2+)
    from flask_wtf.recaptcha import RecaptchaField  # type: ignore
except Exception:  # pragma: no cover
    try:
        # Older Flask-WTF
        from flask_wtf import RecaptchaField  # type: ignore
    except Exception:  # pragma: no cover
        RecaptchaField = None  # fallback: disable recaptcha if not available

from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length


def _strip(val: str | None) -> str | None:
    return val.strip() if isinstance(val, str) else val


class RegisterForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[DataRequired(message="Name is required"), Length(max=120)],
        filters=[_strip],
    )
    email = StringField(
        "Email",
        validators=[DataRequired(message="Email is required"), Email()],
        filters=[_strip, lambda s: s.lower() if isinstance(s, str) else s],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required"), Length(min=8)],
    )
    confirm = PasswordField(
        "Confirm",
        validators=[EqualTo("password", message="Passwords must match")],
    )

    # Only add reCAPTCHA if:
    # 1) The field class exists; and
    # 2) keys are present in the environment (your config pulls these too).
    if RecaptchaField and os.getenv("RECAPTCHA_SITE_KEY") and os.getenv("RECAPTCHA_SECRET_KEY"):
        recaptcha = RecaptchaField()

    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(message="Email is required"), Email()],
        filters=[_strip, lambda s: s.lower() if isinstance(s, str) else s],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required")],
    )
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign In")
