# TrendFind/email_utils.py
from __future__ import annotations

from flask import current_app, render_template
from flask_mail import Message

# ✅ import from your own package (NOT "from mail import mail")
from . import mail                    # 'mail' instance created in TrendFind/__init__.py
from .celery_app import celery        # Celery instance defined in TrendFind/celery_app.py


@celery.task(name="emails.send_welcome")  # a readable task name for logs
def send_welcome_email(user_email: str, user_name: str) -> None:
    """
    Send the welcome email. Celery task runs with Flask app context because
    make_celery() wraps tasks (ContextTask). Keeping an explicit context here
    is harmless if you want to be extra safe.
    """
    # If your make_celery already binds context, the next 'with' is optional.
    with current_app.app_context():
        msg = Message(
            subject="Welcome to TrendFind",
            recipients=[user_email],
            sender=current_app.config.get("MAIL_USERNAME"),
        )
        # templates/emails/welcome.txt must exist
        msg.body = render_template("emails/welcome.txt", name=user_name)
        mail.send(msg)
