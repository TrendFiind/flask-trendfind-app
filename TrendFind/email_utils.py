# TrendFind/email_utils.py
from flask import current_app, render_template
from flask_mail import Message

# import the extension singletons from the package (NOT "from mail import mail")
from TrendFind import mail, celery

@celery.task(name="send_welcome_email")
def send_welcome_email(user_email: str, user_name: str):
    # make_celery binds Flask context, so current_app is available here
    msg = Message(
        subject="Welcome to TrendFind",
        recipients=[user_email],
        sender=current_app.config.get("MAIL_DEFAULT_SENDER") or current_app.config.get("MAIL_USERNAME"),
    )
    # create these templates or switch to a simple body string
    try:
        msg.body = render_template("emails/welcome.txt", name=user_name)
        msg.html = render_template("emails/welcome.html", name=user_name)
    except Exception:
        msg.body = f"Welcome to TrendFind, {user_name}!"
    mail.send(msg)
