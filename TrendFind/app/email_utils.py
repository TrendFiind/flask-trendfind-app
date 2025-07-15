from flask_mail import Message
from . import mail, celery
from flask import current_app, render_template

@celery.task
def send_welcome_email(user_email, user_name):
    msg = Message(
        subject="Welcome to TrendFind",
        recipients=[user_email],
        sender=current_app.config["MAIL_USERNAME"]
    )
    msg.body = render_template("emails/welcome.txt", name=user_name)
    mail.send(msg)
