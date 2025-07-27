from flask_mail import Message
from flask import current_app, render_template
from mail import mail
from celery_app import celery

@celery.task(name="send_welcome_email")  # ✅ optional: name it for debugging
def send_welcome_email(user_email, user_name):
    with current_app.app_context():  # ✅ ensure it's inside Flask context
        msg = Message(
            subject="Welcome to TrendFind",
            recipients=[user_email],
            sender=current_app.config["MAIL_USERNAME"]
        )
        msg.body = render_template("emails/welcome.txt", name=user_name)
        mail.send(msg)
