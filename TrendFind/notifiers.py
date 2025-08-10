# notifiers.py
# Replace the stubs with your actual providers (SendGrid/SMTP and Twilio/other)
import os
from flask import current_app

def send_email(to_email: str, subject: str, body: str):
    # TODO: integrate your real email service. For now, log to console.
    current_app.logger.info(f"[EMAIL -> {to_email}] {subject}\n{body}")

def send_sms(to_phone: str, body: str):
    # TODO: integrate Twilio or your SMS gateway here.
    current_app.logger.info(f"[SMS -> {to_phone}] {body}")
