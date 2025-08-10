# notifiers.py
"""
Production-ready notifications:
- Email: Prefer SendGrid when SENDGRID_API_KEY is set; fallback to SMTP (Gmail or your server).
- SMS: Twilio (requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM).
- HTML emails supported; plain-text auto-generated if not provided.
- Tight timeouts and explicit exceptions.
"""

import os
import smtplib
import socket
import ssl
import logging
from email.message import EmailMessage
from typing import Optional

from flask import current_app

# Custom exceptions for clearer error handling upstream
class NotifierConfigError(RuntimeError):
    pass

class NotifierSendError(RuntimeError):
    pass


# ---------- Email Providers ----------

class BaseEmailProvider:
    def send(self, to_email: str, subject: str, text: str, html: Optional[str] = None):
        raise NotImplementedError


class SMTPEmailProvider(BaseEmailProvider):
    def __init__(self, server: str, port: int, username: str, password: str, use_tls: bool, use_ssl: bool, default_sender: str):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.default_sender = default_sender

        if not (self.server and self.port and self.default_sender):
            raise NotifierConfigError("SMTP not fully configured (server/port/sender missing)")

    def _connect(self):
        timeout = 15  # seconds
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                smtp = smtplib.SMTP_SSL(self.server, self.port, timeout=timeout, context=context)
            else:
                smtp = smtplib.SMTP(self.server, self.port, timeout=timeout)
                if self.use_tls:
                    smtp.starttls(context=ssl.create_default_context())
            if self.username and self.password:
                smtp.login(self.username, self.password)
            return smtp
        except (smtplib.SMTPException, OSError, socket.timeout) as e:
            raise NotifierSendError(f"SMTP connect/login failed: {e}") from e

    def send(self, to_email: str, subject: str, text: str, html: Optional[str] = None):
        if not to_email:
            raise NotifierSendError("Missing recipient email")

        msg = EmailMessage()
        msg["From"] = self.default_sender
        msg["To"] = to_email
        msg["Subject"] = subject or ""

        text = text or ""
        if html:
            msg.set_content(text)
            msg.add_alternative(html, subtype="html")
        else:
            msg.set_content(text)

        smtp = None
        try:
            smtp = self._connect()
            smtp.send_message(msg)
        except (smtplib.SMTPException, OSError, socket.timeout) as e:
            raise NotifierSendError(f"SMTP send failed: {e}") from e
        finally:
            try:
                if smtp:
                    smtp.quit()
            except Exception:
                pass


class SendGridEmailProvider(BaseEmailProvider):
    def __init__(self, api_key: str, default_sender: str):
        if not api_key or not default_sender:
            raise NotifierConfigError("SendGrid not fully configured (api_key/sender missing)")
        self.api_key = api_key
        self.default_sender = default_sender
        # Delay import so the module isn't required unless configured
        try:
            from sendgrid import SendGridAPIClient  # noqa
            from sendgrid.helpers.mail import Mail  # noqa
        except Exception as e:
            raise NotifierConfigError(f"SendGrid SDK not installed: {e}") from e

    def send(self, to_email: str, subject: str, text: str, html: Optional[str] = None):
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail, Content

        if not to_email:
            raise NotifierSendError("Missing recipient email")

        # If only HTML provided, keep a minimal text fallback
        if html and not text:
            text = "View this message in an HTML-capable email client."

        message = Mail(
            from_email=self.default_sender,
            to_emails=to_email,
            subject=subject or "",
            plain_text_content=text or "",
            html_content=html
        )

        try:
            sg = SendGridAPIClient(self.api_key)
            resp = sg.send(message)
            if resp.status_code >= 300:
                raise NotifierSendError(f"SendGrid send failed: HTTP {resp.status_code}")
        except Exception as e:
            raise NotifierSendError(f"SendGrid send exception: {e}") from e


def _get_email_provider() -> BaseEmailProvider:
    """
    Choose SendGrid if configured; fall back to SMTP.
    """
    cfg = current_app.config
    # Prefer SendGrid if API key present
    if cfg.get("SENDGRID_API_KEY") and cfg.get("MAIL_DEFAULT_SENDER"):
        current_app.logger.debug("Using SendGridEmailProvider")
        return SendGridEmailProvider(
            api_key=cfg["SENDGRID_API_KEY"],
            default_sender=cfg["MAIL_DEFAULT_SENDER"],
        )

    # Otherwise use SMTP (your current setup)
    server = cfg.get("MAIL_SERVER")
    port = int(cfg.get("MAIL_PORT", 587))
    username = cfg.get("MAIL_USERNAME")
    password = cfg.get("MAIL_PASSWORD")
    use_tls = bool(cfg.get("MAIL_USE_TLS", True))
    use_ssl = bool(cfg.get("MAIL_USE_SSL", False))
    default_sender = cfg.get("MAIL_DEFAULT_SENDER") or cfg.get("EMAIL_FROM")

    if not default_sender:
        # Try to infer sender from username, else error
        default_sender = username

    current_app.logger.debug("Using SMTPEmailProvider")
    return SMTPEmailProvider(
        server=server,
        port=port,
        username=username,
        password=password,
        use_tls=use_tls,
        use_ssl=use_ssl,
        default_sender=default_sender,
    )


# ---------- SMS Provider (Twilio) ----------

class TwilioSMSProvider:
    def __init__(self, sid: str, token: str, from_number: str):
        if not (sid and token and from_number):
            raise NotifierConfigError("Twilio not fully configured (sid/token/from missing)")
        self.sid = sid
        self.token = token
        self.from_number = from_number
        try:
            from twilio.rest import Client  # noqa
        except Exception as e:
            raise NotifierConfigError(f"Twilio SDK not installed: {e}") from e

    def send(self, to_phone: str, body: str):
        if not to_phone:
            raise NotifierSendError("Missing recipient phone")
        if not body:
            raise NotifierSendError("Missing SMS body")

        from twilio.rest import Client
        try:
            client = Client(self.sid, self.token)
            msg = client.messages.create(
                to=to_phone,
                from_=self.from_number,
                body=body[:1600],  # hard cap to avoid surprises
            )
            if not getattr(msg, "sid", None):
                raise NotifierSendError("Twilio did not return a message SID")
        except Exception as e:
            raise NotifierSendError(f"Twilio send exception: {e}") from e


def _get_sms_provider() -> TwilioSMSProvider:
    cfg = current_app.config
    sid = cfg.get("TWILIO_ACCOUNT_SID")
    token = cfg.get("TWILIO_AUTH_TOKEN")
    from_num = cfg.get("TWILIO_FROM")
    return TwilioSMSProvider(sid, token, from_num)


# ---------- Public API ----------

def send_email(to_email: str, subject: str, body_text: str, html: Optional[str] = None):
    """
    Send an email using the configured provider.
    - body_text: plain-text fallback (required)
    - html: optional HTML body
    Raises NotifierConfigError or NotifierSendError on failure.
    """
    logger = current_app.logger or logging.getLogger(__name__)
    try:
        provider = _get_email_provider()
        provider.send(to_email=to_email, subject=subject, text=body_text, html=html)
        logger.info(f"[EMAIL✓] to={to_email} subject={subject!r}")
    except (NotifierConfigError, NotifierSendError) as e:
        logger.error(f"[EMAIL✗] to={to_email} subject={subject!r} err={e}")
        raise
    except Exception as e:
        logger.exception(f"[EMAIL✗] unexpected error to={to_email} subject={subject!r}")
        raise NotifierSendError(str(e)) from e


def send_sms(to_phone: str, body: str):
    """
    Send an SMS using Twilio.
    - to_phone must be E.164 (e.g., +614xxxxxxxx). Normalize upstream if needed.
    Raises NotifierConfigError or NotifierSendError on failure.
    """
    logger = current_app.logger or logging.getLogger(__name__)
    try:
        provider = _get_sms_provider()
        provider.send(to_phone=to_phone, body=body)
        logger.info(f"[SMS✓] to={to_phone} len={len(body)}")
    except (NotifierConfigError, NotifierSendError) as e:
        logger.error(f"[SMS✗] to={to_phone} err={e}")
        raise
    except Exception as e:
        logger.exception(f"[SMS✗] unexpected error to={to_phone}")
        raise NotifierSendError(str(e)) from e
