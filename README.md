# TrendFind

## Profile Change Verification

The profile settings module uses email and SMS one-time passwords (OTP) to verify sensitive changes.

### Environment variables
- `SENDGRID_API_KEY` – API key for sending verification emails (or configure SMTP via `MAIL_*` variables).
- `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` – credentials for sending verification SMS messages.
- `MAIL_DEFAULT_SENDER` – From address used in emails.
- `TWILIO_FROM` – Phone number to send SMS from.

### Running tests
Install dependencies then run:
```bash
pytest
```
