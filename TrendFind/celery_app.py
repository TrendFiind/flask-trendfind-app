# TrendFind/celery_app.py
import os
from celery import Celery

# Build Redis URL with SSL override for Heroku Redis
_raw = os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"
if "ssl_cert_reqs=none" not in _raw:
    redis_url = _raw + ("?ssl_cert_reqs=none" if "?" not in _raw else "&ssl_cert_reqs=none")
else:
    redis_url = _raw

# Single Celery instance shared across the app
celery = Celery(__name__, include=["TrendFind.email_utils"])

def make_celery(app):
    celery.conf.update(
        broker_url=redis_url,
        result_backend=redis_url,
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
    )

    # Ensure Flask app context in every task
    class ContextTask(celery.Task):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return super().__call__(*args, **kwargs)

    celery.Task = ContextTask
    return celery
