# TrendFind/celery_app.py
import os

def _redis_url():
    raw = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    # Upgrade to TLS on Heroku if wanted
    if raw.startswith("redis://") and os.environ.get("REDIS_TLS", "1") == "1":
        raw = raw.replace("redis://", "rediss://", 1)
    # Allow self-signed certs on Heroku Redis
    if raw.startswith("rediss://") and "ssl_cert_reqs=none" not in raw:
        raw += ("&" if "?" in raw else "?") + "ssl_cert_reqs=none"
    return raw

def make_celery(app, celery):
    redis_url = _redis_url()
    celery.conf.update(
        broker_url=redis_url,
        result_backend=redis_url,
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        broker_connection_retry_on_startup=True,
        imports=[
            "TrendFind.email_utils",   # <-- change/remove if your tasks live elsewhere
            "TrendFind.tasks",         # <-- optional; safe to remove if you don't have it
        ],
    )

    # Bind Flask app context to all tasks
    class ContextTask(celery.Task):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return super().__call__(*args, **kwargs)

    celery.Task = ContextTask
    return celery
