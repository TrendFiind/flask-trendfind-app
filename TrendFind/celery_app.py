# TrendFind/celery_app.py
import os
from celery import Celery

raw_redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
if "ssl_cert_reqs=none" not in raw_redis_url:
    redis_url = raw_redis_url + ("?ssl_cert_reqs=none" if "?" not in raw_redis_url else "&ssl_cert_reqs=none")
else:
    redis_url = raw_redis_url

# IMPORTANT: use your package name here
celery = Celery(__name__, include=["TrendFind.email_utils"])

def make_celery(app):
    celery.conf.update(
        broker_url=redis_url,
        result_backend=redis_url,
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
    )
    class ContextTask(celery.Task):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return super().__call__(*args, **kwargs)
    celery.Task = ContextTask
    return celery
