# app/celery_app.py
import os
from celery import Celery

# Global Celery instance with task auto-discovery
celery = Celery(__name__, include=["app.email_utils"])

def make_celery(app):
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

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
