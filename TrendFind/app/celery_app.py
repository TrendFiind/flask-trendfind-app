import os
from celery import Celery

# Create the Celery instance globally
celery = Celery(__name__, include=["app.email_utils"])  # ✅ include your tasks here

def make_celery(app):
    celery.conf.update(
        broker_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),        # ✅ Use Heroku Redis
        result_backend=os.environ.get("REDIS_URL", "redis://localhost:6379/1"),    # ✅ Use same Redis as fallback
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
