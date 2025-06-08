from celery import Celery
celery = Celery(__name__, include=["app.email_utils"])

def make_celery(app):
    celery.conf.update(
        broker_url = app.config.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
        result_backend = app.config.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
        task_serializer = "json",
        accept_content  = ["json"],
        timezone        = "UTC",
    )
    # bind Flask app context to every task
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
