# TrendFind/celery_worker.py
from TrendFind import create_app, celery  # celery instance from __init__.py
from TrendFind.celery_app import make_celery

app = create_app()
make_celery(app, celery)  # configure broker/backends + context
