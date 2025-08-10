web: gunicorn "TrendFind:create_app()"
worker: celery -A TrendFind.celery_worker.celery worker --loglevel=info
