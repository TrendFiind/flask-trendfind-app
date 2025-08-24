web: gunicorn "TrendFind:create_app()"
worker: celery -A TrendFind.celery_app.celery worker --loglevel=info
