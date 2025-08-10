web: gunicorn --worker-class sync --workers 2 TrendFind.main:app
worker: celery -A app.celery_app.celery worker --loglevel=info
