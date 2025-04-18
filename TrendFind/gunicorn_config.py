# gunicorn_config.py
workers = 2
bind = "0.0.0.0:$PORT"
worker_class = "gevent"
timeout = 30
