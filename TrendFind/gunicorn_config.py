bind = "0.0.0.0:8000"
workers = 3             # at least (2 × CPU) + 1 in prod
worker_class = "gthread"
threads = 2
timeout = 30
