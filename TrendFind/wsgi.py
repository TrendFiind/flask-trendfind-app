from app import create_app
app = create_app("config.Production")    # switch via env var on Heroku
