import os
import sys
import tempfile
from werkzeug.security import generate_password_hash

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from TrendFind import main


def setup_app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    main.Config.LOCAL_SQLITE_PATH = path
    main.app.config['TESTING'] = True
    with main.app.app_context():
        main.init_db()
        db = main.get_db()
        db.execute(
            "INSERT INTO users (email,password,name) VALUES (?,?,?)",
            ("user@example.com", generate_password_hash("secret"), "User"),
        )
        db.commit()
    return main.app.test_client(), path


def teardown_app(path):
    if os.path.exists(path):
        os.remove(path)


def test_contact_page_ignores_auth_flashes():
    client, path = setup_app()
    try:
        client.post('/login', data={'email': 'user@example.com', 'password': 'secret'})
        resp = client.get('/contact-us')
        assert b'Login successful' not in resp.data
    finally:
        teardown_app(path)
