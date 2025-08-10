import json
from datetime import datetime, timedelta

import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from TrendFind import create_app, db
from TrendFind.models import User, VerificationCode, Purpose
import TrendFind.profile as profile_module


@pytest.fixture
def app():
    app = create_app("config.Development")
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:", TESTING=True)
    app.register_blueprint(profile_module.bp)
    with app.app_context():
        db.create_all()
        user = User(name="User", email="old@example.com")
        user.set_password("secret123")
        db.session.add(user)
        db.session.commit()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, user_id):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['user_id'] = user_id


def request_email_change(client, app, monkeypatch, new_email="new@example.com"):
    with app.app_context():
        user = User.query.first()
    login(client, user.id)
    captured = {}
    orig_create = profile_module.VerificationCode.create

    def capture_create(user, purpose, channel, pending, ttl_minutes=10):
        code, obj = orig_create(user, purpose, channel, pending, ttl_minutes)
        captured['code'] = code
        return code, obj

    monkeypatch.setattr(profile_module.VerificationCode, 'create', capture_create)
    monkeypatch.setattr(profile_module, 'send_email', lambda *a, **k: None)
    resp = client.post('/profile/request-change', data={'type': 'email', 'new_email': new_email})
    assert resp.get_json()['ok']
    return captured['code'], user.id


def test_email_change_flow(client, app, monkeypatch):
    code, user_id = request_email_change(client, app, monkeypatch)
    resp = client.post('/profile/confirm-change', data={'type': 'email', 'code': code})
    assert resp.get_json()['ok']
    with app.app_context():
        assert User.query.get(user_id).email == 'new@example.com'


def test_email_change_wrong_code(client, app, monkeypatch):
    _, user_id = request_email_change(client, app, monkeypatch)
    resp = client.post('/profile/confirm-change', data={'type': 'email', 'code': '000000'})
    assert resp.status_code == 400


def test_email_change_expired_code(client, app, monkeypatch):
    code, user_id = request_email_change(client, app, monkeypatch)
    with app.app_context():
        rec = VerificationCode.query.filter_by(user_id=user_id, purpose=Purpose.change_email).order_by(VerificationCode.id.desc()).first()
        rec.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
    resp = client.post('/profile/confirm-change', data={'type': 'email', 'code': code})
    assert resp.status_code == 400


def test_request_change_cooldown(client, app, monkeypatch):
    request_email_change(client, app, monkeypatch, new_email='one@example.com')
    resp = client.post('/profile/request-change', data={'type': 'email', 'new_email': 'two@example.com'})
    assert resp.status_code == 429
    assert resp.get_json()['error'] == 'cooldown'


def test_request_change_rate_limit(client, app, monkeypatch):
    with app.app_context():
        user = User.query.first()
    login(client, user.id)
    monkeypatch.setattr(profile_module, 'send_email', lambda *a, **k: None)
    for i in range(5):
        resp = client.post('/profile/request-change', data={'type': 'email', 'new_email': f'u{i}@example.com'})
        assert resp.get_json()['ok']
        with app.app_context():
            rec = VerificationCode.query.order_by(VerificationCode.id.desc()).first()
            rec.created_at -= timedelta(seconds=61)
            db.session.commit()
    resp = client.post('/profile/request-change', data={'type': 'email', 'new_email': 'u5@example.com'})
    assert resp.status_code == 429
    assert resp.get_json()['error'] == 'rate_limited'
