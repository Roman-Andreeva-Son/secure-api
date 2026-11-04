import sqlite3
import time

import jwt
import pytest

from app import create_app, db, security

PASSWORD = "correct-horse-battery"


@pytest.fixture()
def app(tmp_path):
    path = str(tmp_path / "test.db")
    application = create_app({"DATABASE": path, "JWT_SECRET": "test-secret-" + "x" * 32, "TESTING": True})
    db.create_user(path, "alice", security.hash_password(PASSWORD))
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="alice", password=PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth(client):
    token = login(client).get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------- функциональность ----------

def test_login_success_returns_jwt(client):
    r = login(client)
    assert r.status_code == 200
    body = r.get_json()
    assert body["token_type"] == "Bearer"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["username"] == "alice" and "exp" in claims


def test_login_wrong_password(client):
    assert login(client, password="wrong-password").status_code == 401


def test_login_unknown_user_same_error(client):
    a = login(client, username="nobody")
    b = login(client, password="wrong-password")
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json()


@pytest.mark.parametrize("payload", [None, {}, {"username": "alice"}, {"username": 1, "password": 2}, []])
def test_login_bad_input(client, payload):
    r = client.post("/auth/login", json=payload)
    assert r.status_code == 400


def test_data_requires_token(client):
    r = client.get("/api/data")
    assert r.status_code == 401


def test_data_with_token(client):
    h = auth(client)
    assert client.post("/api/posts", json={"title": "Привет", "body": "Первый пост"}, headers=h).status_code == 201
    r = client.get("/api/data", headers=h)
    assert r.status_code == 200
    assert r.get_json()["count"] == 1
    assert r.get_json()["items"][0]["author"] == "alice"


def test_create_post_requires_token(client):
    assert client.post("/api/posts", json={"title": "a", "body": "b"}).status_code == 401


@pytest.mark.parametrize(
    "payload",
    [{}, {"title": "", "body": "x"}, {"title": "x", "body": " "}, {"title": 1, "body": 2}, {"title": "a" * 101, "body": "x"}],
)
def test_create_post_validation(client, payload):
    assert client.post("/api/posts", json=payload, headers=auth(client)).status_code == 400


def test_health_is_public(client):
    assert client.get("/health").status_code == 200


# ---------- токены ----------

def test_garbage_token_rejected(client):
    r = client.get("/api/data", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_wrong_scheme_rejected(client):
    token = login(client).get_json()["access_token"]
    assert client.get("/api/data", headers={"Authorization": f"Basic {token}"}).status_code == 401


def test_token_signed_with_other_secret_rejected(client):
    forged = security.create_token(1, "alice", "attacker-secret-" + "y" * 32)
    assert client.get("/api/data", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_rejected(app, client):
    now = int(time.time())
    payload = {"sub": "1", "username": "alice", "iat": now - 100, "exp": now - 10, "iss": security.JWT_ISSUER}
    expired = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
    assert client.get("/api/data", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_alg_none_token_rejected(client):
    now = int(time.time())
    payload = {"sub": "1", "username": "alice", "iat": now, "exp": now + 600, "iss": security.JWT_ISSUER}
    none_token = jwt.encode(payload, key=None, algorithm="none")
    assert client.get("/api/data", headers={"Authorization": f"Bearer {none_token}"}).status_code == 401


# ---------- пароли ----------

def test_password_not_stored_in_plaintext(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    (stored,) = conn.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    conn.close()
    assert PASSWORD not in stored and stored.startswith("scrypt$")


def test_same_password_gives_different_hashes():
    assert security.hash_password("same-password") != security.hash_password("same-password")


def test_verify_password_rejects_malformed_hash():
    assert security.verify_password("x", "garbage") is False


# ---------- SQL-инъекции ----------

@pytest.mark.parametrize("payload", ["' OR '1'='1", "alice'--", "' OR 1=1 --", "\" OR \"\"=\""])
def test_sqli_in_login_username(client, payload):
    assert login(client, username=payload, password="anything-123").status_code == 401


def test_sqli_in_login_password(client):
    assert login(client, password="' OR '1'='1").status_code == 401


def test_sqli_in_search_does_not_leak_or_break(client):
    h = auth(client)
    client.post("/api/posts", json={"title": "secret", "body": "data"}, headers=h)
    r = client.get("/api/data", query_string={"q": "x' OR '1'='1"}, headers=h)
    assert r.status_code == 200 and r.get_json()["count"] == 0
    r = client.get("/api/data", query_string={"q": "'; DROP TABLE posts;--"}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/data", headers=h).get_json()["count"] == 1  # таблица цела


# ---------- XSS ----------

def test_xss_payload_is_escaped_in_response(client):
    h = auth(client)
    evil = '<script>alert("xss")</script>'
    client.post("/api/posts", json={"title": evil, "body": "<img src=x onerror=alert(1)>"}, headers=h)
    item = client.get("/api/data", headers=h).get_json()["items"][0]
    assert "<script>" not in item["title"] and "&lt;script&gt;" in item["title"]
    assert "<img" not in item["body"] and "&lt;img" in item["body"]


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
