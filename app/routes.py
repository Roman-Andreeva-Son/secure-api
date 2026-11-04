"""Эндпоинты API."""
from flask import Blueprint, current_app, g, jsonify, request
from markupsafe import escape

from . import security
from .db import get_db

bp = Blueprint("api", __name__)

MAX_TITLE = 100
MAX_BODY = 2000
MAX_USERNAME = 64
MAX_PASSWORD = 256


def _clean(value) -> str:
    """Экранирование HTML для всего, что уходит клиенту (защита от XSS)."""
    return str(escape(value))


def _post_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "author": _clean(row["author"]),
        "title": _clean(row["title"]),
        "body": _clean(row["body"]),
        "created_at": row["created_at"],
    }


@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.post("/auth/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Ожидается JSON с полями username и password"), 400
    username = data.get("username")
    password = data.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
        or len(username) > MAX_USERNAME
        or len(password) > MAX_PASSWORD
    ):
        return jsonify(error="Некорректные username или password"), 400

    # Параметризованный запрос: данные пользователя передаются отдельно от SQL.
    row = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored = row["password_hash"] if row else security.DUMMY_HASH
    ok = security.verify_password(password, stored)
    if not row or not ok:
        # Одинаковый ответ для «нет пользователя» и «неверный пароль».
        return jsonify(error="Неверный логин или пароль"), 401

    token = security.create_token(row["id"], row["username"], current_app.config["JWT_SECRET"])
    return jsonify(access_token=token, token_type="Bearer", expires_in=security.JWT_TTL_SECONDS)


@bp.get("/api/data")
def get_data():
    """Список постов (только для аутентифицированных). Необязательный фильтр ?q=."""
    q = request.args.get("q", "", type=str)[:100]
    like = f"%{q}%"
    rows = get_db().execute(
        "SELECT p.id, p.title, p.body, p.created_at, u.username AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id "
        "WHERE p.title LIKE ? OR p.body LIKE ? "
        "ORDER BY p.id DESC LIMIT 100",
        (like, like),
    ).fetchall()
    return jsonify(count=len(rows), items=[_post_to_dict(r) for r in rows])


@bp.post("/api/posts")
def create_post():
    """Создание поста от имени аутентифицированного пользователя."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Ожидается JSON с полями title и body"), 400
    title = data.get("title")
    body = data.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="title и body должны быть строками"), 400
    title, body = title.strip(), body.strip()
    if not title or not body:
        return jsonify(error="title и body не должны быть пустыми"), 400
    if len(title) > MAX_TITLE or len(body) > MAX_BODY:
        return jsonify(error=f"Максимум {MAX_TITLE} символов в title и {MAX_BODY} в body"), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
        (g.user_id, title, body),
    )
    db.commit()
    row = db.execute(
        "SELECT p.id, p.title, p.body, p.created_at, u.username AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ?",
        (cur.lastrowid,),
    ).fetchone()
    return jsonify(_post_to_dict(row)), 201
