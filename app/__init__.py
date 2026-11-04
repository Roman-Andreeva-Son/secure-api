"""Фабрика Flask-приложения: конфигурация, JWT-middleware, заголовки безопасности."""
import logging
import os
import secrets

import jwt
from flask import Flask, g, jsonify, request

from . import db, security
from .routes import bp

# Эндпоинты, доступные без токена. Всё остальное закрыто по умолчанию (deny by default).
PUBLIC_ENDPOINTS = {"api.login", "api.health"}


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.json.ensure_ascii = False  # читаемая кириллица в JSON; HTML-символы экранируются отдельно
    app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "app.db")
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # маленький лимит тела запроса

    secret = os.environ.get("JWT_SECRET")
    if not secret:
        # Секрет не должен храниться в коде. Если он не задан — генерируем на время
        # работы процесса (токены перестанут действовать после перезапуска).
        secret = secrets.token_hex(32)
        logging.getLogger(__name__).warning("JWT_SECRET не задан, использован временный секрет")
    app.config["JWT_SECRET"] = secret

    if config:
        app.config.update(config)

    db.init_db(app.config["DATABASE"])
    app.teardown_appcontext(db.close_db)
    app.register_blueprint(bp)

    @app.before_request
    def jwt_middleware():
        """Проверка JWT для всех защищённых эндпоинтов."""
        if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
            return None
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return jsonify(error="Требуется токен в заголовке Authorization: Bearer <token>"), 401
        try:
            claims = security.decode_token(token, app.config["JWT_SECRET"])
        except jwt.PyJWTError:
            return jsonify(error="Недействительный или просроченный токен"), 401
        g.user_id = int(claims["sub"])
        g.username = claims["username"]
        return None

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="Не найдено"), 404

    @app.errorhandler(405)
    def not_allowed(_e):
        return jsonify(error="Метод не поддерживается"), 405

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error="Слишком большое тело запроса"), 413

    return app
