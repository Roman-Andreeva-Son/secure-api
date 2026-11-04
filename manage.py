"""Управление пользователями: python manage.py create-user <username>

Пароль вводится интерактивно (не попадает в историю shell) либо берётся из
переменной окружения NEW_USER_PASSWORD (удобно для скриптов и CI).
"""
import getpass
import os
import sys

from app import db, security


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "create-user":
        print("Использование: python manage.py create-user <username>")
        return 2
    username = argv[2]
    password = os.environ.get("NEW_USER_PASSWORD") or getpass.getpass("Пароль: ")
    if len(password) < 8:
        print("Пароль должен быть не короче 8 символов")
        return 1
    path = os.environ.get("DATABASE_PATH", "app.db")
    db.init_db(path)
    db.create_user(path, username, security.hash_password(password))
    print(f"Пользователь {username!r} создан")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
