"""Криптографические примитивы: хэширование паролей (scrypt) и JWT."""
import base64
import hashlib
import hmac
import os
import secrets
import time

import jwt

# Параметры scrypt (рекомендации OWASP: N=2^17 для production; 2^15 — компромисс
# для учебного проекта и быстрых тестов в CI).
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "secure-api"
JWT_TTL_SECONDS = 15 * 60


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str) -> str:
    """Возвращает строку вида scrypt$N$r$p$salt$hash (соль уникальна для каждого пароля)."""
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=128 * 1024 * 1024,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Проверка пароля за постоянное время (hmac.compare_digest)."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = _b64d(hash_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_b64d(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            maxmem=128 * 1024 * 1024,
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


# Хэш-«пустышка»: проверяем против него, если пользователь не найден, чтобы время
# ответа не выдавало, существует ли логин (защита от перебора имён).
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def create_token(user_id: int, username: str, secret: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
        "iss": JWT_ISSUER,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    """Проверяет подпись, срок действия и издателя. Алгоритм жёстко зафиксирован,
    поэтому токены с alg=none или другим алгоритмом отклоняются."""
    return jwt.decode(
        token,
        secret,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        options={"require": ["exp", "iat", "sub", "iss"]},
    )
