from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(*, subject: str, expires_minutes: Optional[int] = None, extra: dict[str, Any] | None = None) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    minutes = expires_minutes if expires_minutes is not None else settings.jwt_access_token_minutes
    exp = now + dt.timedelta(minutes=minutes)
    payload: dict[str, Any] = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as e:
        raise ValueError("Invalid token") from e


def subject_to_uuid(sub: str) -> uuid.UUID:
    try:
        return uuid.UUID(sub)
    except Exception as e:  # noqa: BLE001
        raise ValueError("Invalid subject") from e
