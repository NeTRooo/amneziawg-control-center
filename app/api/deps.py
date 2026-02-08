from __future__ import annotations

from typing import AsyncGenerator

from arq.connections import ArqRedis
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import CryptoBox
from app.db.session import get_session


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async for s in get_session():
        yield s


def get_redis(request: Request) -> ArqRedis:
    return request.app.state.redis  # type: ignore[attr-defined]


def get_crypto() -> CryptoBox:
    return CryptoBox.from_key(settings.encryption_key)
