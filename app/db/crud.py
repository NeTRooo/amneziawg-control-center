from __future__ import annotations

import datetime as dt
import uuid
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Server, ServerStatus, utcnow


async def create_server(session: AsyncSession, server: Server) -> Server:
    session.add(server)
    await session.commit()
    await session.refresh(server)
    return server


async def get_server(session: AsyncSession, server_id: uuid.UUID) -> Optional[Server]:
    res = await session.execute(select(Server).where(Server.id == server_id))
    return res.scalar_one_or_none()


async def list_servers(session: AsyncSession) -> list[Server]:
    res = await session.execute(select(Server).order_by(Server.created_at.desc()))
    return list(res.scalars().all())


async def update_server_status(
    session: AsyncSession,
    server: Server,
    status: ServerStatus,
    error: str | None = None,
) -> Server:
    server.status = status
    server.last_error = error
    server.updated_at = utcnow()
    if status in (ServerStatus.checking,):
        server.last_check_at = utcnow()
    if status in (ServerStatus.deploying, ServerStatus.ready, ServerStatus.error):
        server.last_deploy_at = utcnow()
    session.add(server)
    await session.commit()
    await session.refresh(server)
    return server


async def patch_server(session: AsyncSession, server: Server, **fields) -> Server:
    for k, v in fields.items():
        if v is not None:
            setattr(server, k, v)
    server.updated_at = utcnow()
    session.add(server)
    await session.commit()
    await session.refresh(server)
    return server


async def delete_server(session: AsyncSession, server: Server) -> None:
    await session.delete(server)
    await session.commit()
