from __future__ import annotations

import uuid
from typing import AsyncGenerator, Callable, Optional

from arq.connections import ArqRedis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import decode_token, subject_to_uuid
from app.core.config import settings
from app.core.security import CryptoBox
from app.db import crud
from app.db.models import GlobalRole, Instance, InstanceRole, User, ROLE_RANK
from app.db.session import get_session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async for s in get_session():
        yield s


def get_redis(request: Request) -> ArqRedis:
    return request.app.state.redis  # type: ignore[attr-defined]


def get_crypto() -> CryptoBox:
    return CryptoBox.from_key(settings.encryption_key)


def _extract_token(request: Request, header_token: Optional[str]) -> Optional[str]:
    if header_token:
        return header_token
    # UI cookie
    cookie = request.cookies.get(settings.auth_cookie_name)
    if not cookie:
        return None
    # Allow optional "Bearer " prefix
    return cookie.split(" ", 1)[1] if cookie.lower().startswith("bearer ") else cookie


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    header_token: Optional[str] = Depends(oauth2_scheme),
) -> User:
    token = _extract_token(request, header_token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = decode_token(token)
        sub = payload.get("sub")
        if not sub:
            raise ValueError("missing sub")
        user_id = subject_to_uuid(str(sub))
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = await crud.get_user(session, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user


def require_global_role(*roles: GlobalRole) -> Callable[[User], User]:
    async def _dep(user: User = Depends(get_current_user)) -> User:
        if user.global_role == GlobalRole.admin:
            return user
        if user.global_role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user

    return _dep


def require_instance_role(required: InstanceRole) -> Callable[..., Instance]:
    async def _dep(
        instance_id: uuid.UUID,
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_db_session),
    ) -> Instance:
        inst = await crud.get_instance(session, instance_id)
        if not inst:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found")

        if user.global_role == GlobalRole.admin:
            return inst

        access = await crud.get_instance_access(session, user.id, inst.id)
        if not access:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this instance")

        eff = crud.effective_instance_rank(user.global_role, access.role)
        if eff < ROLE_RANK[required]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return inst

    return _dep
