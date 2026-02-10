from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_global_role
from app.core.auth import hash_password
from app.db import crud
from app.db.models import (
    GlobalRole,
    InstanceAccessCreate,
    InstanceAccessRead,
    User,
    UserCreate,
    UserRead,
)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserRead])
async def list_users(
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    return await crud.list_users(session)


@router.post("/users", response_model=UserRead)
async def create_user(
    payload: UserCreate,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    existing = await crud.get_user_by_username(session, payload.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        global_role=payload.global_role,
        is_active=payload.is_active,
    )
    return await crud.create_user(session, user)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    await crud.delete_user(session, user_id)
    return {"ok": True}


@router.get("/instances/{instance_id}/access", response_model=list[InstanceAccessRead])
async def list_instance_access(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    inst = await crud.get_instance(session, instance_id)
    if not inst:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found")
    rows = await crud.list_instance_access(session, instance_id)
    return [InstanceAccessRead(**r.model_dump()) for r in rows]


@router.put("/instances/{instance_id}/access", response_model=InstanceAccessRead)
async def upsert_instance_access(
    instance_id: uuid.UUID,
    payload: InstanceAccessCreate,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    inst = await crud.get_instance(session, instance_id)
    if not inst:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found")
    row = await crud.upsert_instance_access(session, payload.user_id, instance_id, payload.role)
    return InstanceAccessRead(**row.model_dump())


@router.delete("/instances/{instance_id}/access/{access_id}")
async def delete_instance_access(
    instance_id: uuid.UUID,
    access_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_global_role(GlobalRole.admin)),
):
    inst = await crud.get_instance(session, instance_id)
    if not inst:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found")
    await crud.delete_instance_access(session, access_id)
    return {"ok": True}
