from __future__ import annotations

import datetime as dt
import uuid
from typing import Optional

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    GlobalRole,
    Instance,
    InstanceAccess,
    InstanceRole,
    InstanceStatus,
    ROLE_RANK,
    User,
    utcnow,
)


# -----------------------------
# Users
# -----------------------------
async def count_users(session: AsyncSession) -> int:
    res = await session.execute(select(func.count(User.id)))
    return int(res.scalar_one())


async def get_user(session: AsyncSession, user_id: uuid.UUID) -> Optional[User]:
    res = await session.execute(select(User).where(User.id == user_id))
    return res.scalar_one_or_none()


async def get_user_by_username(session: AsyncSession, username: str) -> Optional[User]:
    res = await session.execute(select(User).where(User.username == username))
    return res.scalar_one_or_none()


async def list_users(session: AsyncSession) -> list[User]:
    res = await session.execute(select(User).order_by(User.created_at.desc()))
    return list(res.scalars().all())


async def create_user(session: AsyncSession, user: User) -> User:
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def delete_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(delete(User).where(User.id == user_id))
    await session.commit()


# -----------------------------
# Instances
# -----------------------------
async def create_instance(session: AsyncSession, instance: Instance) -> Instance:
    session.add(instance)
    await session.commit()
    await session.refresh(instance)
    return instance


async def get_instance(session: AsyncSession, instance_id: uuid.UUID) -> Optional[Instance]:
    res = await session.execute(select(Instance).where(Instance.id == instance_id))
    return res.scalar_one_or_none()


async def list_instances(session: AsyncSession) -> list[Instance]:
    res = await session.execute(select(Instance).order_by(Instance.created_at.desc()))
    return list(res.scalars().all())


async def list_instances_for_user(session: AsyncSession, user: User) -> list[Instance]:
    if user.global_role == GlobalRole.admin:
        return await list_instances(session)
    res = await session.execute(
        select(Instance)
        .join(InstanceAccess, InstanceAccess.instance_id == Instance.id)
        .where(InstanceAccess.user_id == user.id)
        .order_by(Instance.created_at.desc())
    )
    return list(res.scalars().all())


async def delete_instance(session: AsyncSession, instance_id: uuid.UUID) -> None:
    await session.execute(delete(Instance).where(Instance.id == instance_id))
    await session.commit()


async def update_instance_status(
    session: AsyncSession,
    instance_id: uuid.UUID,
    status: InstanceStatus,
    *,
    last_error: str | None = None,
    checked: bool = False,
    deployed: bool = False,
) -> None:
    inst = await get_instance(session, instance_id)
    if not inst:
        return
    inst.status = status
    inst.last_error = last_error
    now = utcnow()
    inst.updated_at = now
    if checked:
        inst.last_check_at = now
    if deployed:
        inst.last_deploy_at = now
    session.add(inst)
    await session.commit()


# -----------------------------
# RBAC (instance access)
# -----------------------------
async def get_instance_access(session: AsyncSession, user_id: uuid.UUID, instance_id: uuid.UUID) -> Optional[InstanceAccess]:
    res = await session.execute(
        select(InstanceAccess).where(and_(InstanceAccess.user_id == user_id, InstanceAccess.instance_id == instance_id))
    )
    return res.scalar_one_or_none()


async def list_instance_access(session: AsyncSession, instance_id: uuid.UUID) -> list[InstanceAccess]:
    res = await session.execute(select(InstanceAccess).where(InstanceAccess.instance_id == instance_id))
    return list(res.scalars().all())


async def upsert_instance_access(
    session: AsyncSession, user_id: uuid.UUID, instance_id: uuid.UUID, role: InstanceRole
) -> InstanceAccess:
    row = await get_instance_access(session, user_id, instance_id)
    if row:
        row.role = role
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row
    row = InstanceAccess(user_id=user_id, instance_id=instance_id, role=role)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def delete_instance_access(session: AsyncSession, access_id: uuid.UUID) -> None:
    await session.execute(delete(InstanceAccess).where(InstanceAccess.id == access_id))
    await session.commit()


def effective_instance_rank(global_role: GlobalRole, instance_role: InstanceRole) -> int:
    # Global admin bypass is handled elsewhere.
    return min(ROLE_RANK[global_role], ROLE_RANK[instance_role])
