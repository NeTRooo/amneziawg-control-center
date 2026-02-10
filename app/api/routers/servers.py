from __future__ import annotations

import uuid

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_crypto, get_db_session, get_redis, get_current_user, require_global_role, require_instance_role
from app.core.security import CryptoBox, generate_password
from app.db import crud
from app.db.models import (
    AuthMethod,
    GlobalRole,
    Instance,
    InstanceCreate,
    InstanceRead,
    InstanceRole,
    InstanceStatus,
    InstanceUpdate,
    User,
    utcnow,
)

router = APIRouter(tags=["instances"])


def _apply_secrets(inst: Instance, payload: InstanceCreate | InstanceUpdate, crypto: CryptoBox) -> None:
    # SSH auth
    if getattr(payload, "ssh_password", None):
        inst.ssh_password_enc = crypto.encrypt(payload.ssh_password)  # type: ignore[arg-type]
    if getattr(payload, "ssh_private_key", None):
        inst.ssh_private_key_enc = crypto.encrypt(payload.ssh_private_key)  # type: ignore[arg-type]
    if getattr(payload, "ssh_private_key_passphrase", None):
        inst.ssh_private_key_passphrase_enc = crypto.encrypt(payload.ssh_private_key_passphrase)  # type: ignore[arg-type]

    # Nginx password
    nginx_password = getattr(payload, "nginx_password", None)
    if nginx_password is None and isinstance(payload, InstanceCreate):
        nginx_password = generate_password(24)
    if nginx_password is not None:
        inst.nginx_password_enc = crypto.encrypt(nginx_password)


@router.get("/servers", response_model=list[InstanceRead])
@router.get("/instances", response_model=list[InstanceRead])
async def list_instances(
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    return await crud.list_instances_for_user(session, user)


@router.post("/servers", response_model=InstanceRead, status_code=status.HTTP_201_CREATED)
@router.post("/instances", response_model=InstanceRead, status_code=status.HTTP_201_CREATED)
async def create_instance(
    payload: InstanceCreate,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
    redis: ArqRedis = Depends(get_redis),
    user: User = Depends(require_global_role(GlobalRole.admin, GlobalRole.operator)),
):
    if payload.auth_method == AuthMethod.password and not payload.ssh_password:
        raise HTTPException(status_code=400, detail="ssh_password is required for auth_method=password")
    if payload.auth_method == AuthMethod.key and not payload.ssh_private_key:
        raise HTTPException(status_code=400, detail="ssh_private_key is required for auth_method=key")

    inst = Instance(
        name=payload.name,
        host=payload.host,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        auth_method=payload.auth_method,
        web_ui_port=payload.web_ui_port,
        wg_port=payload.wg_port,
        deploy_dir=payload.deploy_dir,
        awg_image=payload.awg_image,
        remote_scheme=payload.remote_scheme,
        nginx_user=payload.nginx_user,
        status=InstanceStatus.new,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    _apply_secrets(inst, payload, crypto)

    inst = await crud.create_instance(session, inst)

    # Give creator admin access (unless global admin; still fine)
    await crud.upsert_instance_access(session, user.id, inst.id, InstanceRole.admin)

    # Enqueue checks/deploy
    await redis.enqueue_job("instance_precheck", str(inst.id))
    if payload.deploy_now:
        await redis.enqueue_job("instance_deploy", str(inst.id))

    return inst


@router.get("/servers/{instance_id}", response_model=InstanceRead)
@router.get("/instances/{instance_id}", response_model=InstanceRead)
async def get_instance(
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
):
    return instance


@router.patch("/servers/{instance_id}", response_model=InstanceRead)
@router.patch("/instances/{instance_id}", response_model=InstanceRead)
async def update_instance(
    instance_id: uuid.UUID,
    payload: InstanceUpdate,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
    redis: ArqRedis = Depends(get_redis),
    _: User = Depends(require_instance_role(InstanceRole.operator)),
):
    inst = await crud.get_instance(session, instance_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Instance not found")

    for f in ["name", "web_ui_port", "wg_port", "remote_scheme"]:
        v = getattr(payload, f)
        if v is not None:
            setattr(inst, f, v)

    _apply_secrets(inst, payload, crypto)

    inst.updated_at = utcnow()
    session.add(inst)
    await session.commit()
    await session.refresh(inst)

    await redis.enqueue_job("instance_precheck", str(inst.id))
    return inst


@router.post("/servers/{instance_id}/check")
@router.post("/instances/{instance_id}/check")
async def check_instance(
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    redis: ArqRedis = Depends(get_redis),
):
    await redis.enqueue_job("instance_precheck", str(instance.id))
    return {"queued": True}


@router.post("/servers/{instance_id}/deploy")
@router.post("/instances/{instance_id}/deploy")
async def deploy_instance(
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    redis: ArqRedis = Depends(get_redis),
):
    await redis.enqueue_job("instance_deploy", str(instance.id))
    return {"queued": True}


@router.delete("/servers/{instance_id}")
@router.delete("/instances/{instance_id}")
async def delete_instance(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _: User = Depends(require_instance_role(InstanceRole.admin)),
):
    await crud.delete_instance(session, instance_id)
    return {"ok": True}
