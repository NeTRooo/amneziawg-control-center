from __future__ import annotations

import uuid
from typing import Any, Optional

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_crypto, get_db_session, get_redis
from app.core.auth import create_access_token, decode_token, subject_to_uuid, verify_password
from app.core.config import settings
from app.core.security import CryptoBox, generate_password
from app.db import crud
from app.db.models import (
    AuthMethod,
    GlobalRole,
    Instance,
    InstanceCreate,
    InstanceRole,
    InstanceStatus,
    InstanceUpdate,
    ROLE_RANK,
    User,
    utcnow,
)
from app.services import remote_api

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


async def _ui_user(request: Request, session: AsyncSession) -> Optional[User]:
    token = request.cookies.get(settings.auth_cookie_name)
    if not token:
        return None
    token = token.split(" ", 1)[1] if token.lower().startswith("bearer ") else token
    try:
        payload = decode_token(token)
        sub = payload.get("sub")
        if not sub:
            return None
        user_id = subject_to_uuid(str(sub))
    except Exception:  # noqa: BLE001
        return None
    user = await crud.get_user(session, user_id)
    if not user or not user.is_active:
        return None
    return user


def _set_auth_cookie(resp: RedirectResponse, token: str) -> RedirectResponse:
    resp.set_cookie(
        settings.auth_cookie_name,
        token,
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind HTTPS
        max_age=settings.jwt_access_token_minutes * 60,
        path="/",
    )
    return resp


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_db_session),
):
    user = await crud.get_user_by_username(session, username)
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный логин или пароль"},
            status_code=401,
        )
    token = create_access_token(subject=str(user.id))
    resp = _redirect("/ui/servers")
    return _set_auth_cookie(resp, token)


@router.get("/logout")
async def logout_action():
    resp = _redirect("/ui/login")
    resp.delete_cookie(settings.auth_cookie_name, path="/")
    return resp


@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return _redirect("/ui/servers")


@router.get("/servers", response_class=HTMLResponse)
@router.get("/instances", response_class=HTMLResponse)
async def servers_page(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")

    instances = await crud.list_instances_for_user(session, user)
    return templates.TemplateResponse(
        "servers.html",
        {"request": request, "user": user, "instances": instances},
    )


@router.get("/servers/add", response_class=HTMLResponse)
async def add_server_page(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role not in (GlobalRole.admin, GlobalRole.operator):
        return templates.TemplateResponse("error.html", {"request": request, "user": user, "error": "Недостаточно прав"}, status_code=403)

    return templates.TemplateResponse("add_server.html", {"request": request, "user": user})


@router.post("/servers/add")
async def add_server_action(
    request: Request,
    name: str = Form(...),
    host: str = Form(...),
    ssh_port: int = Form(22),
    ssh_user: str = Form("root"),
    auth_method: str = Form("key"),
    ssh_password: str = Form(""),
    ssh_private_key: str = Form(""),
    ssh_private_key_passphrase: str = Form(""),
    web_ui_port: int = Form(8080),
    wg_port: int = Form(51820),
    remote_scheme: str = Form("http"),
    nginx_user: str = Form("admin"),
    nginx_password: str = Form(""),
    deploy_now: bool = Form(False),
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
    redis: ArqRedis = Depends(get_redis),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role not in (GlobalRole.admin, GlobalRole.operator):
        return templates.TemplateResponse("error.html", {"request": request, "user": user, "error": "Недостаточно прав"}, status_code=403)

    method = AuthMethod(auth_method)

    payload = InstanceCreate(
        name=name,
        host=host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        auth_method=method,
        ssh_password=ssh_password or None,
        ssh_private_key=ssh_private_key or None,
        ssh_private_key_passphrase=ssh_private_key_passphrase or None,
        web_ui_port=web_ui_port,
        wg_port=wg_port,
        remote_scheme=remote_scheme,
        nginx_user=nginx_user,
        nginx_password=nginx_password or None,
        deploy_now=deploy_now,
    )

    if payload.auth_method == AuthMethod.password and not payload.ssh_password:
        return templates.TemplateResponse("add_server.html", {"request": request, "user": user, "error": "ssh_password обязателен для auth_method=password"})
    if payload.auth_method == AuthMethod.key and not payload.ssh_private_key:
        return templates.TemplateResponse("add_server.html", {"request": request, "user": user, "error": "ssh_private_key обязателен для auth_method=key"})

    inst = Instance(
        name=payload.name,
        host=payload.host,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        auth_method=payload.auth_method,
        web_ui_port=payload.web_ui_port,
        wg_port=payload.wg_port,
        deploy_dir=settings.remote_deploy_dir,
        awg_image=settings.awg_image,
        remote_scheme=payload.remote_scheme,
        nginx_user=payload.nginx_user,
        status=InstanceStatus.new,
        created_at=utcnow(),
        updated_at=utcnow(),
    )

    # encrypt secrets
    if payload.ssh_password:
        inst.ssh_password_enc = crypto.encrypt(payload.ssh_password)
    if payload.ssh_private_key:
        inst.ssh_private_key_enc = crypto.encrypt(payload.ssh_private_key)
    if payload.ssh_private_key_passphrase:
        inst.ssh_private_key_passphrase_enc = crypto.encrypt(payload.ssh_private_key_passphrase)
    pw = payload.nginx_password or generate_password(24)
    inst.nginx_password_enc = crypto.encrypt(pw)

    inst = await crud.create_instance(session, inst)
    await crud.upsert_instance_access(session, user.id, inst.id, InstanceRole.admin)

    await redis.enqueue_job("instance_precheck", str(inst.id))
    if payload.deploy_now:
        await redis.enqueue_job("instance_deploy", str(inst.id))

    return _redirect(f"/ui/servers/{inst.id}")


async def _get_instance_for_ui(
    request: Request,
    session: AsyncSession,
    instance_id: uuid.UUID,
    required: InstanceRole,
) -> tuple[Optional[User], Optional[Instance], Optional[RedirectResponse], Optional[str]]:
    user = await _ui_user(request, session)
    if not user:
        return None, None, _redirect("/ui/login"), None

    inst = await crud.get_instance(session, instance_id)
    if not inst:
        return user, None, _redirect("/ui/servers"), "Инстанс не найден"

    if user.global_role == GlobalRole.admin:
        return user, inst, None, None

    access = await crud.get_instance_access(session, user.id, instance_id)
    if not access:
        return user, None, _redirect("/ui/servers"), "Нет доступа к инстансу"

    eff = crud.effective_instance_rank(user.global_role, access.role)
    if eff < ROLE_RANK[required]:
        return user, None, _redirect("/ui/servers"), "Недостаточно прав"

    return user, inst, None, None


@router.get("/servers/{instance_id}", response_class=HTMLResponse)
async def instance_detail_page(
    request: Request,
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, err = await _get_instance_for_ui(request, session, instance_id, InstanceRole.viewer)
    if redir:
        return redir
    assert user and inst

    # Remote status
    system_status: Any = None
    awg_servers: Any = None
    remote_error: str | None = None
    try:
        resp = await remote_api.request(inst, crypto, "GET", "/api/system/status")
        if resp.status_code < 400:
            system_status = resp.json()
        else:
            remote_error = resp.text[:200]
    except Exception as e:  # noqa: BLE001
        remote_error = str(e)

    try:
        resp = await remote_api.request(inst, crypto, "GET", "/api/servers")
        if resp.status_code < 400:
            awg_servers = resp.json()
        else:
            remote_error = remote_error or resp.text[:200]
    except Exception as e:  # noqa: BLE001
        remote_error = remote_error or str(e)

    return templates.TemplateResponse(
        "instance_detail.html",
        {
            "request": request,
            "user": user,
            "instance": inst,
            "system_status": system_status,
            "awg_servers": awg_servers,
            "remote_error": remote_error,
        },
    )


@router.post("/servers/{instance_id}/check")
async def ui_instance_check(
    request: Request,
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.operator)
    if redir:
        return redir
    assert inst
    await redis.enqueue_job("instance_precheck", str(inst.id))
    return _redirect(f"/ui/servers/{inst.id}")


@router.post("/servers/{instance_id}/deploy")
async def ui_instance_deploy(
    request: Request,
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.operator)
    if redir:
        return redir
    assert inst
    await redis.enqueue_job("instance_deploy", str(inst.id))
    return _redirect(f"/ui/servers/{inst.id}")


@router.post("/servers/{instance_id}/delete")
async def ui_instance_delete(
    request: Request,
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.admin)
    if redir:
        return redir
    assert inst
    await crud.delete_instance(session, inst.id)
    return _redirect("/ui/servers")


@router.get("/servers/{instance_id}/awg/servers/{awg_server_id}", response_class=HTMLResponse)
async def ui_awg_server_page(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.viewer)
    if redir:
        return redir
    assert user and inst

    info: Any = None
    clients: Any = None
    remote_error: str | None = None
    try:
        r = await remote_api.request(inst, crypto, "GET", f"/api/servers/{awg_server_id}/info")
        if r.status_code < 400:
            info = r.json()
        else:
            remote_error = r.text[:200]
    except Exception as e:  # noqa: BLE001
        remote_error = str(e)

    try:
        r = await remote_api.request(inst, crypto, "GET", f"/api/servers/{awg_server_id}/clients")
        if r.status_code < 400:
            clients = r.json()
        else:
            remote_error = remote_error or r.text[:200]
    except Exception as e:  # noqa: BLE001
        remote_error = remote_error or str(e)

    return templates.TemplateResponse(
        "awg_server_detail.html",
        {
            "request": request,
            "user": user,
            "instance": inst,
            "awg_server_id": awg_server_id,
            "info": info,
            "clients": clients,
            "remote_error": remote_error,
        },
    )


@router.post("/servers/{instance_id}/awg/servers/{awg_server_id}/start")
async def ui_awg_server_start(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.operator)
    if redir:
        return redir
    assert inst
    await remote_api.request(inst, crypto, "POST", f"/api/servers/{awg_server_id}/start")
    return _redirect(f"/ui/servers/{instance_id}")


@router.post("/servers/{instance_id}/awg/servers/{awg_server_id}/stop")
async def ui_awg_server_stop(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.operator)
    if redir:
        return redir
    assert inst
    await remote_api.request(inst, crypto, "POST", f"/api/servers/{awg_server_id}/stop")
    return _redirect(f"/ui/servers/{instance_id}")


@router.post("/servers/{instance_id}/awg/servers/{awg_server_id}/delete")
async def ui_awg_server_delete(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.admin)
    if redir:
        return redir
    assert inst
    await remote_api.request(inst, crypto, "DELETE", f"/api/servers/{awg_server_id}")
    return _redirect(f"/ui/servers/{instance_id}")


@router.post("/servers/{instance_id}/awg/servers/{awg_server_id}/clients/add")
async def ui_client_add(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    client_name: str = Form(...),
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.operator)
    if redir:
        return redir
    assert inst
    await remote_api.request(inst, crypto, "POST", f"/api/servers/{awg_server_id}/clients", json={"name": client_name})
    return _redirect(f"/ui/servers/{instance_id}/awg/servers/{awg_server_id}")


@router.post("/servers/{instance_id}/awg/servers/{awg_server_id}/clients/{client_id}/delete")
async def ui_client_delete(
    request: Request,
    instance_id: uuid.UUID,
    awg_server_id: str,
    client_id: str,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
):
    user, inst, redir, _ = await _get_instance_for_ui(request, session, instance_id, InstanceRole.admin)
    if redir:
        return redir
    assert inst
    await remote_api.request(inst, crypto, "DELETE", f"/api/servers/{awg_server_id}/clients/{client_id}")
    return _redirect(f"/ui/servers/{instance_id}/awg/servers/{awg_server_id}")


# -----------------------------
# Admin UI (global admin)
# -----------------------------
@router.get("/admin/users", response_class=HTMLResponse)
async def ui_admin_users(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return templates.TemplateResponse("error.html", {"request": request, "user": user, "error": "Только admin"}, status_code=403)

    users = await crud.list_users(session)
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users})


@router.post("/admin/users/add")
async def ui_admin_users_add(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    global_role: str = Form("viewer"),
    is_active: bool = Form(True),
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return _redirect("/ui/servers")

    from app.core.auth import hash_password  # local import

    existing = await crud.get_user_by_username(session, username)
    if existing:
        return _redirect("/ui/admin/users")

    new_user = User(username=username, password_hash=hash_password(password), global_role=GlobalRole(global_role), is_active=is_active)
    await crud.create_user(session, new_user)
    return _redirect("/ui/admin/users")


@router.post("/admin/users/{user_id}/delete")
async def ui_admin_users_delete(
    request: Request,
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return _redirect("/ui/servers")
    await crud.delete_user(session, user_id)
    return _redirect("/ui/admin/users")


@router.get("/admin/servers/{instance_id}/access", response_class=HTMLResponse)
async def ui_admin_instance_access(
    request: Request,
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return _redirect("/ui/servers")

    inst = await crud.get_instance(session, instance_id)
    if not inst:
        return _redirect("/ui/servers")
    users = await crud.list_users(session)
    access = await crud.list_instance_access(session, instance_id)
    access_map = {a.user_id: a for a in access}

    return templates.TemplateResponse(
        "admin_instance_access.html",
        {"request": request, "user": user, "instance": inst, "users": users, "access_map": access_map},
    )


@router.post("/admin/servers/{instance_id}/access/set")
async def ui_admin_instance_access_set(
    request: Request,
    instance_id: uuid.UUID,
    user_id: uuid.UUID = Form(...),
    role: str = Form("viewer"),
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return _redirect("/ui/servers")
    await crud.upsert_instance_access(session, user_id, instance_id, InstanceRole(role))
    return _redirect(f"/ui/admin/servers/{instance_id}/access")


@router.post("/admin/servers/{instance_id}/access/{access_id}/delete")
async def ui_admin_instance_access_delete(
    request: Request,
    instance_id: uuid.UUID,
    access_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
):
    user = await _ui_user(request, session)
    if not user:
        return _redirect("/ui/login")
    if user.global_role != GlobalRole.admin:
        return _redirect("/ui/servers")
    await crud.delete_instance_access(session, access_id)
    return _redirect(f"/ui/admin/servers/{instance_id}/access")
