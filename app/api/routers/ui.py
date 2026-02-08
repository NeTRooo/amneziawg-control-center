from __future__ import annotations

import uuid

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_crypto, get_db_session, get_redis
from app.core.security import CryptoBox
from app.db.crud import create_server, get_server, list_servers
from app.db.models import AuthMethod, Server, ServerStatus

templates = Jinja2Templates(directory="app/templates")

router = APIRouter(default_response_class=HTMLResponse, tags=["ui"])


@router.get("/")
async def ui_index() -> RedirectResponse:
    return RedirectResponse(url="/ui/servers", status_code=302)


@router.get("/servers")
async def ui_servers(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> HTMLResponse:
    servers = await list_servers(session)
    return templates.TemplateResponse(
        "servers.html",
        {"request": request, "servers": servers},
    )


@router.get("/servers/add")
async def ui_add_server(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("add_server.html", {"request": request})


@router.post("/servers/add")
async def ui_add_server_post(
    request: Request,
    name: str = Form(...),
    host: str = Form(...),
    ssh_port: int = Form(22),
    ssh_user: str = Form("root"),
    auth_method: str = Form("key"),
    ssh_password: str | None = Form(None),
    ssh_private_key: str | None = Form(None),
    ssh_private_key_passphrase: str | None = Form(None),
    web_ui_port: int = Form(8080),
    wg_port: int = Form(51820),
    deploy_dir: str = Form("/opt/amneziawg-web-ui"),
    awg_image: str = Form("alexishw/amneziawg-web-ui:latest"),
    nginx_user: str = Form("admin"),
    nginx_password: str | None = Form(None),
    deploy_now: bool = Form(False),
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
    crypto: CryptoBox = Depends(get_crypto),
) -> RedirectResponse:
    method = AuthMethod.password if auth_method == "password" else AuthMethod.key

    srv = Server(
        name=name,
        host=host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        auth_method=method,
        web_ui_port=web_ui_port,
        wg_port=wg_port,
        deploy_dir=deploy_dir,
        awg_image=awg_image,
        nginx_user=nginx_user,
        ssh_password_enc=crypto.encrypt(ssh_password),
        ssh_private_key_enc=crypto.encrypt(ssh_private_key),
        ssh_private_key_passphrase_enc=crypto.encrypt(ssh_private_key_passphrase),
        nginx_password_enc=crypto.encrypt(nginx_password),
        status=ServerStatus.new,
    )
    srv = await create_server(session, srv)

    if deploy_now:
        await redis.enqueue_job("precheck_and_deploy", str(srv.id))

    return RedirectResponse(url="/ui/servers", status_code=303)


@router.post("/servers/{server_id}/check")
async def ui_check_server(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
) -> RedirectResponse:
    srv = await get_server(session, server_id)
    if srv:
        await redis.enqueue_job("precheck_only", str(server_id))
    return RedirectResponse(url="/ui/servers", status_code=303)


@router.post("/servers/{server_id}/deploy")
async def ui_deploy_server(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
) -> RedirectResponse:
    srv = await get_server(session, server_id)
    if srv:
        await redis.enqueue_job("precheck_and_deploy", str(server_id))
    return RedirectResponse(url="/ui/servers", status_code=303)
