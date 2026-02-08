from __future__ import annotations

import logging
import uuid
from typing import Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_crypto, get_db_session, get_redis
from app.core.security import CryptoBox
from app.db.crud import create_server, get_server, list_servers, patch_server, update_server_status
from app.db.models import AuthMethod, Server, ServerCreate, ServerRead, ServerStatus, ServerUpdate
from app.services.remote_api import request as remote_request

log = logging.getLogger(__name__)

router = APIRouter(tags=["servers"])


@router.post("/servers", response_model=ServerRead, status_code=status.HTTP_201_CREATED)
async def create_server_endpoint(
    payload: ServerCreate,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
    crypto: CryptoBox = Depends(get_crypto),
) -> ServerRead:
    if payload.auth_method == AuthMethod.password and not payload.ssh_password:
        raise HTTPException(status_code=400, detail="ssh_password is required for auth_method=password")
    if payload.auth_method == AuthMethod.key and not payload.ssh_private_key:
        raise HTTPException(status_code=400, detail="ssh_private_key is required for auth_method=key")

    srv = Server(
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
        ssh_password_enc=crypto.encrypt(payload.ssh_password),
        ssh_private_key_enc=crypto.encrypt(payload.ssh_private_key),
        ssh_private_key_passphrase_enc=crypto.encrypt(payload.ssh_private_key_passphrase),
        nginx_password_enc=crypto.encrypt(payload.nginx_password),
        status=ServerStatus.new,
    )
    srv = await create_server(session, srv)

    if payload.deploy_now:
        await redis.enqueue_job("precheck_and_deploy", str(srv.id))

    return ServerRead.from_orm_server(srv)


@router.get("/servers", response_model=list[ServerRead])
async def list_servers_endpoint(
    session: AsyncSession = Depends(get_db_session),
) -> list[ServerRead]:
    servers = await list_servers(session)
    return [ServerRead.from_orm_server(s) for s in servers]


@router.get("/servers/{server_id}", response_model=ServerRead)
async def get_server_endpoint(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ServerRead:
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")
    return ServerRead.from_orm_server(srv)


@router.patch("/servers/{server_id}", response_model=ServerRead)
async def update_server_endpoint(
    server_id: uuid.UUID,
    payload: ServerUpdate,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
) -> ServerRead:
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")

    updated = await patch_server(
        session,
        srv,
        name=payload.name,
        web_ui_port=payload.web_ui_port,
        wg_port=payload.wg_port,
        remote_scheme=payload.remote_scheme,
        ssh_password_enc=crypto.encrypt(payload.ssh_password) if payload.ssh_password else None,
        ssh_private_key_enc=crypto.encrypt(payload.ssh_private_key) if payload.ssh_private_key else None,
        ssh_private_key_passphrase_enc=crypto.encrypt(payload.ssh_private_key_passphrase) if payload.ssh_private_key_passphrase else None,
    )
    return ServerRead.from_orm_server(updated)


@router.post("/servers/{server_id}/check")
async def enqueue_check(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
) -> dict:
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")
    await redis.enqueue_job("precheck_only", str(server_id))
    return {"queued": True}


@router.post("/servers/{server_id}/deploy")
async def enqueue_deploy(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    redis: ArqRedis = Depends(get_redis),
) -> dict:
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")
    await redis.enqueue_job("precheck_and_deploy", str(server_id))
    return {"queued": True}


@router.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_server(
    server_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")

    await update_server_status(session, srv, ServerStatus.removed, error=None)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.api_route(
    "/servers/{server_id}/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_to_remote_awg(
    server_id: uuid.UUID,
    path: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    crypto: CryptoBox = Depends(get_crypto),
) -> Response:
    """Proxy requests to the remote AmneziaWG Web UI API.

    Example:
      GET /api/servers/{id}/proxy/api/servers  -> remote GET {remote_url}/api/servers
    """
    srv = await get_server(session, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="server not found")

    body: Any | None = None
    if request.method in {"POST", "PUT", "PATCH"}:
        # Try JSON; if not JSON - ignore
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None

    resp = await remote_request(
        srv,
        crypto,
        method=request.method,
        path=path,
        json=body,
        params=dict(request.query_params),
    )

    # Pass through status + body (json/text)
    content_type = resp.headers.get("content-type", "application/octet-stream")
    return Response(content=resp.content, status_code=resp.status_code, media_type=content_type)
