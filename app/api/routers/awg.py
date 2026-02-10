from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_crypto, get_db_session, require_instance_role
from app.core.security import CryptoBox
from app.db.models import Instance, InstanceRole
from app.services import remote_api

router = APIRouter(tags=["awg"])


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text or resp.reason_phrase)


@router.get("/servers/{instance_id}/awg/system/status")
@router.get("/instances/{instance_id}/awg/system/status")
async def system_status(
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", "/api/system/status")
    _raise_for_status(resp)
    return resp.json()


@router.get("/servers/{instance_id}/awg/servers")
@router.get("/instances/{instance_id}/awg/servers")
async def list_awg_servers(
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", "/api/servers")
    _raise_for_status(resp)
    return resp.json()


@router.post("/servers/{instance_id}/awg/servers")
@router.post("/instances/{instance_id}/awg/servers")
async def create_awg_server(
    payload: dict[str, Any] = Body(...),
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "POST", "/api/servers", json=payload)
    _raise_for_status(resp)
    return resp.json()


@router.get("/servers/{instance_id}/awg/servers/{server_id}/info")
@router.get("/instances/{instance_id}/awg/servers/{server_id}/info")
async def awg_server_info(
    server_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", f"/api/servers/{server_id}/info")
    _raise_for_status(resp)
    return resp.json()


@router.post("/servers/{instance_id}/awg/servers/{server_id}/start")
@router.post("/instances/{instance_id}/awg/servers/{server_id}/start")
async def awg_server_start(
    server_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "POST", f"/api/servers/{server_id}/start")
    _raise_for_status(resp)
    return resp.json() if resp.headers.get("content-type","").startswith("application/json") else {"ok": True}


@router.post("/servers/{instance_id}/awg/servers/{server_id}/stop")
@router.post("/instances/{instance_id}/awg/servers/{server_id}/stop")
async def awg_server_stop(
    server_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "POST", f"/api/servers/{server_id}/stop")
    _raise_for_status(resp)
    return resp.json() if resp.headers.get("content-type","").startswith("application/json") else {"ok": True}


@router.delete("/servers/{instance_id}/awg/servers/{server_id}")
@router.delete("/instances/{instance_id}/awg/servers/{server_id}")
async def awg_server_delete(
    server_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.admin)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "DELETE", f"/api/servers/{server_id}")
    _raise_for_status(resp)
    return resp.json() if resp.headers.get("content-type","").startswith("application/json") else {"ok": True}


@router.get("/servers/{instance_id}/awg/servers/{server_id}/clients")
@router.get("/instances/{instance_id}/awg/servers/{server_id}/clients")
async def list_clients(
    server_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", f"/api/servers/{server_id}/clients")
    _raise_for_status(resp)
    return resp.json()


@router.post("/servers/{instance_id}/awg/servers/{server_id}/clients")
@router.post("/instances/{instance_id}/awg/servers/{server_id}/clients")
async def add_client(
    server_id: str,
    payload: dict[str, Any] = Body(...),
    instance: Instance = Depends(require_instance_role(InstanceRole.operator)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "POST", f"/api/servers/{server_id}/clients", json=payload)
    _raise_for_status(resp)
    return resp.json()


@router.delete("/servers/{instance_id}/awg/servers/{server_id}/clients/{client_id}")
@router.delete("/instances/{instance_id}/awg/servers/{server_id}/clients/{client_id}")
async def delete_client(
    server_id: str,
    client_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.admin)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "DELETE", f"/api/servers/{server_id}/clients/{client_id}")
    _raise_for_status(resp)
    return resp.json() if resp.headers.get("content-type","").startswith("application/json") else {"ok": True}


@router.get("/servers/{instance_id}/awg/servers/{server_id}/clients/{client_id}/config")
@router.get("/instances/{instance_id}/awg/servers/{server_id}/clients/{client_id}/config")
async def client_config_conf(
    server_id: str,
    client_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", f"/api/servers/{server_id}/clients/{client_id}/config")
    _raise_for_status(resp)
    # Stream back as-is
    return Response(content=resp.content, media_type=resp.headers.get("content-type", "text/plain"))


@router.get("/servers/{instance_id}/awg/servers/{server_id}/clients/{client_id}/config-both")
@router.get("/instances/{instance_id}/awg/servers/{server_id}/clients/{client_id}/config-both")
async def client_config_both(
    server_id: str,
    client_id: str,
    instance: Instance = Depends(require_instance_role(InstanceRole.viewer)),
    crypto: CryptoBox = Depends(get_crypto),
):
    resp = await remote_api.request(instance, crypto, "GET", f"/api/servers/{server_id}/clients/{client_id}/config-both")
    _raise_for_status(resp)
    return resp.json()
