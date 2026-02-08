from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.core.security import CryptoBox
from app.db.models import Server

log = logging.getLogger(__name__)


def remote_base_url(server: Server) -> str:
    return f"{server.remote_scheme}://{server.host}:{server.web_ui_port}"


async def request(
    server: Server,
    crypto: CryptoBox,
    method: str,
    path: str,
    json: Any | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> httpx.Response:
    base = remote_base_url(server).rstrip("/")
    path = path if path.startswith("/") else "/" + path
    url = base + path

    password = crypto.decrypt(server.nginx_password_enc) or ""
    auth = httpx.BasicAuth(server.nginx_user, password)

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.request(method=method.upper(), url=url, auth=auth, json=json, params=params)
        return resp
