from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.security import CryptoBox
from app.db.models import Instance

log = logging.getLogger(__name__)


def remote_base_url(instance: Instance) -> str:
    return f"{instance.remote_scheme}://{instance.host}:{instance.web_ui_port}"


async def request(
    instance: Instance,
    crypto: CryptoBox,
    method: str,
    path: str,
    json: Any | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> httpx.Response:
    base = remote_base_url(instance).rstrip("/")
    path = path if path.startswith("/") else "/" + path
    url = base + path

    password = crypto.decrypt(instance.nginx_password_enc) or ""
    auth = httpx.BasicAuth(instance.nginx_user, password)

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.request(method, url, json=json, params=params, auth=auth)
        # log a short preview for troubleshooting
        if resp.status_code >= 400:
            log.warning("Remote request failed %s %s -> %s: %s", method, url, resp.status_code, resp.text[:200])
        return resp
