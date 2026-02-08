from __future__ import annotations

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import CryptoBox
from app.core.config import settings
from app.db.crud import get_server, patch_server, update_server_status
from app.db.models import ServerStatus, utcnow
from app.db.session import AsyncSessionLocal
from app.services.deploy import deploy, precheck

log = logging.getLogger(__name__)


def _crypto() -> CryptoBox:
    return CryptoBox.from_key(settings.encryption_key)


async def _with_session(fn, *args, **kwargs):  # noqa: ANN001
    async with AsyncSessionLocal() as session:
        return await fn(session, *args, **kwargs)


async def precheck_only(ctx, server_id: str) -> dict:  # noqa: ANN001
    sid = uuid.UUID(server_id)
    crypto = _crypto()

    async with AsyncSessionLocal() as session:
        srv = await get_server(session, sid)
        if not srv:
            return {"ok": False, "error": "server not found"}

        await update_server_status(session, srv, ServerStatus.checking, error=None)
        report = await precheck(srv, crypto)

        if report.ok:
            await patch_server(session, srv, status=ServerStatus.new, last_error=None, last_check_at=utcnow())
        else:
            await patch_server(session, srv, status=ServerStatus.error, last_error=report.details.get("error"), last_check_at=utcnow())

        return {"ok": report.ok, "details": report.details}


async def deploy_only(ctx, server_id: str) -> dict:  # noqa: ANN001
    sid = uuid.UUID(server_id)
    crypto = _crypto()

    async with AsyncSessionLocal() as session:
        srv = await get_server(session, sid)
        if not srv:
            return {"ok": False, "error": "server not found"}

        await update_server_status(session, srv, ServerStatus.deploying, error=None)

        try:
            await deploy(srv, crypto)
            # deploy() may generate nginx password on the fly
            await patch_server(session, srv, nginx_password_enc=srv.nginx_password_enc)
            await update_server_status(session, srv, ServerStatus.ready, error=None)
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            log.exception("Deploy failed for %s", srv.host)
            await update_server_status(session, srv, ServerStatus.error, error=str(e))
            return {"ok": False, "error": str(e)}


async def precheck_and_deploy(ctx, server_id: str) -> dict:  # noqa: ANN001
    sid = uuid.UUID(server_id)
    crypto = _crypto()

    async with AsyncSessionLocal() as session:
        srv = await get_server(session, sid)
        if not srv:
            return {"ok": False, "error": "server not found"}

        await update_server_status(session, srv, ServerStatus.checking, error=None)
        report = await precheck(srv, crypto)

        if not report.ok:
            await update_server_status(session, srv, ServerStatus.error, error=report.details.get("error"))
            return {"ok": False, "details": report.details}

        await update_server_status(session, srv, ServerStatus.deploying, error=None)

        try:
            await deploy(srv, crypto)
            await patch_server(session, srv, nginx_password_enc=srv.nginx_password_enc)
            await update_server_status(session, srv, ServerStatus.ready, error=None)
            return {"ok": True, "details": report.details}
        except Exception as e:  # noqa: BLE001
            log.exception("Precheck+deploy failed for %s", srv.host)
            await update_server_status(session, srv, ServerStatus.error, error=str(e))
            return {"ok": False, "error": str(e), "details": report.details}
