from __future__ import annotations

import logging
import uuid

from app.core.config import settings
from app.core.security import CryptoBox
from app.db import crud
from app.db.models import InstanceStatus
from app.db.session import AsyncSessionLocal
from app.services.deploy import deploy, precheck

log = logging.getLogger(__name__)


def _crypto() -> CryptoBox:
    return CryptoBox.from_key(settings.encryption_key)


async def instance_precheck(ctx, instance_id: str) -> dict:  # noqa: ANN001
    iid = uuid.UUID(instance_id)
    crypto = _crypto()

    async with AsyncSessionLocal() as session:
        inst = await crud.get_instance(session, iid)
        if not inst:
            return {"ok": False, "error": "instance not found"}

        await crud.update_instance_status(session, iid, InstanceStatus.checking, last_error=None)

        report = await precheck(inst, crypto)
        if report.ok:
            new_status = InstanceStatus.ready if inst.status == InstanceStatus.ready else InstanceStatus.new
            await crud.update_instance_status(session, iid, new_status, last_error=None, checked=True)
            return {"ok": True, "details": report.details}
        await crud.update_instance_status(session, iid, InstanceStatus.error, last_error=report.details.get("error"), checked=True)
        return {"ok": False, "details": report.details}


async def instance_deploy(ctx, instance_id: str) -> dict:  # noqa: ANN001
    iid = uuid.UUID(instance_id)
    crypto = _crypto()

    async with AsyncSessionLocal() as session:
        inst = await crud.get_instance(session, iid)
        if not inst:
            return {"ok": False, "error": "instance not found"}

        await crud.update_instance_status(session, iid, InstanceStatus.deploying, last_error=None)

        report = await precheck(inst, crypto)
        if not report.ok:
            await crud.update_instance_status(session, iid, InstanceStatus.error, last_error=report.details.get("error"), checked=True)
            return {"ok": False, "details": report.details}

        try:
            await deploy(inst, crypto)
        except Exception as e:  # noqa: BLE001
            await crud.update_instance_status(session, iid, InstanceStatus.error, last_error=str(e), deployed=True)
            return {"ok": False, "error": str(e)}

        await crud.update_instance_status(session, iid, InstanceStatus.ready, last_error=None, deployed=True)
        return {"ok": True}
