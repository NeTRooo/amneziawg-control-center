from __future__ import annotations

import logging

from sqlalchemy import select

from app.core.auth import hash_password
from app.core.config import settings
from app.db.models import User, UserRole
from app.db.session import AsyncSessionLocal

log = logging.getLogger(__name__)


async def ensure_bootstrap_admin() -> None:
    """Create the first admin user if the DB is empty."""
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(User).limit(1))
        any_user = res.scalar_one_or_none()
        if any_user:
            return

        if not settings.bootstrap_admin_password:
            raise RuntimeError(
                "BOOTSTRAP_ADMIN_PASSWORD is required on first start (DB is empty). "
                "Set it in .env"
            )

        admin = User(
            username=settings.bootstrap_admin_username,
            password_hash=hash_password(settings.bootstrap_admin_password),
            global_role=UserRole.admin,
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        log.warning("Bootstrap admin created: %s", settings.bootstrap_admin_username)
