from __future__ import annotations

import logging

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routers import admin, auth, awg, health, servers, ui
from app.core.auth import hash_password
from app.core.config import settings
from app.core.logging import setup_logging
from app.db import crud
from app.db.models import GlobalRole, User
from app.db.session import AsyncSessionLocal

log = logging.getLogger(__name__)


async def _bootstrap_admin() -> None:
    try:
        async with AsyncSessionLocal() as session:
            if await crud.count_users(session) > 0:
                return
            user = User(
                username=settings.bootstrap_admin_username,
                password_hash=hash_password(settings.bootstrap_admin_password),
                global_role=GlobalRole.admin,
                is_active=True,
            )
            await crud.create_user(session, user)
            log.warning("Bootstrapped admin user '%s' (please change BOOTSTRAP_ADMIN_PASSWORD).", user.username)
    except Exception as e:  # noqa: BLE001
        log.exception("Failed to bootstrap admin: %s", e)


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)

    app.include_router(health.router)
    app.include_router(auth.router, prefix="/api")
    app.include_router(servers.router, prefix="/api")
    app.include_router(awg.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")
    app.include_router(ui.router, prefix="/ui")

    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    @app.on_event("startup")
    async def _startup() -> None:
        setup_logging(settings.log_level)
        app.state.redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        await _bootstrap_admin()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        redis = getattr(app.state, "redis", None)
        if redis:
            redis.close()
            await redis.wait_closed()

    return app


app = create_app()
