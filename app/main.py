from __future__ import annotations

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routers import health, servers, ui
from app.core.config import settings
from app.core.logging import setup_logging


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)

    app.include_router(health.router)
    app.include_router(servers.router, prefix="/api")
    app.include_router(ui.router, prefix="/ui")

    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    @app.on_event("startup")
    async def _startup() -> None:
        setup_logging(settings.log_level)
        app.state.redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        redis = getattr(app.state, "redis", None)
        if redis:
            redis.close()
            await redis.wait_closed()

    return app


app = create_app()
