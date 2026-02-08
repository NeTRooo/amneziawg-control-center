from __future__ import annotations

import logging

from arq.connections import RedisSettings

from app.core.config import settings
from app.core.logging import setup_logging
from app.workers import tasks

log = logging.getLogger(__name__)


async def startup(ctx) -> None:  # noqa: ANN001
    setup_logging(settings.log_level)
    log.info("Worker startup")


async def shutdown(ctx) -> None:  # noqa: ANN001
    log.info("Worker shutdown")


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(settings.redis_url)

    functions = [
        tasks.precheck_only,
        tasks.precheck_and_deploy,
        tasks.deploy_only,
    ]

    on_startup = startup
    on_shutdown = shutdown

    # Tuning
    job_timeout = 600  # seconds
    max_jobs = 10
