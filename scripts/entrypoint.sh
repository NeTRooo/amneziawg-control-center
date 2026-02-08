#!/usr/bin/env bash
set -euo pipefail

python scripts/wait_for_db.py
alembic upgrade head

exec uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8000}" --proxy-headers
