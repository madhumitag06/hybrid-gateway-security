#!/bin/sh
set -e

echo "[gateway-api] Running Alembic database migrations..."
alembic -c /app/backend/alembic.ini upgrade head

echo "[gateway-api] Starting Adaptive AI Security Gateway Control Plane on 0.0.0.0:8000..."
exec uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 1
