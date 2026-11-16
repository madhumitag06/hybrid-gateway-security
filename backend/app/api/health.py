"""
Health Check API
================
Provides application liveness, readiness, and ML model artifact status.
"""

from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter
from backend.app.config import settings
from backend.app.services.ml_service import MLService

router = APIRouter(tags=["Health"])


@router.get("/health")
def get_health() -> Dict[str, Any]:
    """
    Check backend health, verify that ML model artifacts are loaded,
    and verify PostgreSQL/SQLite database liveness.
    """
    model_loaded = MLService.is_loaded()
    meta = MLService.get_metadata() if model_loaded else {}
    reg = MLService.get_registry_status()
    act = reg.get("active_model_details", {})

    db_status = "connected"
    try:
        from backend.app.db.session import SessionLocal
        from sqlalchemy import text
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unreachable"

    is_healthy = model_loaded and db_status == "connected"

    return {
        "status": "healthy" if is_healthy else ("degraded" if model_loaded else "unhealthy"),
        "app_name": settings.app_name,
        "version": settings.app_version,
        "model_loaded": model_loaded,
        "database_status": db_status,
        "model_type": act.get("algorithm", meta.get("model_type", "Unknown")),
        "model_name": act.get("name", "XGBoost V2"),
        "active_model_version": MLService.get_active_version(),
        "standby_model_version": MLService.get_previous_version(),
        "feature_count": act.get("feature_count", len(meta.get("features", []))),
        "model_features": meta.get("features", []),
        "classes": meta.get("classes", []),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
