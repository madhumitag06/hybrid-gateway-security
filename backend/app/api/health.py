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
    Check backend health and verify that Phase 1 ML model artifacts are loaded.
    """
    model_loaded = MLService.is_loaded()
    meta = MLService.get_metadata() if model_loaded else {}

    return {
        "status": "healthy" if model_loaded else "degraded",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "model_loaded": model_loaded,
        "model_type": meta.get("model_type", "Unknown"),
        "model_features": meta.get("features", []),
        "classes": meta.get("classes", []),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
