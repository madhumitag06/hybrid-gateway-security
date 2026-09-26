"""
FastAPI Backend Application Entrypoint
======================================
Adaptive AI-Powered Security Gateway for Hybrid Cloud.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.health import router as health_router
from backend.app.api.v1.dashboard import router as dashboard_router
from backend.app.api.v1.predict import router as predict_router
from backend.app.config import settings
from backend.app.services.ml_service import MLService


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifespan context.
    Preloads Phase 1 ML model artifacts into memory before accepting requests.
    """
    print(f"[*] Starting {settings.app_name} v{settings.app_version}...")
    try:
        predictor = MLService.get_predictor()
        print(f"[+] Successfully loaded Phase 1 ML model artifacts from {settings.ml_artifacts_dir}")
        print(f"    Loaded classes: {predictor.classes}")
    except Exception as e:
        print(f"[!] Warning: Failed to preload ML model artifacts: {e}")
    yield
    print("[*] Shutting down gateway backend.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Adaptive AI-Powered Security Gateway backend exposing real-time ML anomaly detection and continuous risk scoring.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register routes with /api prefix (for standard frontend integration)
app.include_router(health_router, prefix="/api")
app.include_router(predict_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")

# Also include root-level convenience endpoints
app.include_router(health_router)
app.include_router(dashboard_router)


@app.get("/", tags=["Root"])
def root():
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
        "prediction_endpoint": "/api/v1/predict",
    }
