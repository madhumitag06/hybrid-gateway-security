"""
FastAPI Backend Application Entrypoint
======================================
Adaptive AI-Powered Security Gateway for Hybrid Cloud (Phase 3: PostgreSQL Enabled).
"""

from contextlib import asynccontextmanager
import threading
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.health import router as health_router
from backend.app.api.v1.analytics import router as analytics_router
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.dashboard import router as dashboard_router
from backend.app.api.v1.enforcement import router as enforcement_router
from backend.app.api.v1.evaluation import router as evaluation_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.hybrid import router as hybrid_router
from backend.app.api.v1.ingest import router as ingest_router
from backend.app.api.v1.predict import router as predict_router
from backend.app.config import get_frontend_dist_dir, settings
from backend.app.db.session import SessionLocal, init_db
from backend.app.services.auth_service import AuthService
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.ml_service import MLService


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifespan context.
    Preloads Phase 1 ML model artifacts, initializes PostgreSQL database,
    bootstraps the initial admin account, and reconciles active containment rules.
    """
    print(f"[*] Starting {settings.app_name} v{settings.app_version}...")

    # 1. Preload Phase 1 ML Model Artifacts
    try:
        predictor = MLService.get_predictor()
        print(f"[+] Successfully loaded Phase 1 ML model artifacts from {settings.ml_artifacts_dir}")
        print(f"    Classes: {predictor.classes}")
    except Exception as e:
        print(f"[!] Warning: Failed to preload ML model artifacts: {e}")

    # 2. Initialize Database & Seed Baseline Demo Events if empty
    try:
        print(f"[*] Initializing PostgreSQL database connection ({settings.database_url.split('@')[-1]})...")
        init_db()
        with SessionLocal() as db:
            DashboardService.seed_initial_data_if_empty(db)
            # 3. Bootstrap Initial Admin User if needed
            AuthService.bootstrap_admin_user_if_needed(db)
            # 4. Reconcile Active Containment Rules into Sandbox
            EnforcementService.reconcile_from_db(db)
            db.commit()
        print("[+] PostgreSQL database initialized, admin verified, and rules reconciled.")
    except Exception as e:
        print(f"[!] Warning: Database initialization notice: {e}")

    stop_event = threading.Event()

    def _enforcement_maintenance_loop() -> None:
        while not stop_event.wait(2.0):
            try:
                with SessionLocal() as bg_db:
                    expired_ids = EnforcementService.prune_expired(db=bg_db)
                    if expired_ids:
                        bg_db.commit()
                EnforcementService.get_sandbox_adapter().ensure_router_convergence()
            except Exception:
                pass

    maintenance_thread = threading.Thread(
        target=_enforcement_maintenance_loop,
        name="enforcement-ttl-pruner",
        daemon=True,
    )
    maintenance_thread.start()

    yield
    stop_event.set()
    print("[*] Shutting down gateway backend.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Adaptive AI-Powered Security Gateway backend exposing real-time ML anomaly detection, continuous risk scoring, and PostgreSQL event history.",
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
app.include_router(auth_router, prefix="/api")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(predict_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(ingest_router, prefix="/api")
app.include_router(enforcement_router, prefix="/api")
app.include_router(hybrid_router, prefix="/api/v1")
app.include_router(hybrid_router, prefix="/api")
app.include_router(analytics_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/api")
app.include_router(evaluation_router, prefix="/api/v1")
app.include_router(evaluation_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")

# Also include root-level convenience endpoints
app.include_router(health_router)
app.include_router(dashboard_router)


def _get_root_info():
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "status": "online",
        "database": "PostgreSQL Connected",
        "docs": "/docs",
        "health": "/api/health",
        "prediction_endpoint": "/api/v1/predict",
        "events_endpoint": "/api/v1/events",
        "ingestion_endpoint": "/api/v1/ingest/pcap",
        "enforcement_endpoint": "/api/v1/enforcement/rules",
    }


@app.get("/api", tags=["Root"])
def root_api():
    return _get_root_info()


_dist_dir = get_frontend_dist_dir()
if _dist_dir and (_dist_dir / "index.html").is_file():
    print(f"[+] Serving frontend distribution from: {_dist_dir}")
    _assets_dir = _dist_dir / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")

    @app.get("/", tags=["Root"])
    def root(request: Request):
        accept = request.headers.get("accept", "")
        # Serve React frontend for browser navigation requests
        if "text/html" in accept:
            return FileResponse(_dist_dir / "index.html")
        return _get_root_info()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str, request: Request):
        # Do not intercept API or docs routes
        if (
            full_path.startswith("api/")
            or full_path == "api"
            or full_path.startswith("docs")
            or full_path.startswith("redoc")
            or full_path.startswith("openapi.json")
        ):
            raise HTTPException(status_code=404, detail="API route not found")
        file_cand = _dist_dir / full_path
        if full_path and file_cand.is_file():
            return FileResponse(file_cand)
        return FileResponse(_dist_dir / "index.html")
else:
    @app.get("/", tags=["Root"])
    def root():
        return _get_root_info()
