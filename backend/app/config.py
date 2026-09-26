"""
Backend Application Configuration
=================================
Loads environment variables and sets path references for ML artifacts and CORS settings.
"""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ML_ARTIFACTS_DIR = WORKSPACE_ROOT / "ml" / "models"


class Settings(BaseSettings):
    app_name: str = "Adaptive AI Hybrid Security Gateway API"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server binding
    host: str = "127.0.0.1"
    port: int = 8000

    # ML Artifacts directory
    ml_artifacts_dir: Path = DEFAULT_ML_ARTIFACTS_DIR

    # Allowed CORS origins
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")



settings = Settings()
