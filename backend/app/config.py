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

    # Database Configuration (PostgreSQL with psycopg3)
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5434/hybrid_gateway_db"
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20


    # Allowed CORS origins
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Enforcement Configuration (Phase 5)
    default_enforcement_mode: str = "DRY_RUN"  # "DRY_RUN" or "SANDBOX"
    default_rule_ttl_seconds: int = 300  # 5 minutes default
    management_allowlist: List[str] = [
        "127.0.0.1/32",
        "::1/128",
        "192.168.1.1/32",
        "8.8.8.8/32",
        "1.1.1.1/32",
    ]

    # Hybrid Cloud & AWS Telemetry Configuration (Phase 6)
    on_prem_cidrs: List[str] = ["192.168.0.0/16", "10.0.0.0/16"]
    aws_vpc_cidrs: List[str] = ["10.100.0.0/16", "172.31.0.0/16"]
    aws_telemetry_mode: str = "AWS_FIXTURE"  # "AWS_FIXTURE" or "AWS_READ_ONLY"
    aws_region: str = "us-east-1"
    aws_cloudwatch_log_group: str = "/aws/vpc/flow-logs"

    # Optional Security Analyst AI Copilot Configuration (Phase 10)
    # Providers: "none" (default, deterministic synthesis), "groq", "openai"
    ai_provider: str = "none"
    llm_provider: str = "none"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_model: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

