"""
Backend Application Configuration
=================================
Loads environment variables and sets path references for ML artifacts, database connections,
security secrets, and CORS settings with robust comma-delimited/JSON list parsing.
"""

import json
import os
from pathlib import Path
import sys
from typing import Any, List, Optional, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_workspace_root() -> Path:
    """
    Returns the workspace root directory, accounting for frozen PyInstaller bundles.
    """
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        for p in [exe_path.parent, exe_path.parent.parent, exe_path.parent.parent.parent]:
            if (p / ".env").is_file() or (p / "backend").is_dir() or (p / "ml").is_dir():
                return p
        return exe_path.parent
    return Path(__file__).resolve().parent.parent.parent


def get_env_file_path() -> Optional[str]:
    """
    Discovers the appropriate .env file based on explicit override or environment search order:
    1. ENV_FILE environment variable
    2. Current working directory .env
    3. Executable and parent directories .env (if frozen)
    4. Workspace root .env
    """
    explicit = os.getenv("ENV_FILE")
    if explicit and Path(explicit).is_file():
        return str(Path(explicit).resolve())
    
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return str(cwd_env.resolve())
        
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        for p in [exe_path.parent, exe_path.parent.parent, exe_path.parent.parent.parent]:
            candidate = p / ".env"
            if candidate.is_file():
                return str(candidate.resolve())
            
    ws_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if ws_env.is_file():
        return str(ws_env.resolve())
        
    return ".env"


def get_default_ml_artifacts_dir() -> Path:
    """
    Resolves the ML artifacts directory across development and packaged standalone environments.
    """
    explicit = os.getenv("ML_ARTIFACTS_DIR")
    if explicit:
        return Path(explicit).resolve()
        
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bundled_dir = Path(meipass) / "ml" / "models"
            if bundled_dir.is_dir():
                return bundled_dir
        exe_dir = Path(sys.executable).resolve().parent / "ml" / "models"
        if exe_dir.is_dir():
            return exe_dir

    return Path(__file__).resolve().parent.parent.parent / "ml" / "models"


WORKSPACE_ROOT = get_workspace_root()
DEFAULT_ML_ARTIFACTS_DIR = get_default_ml_artifacts_dir()


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
    secret_key: str = "adaptive-hybrid-gateway-dev-insecure-secret-key-change-in-prod"
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Allowed CORS origins (Supports JSON list or comma-separated strings)
    cors_origins: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Enforcement Configuration (Phase 5)
    default_enforcement_mode: str = "DRY_RUN"  # "DRY_RUN" or "SANDBOX"
    default_rule_ttl_seconds: int = 300  # 5 minutes default
    management_allowlist: Union[List[str], str] = [
        "127.0.0.1/32",
        "::1/128",
        "192.168.1.1/32",
        "8.8.8.8/32",
        "1.1.1.1/32",
    ]

    # Hybrid Cloud & AWS Telemetry Configuration (Phase 6)
    on_prem_cidrs: Union[List[str], str] = ["192.168.0.0/16", "10.0.0.0/16"]
    aws_vpc_cidrs: Union[List[str], str] = ["10.100.0.0/16", "172.31.0.0/16"]
    aws_telemetry_mode: str = "AWS_FIXTURE"  # "AWS_FIXTURE" or "AWS_READ_ONLY"
    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_cloudwatch_log_group: str = "/aws/vpc/flow-logs"
    aws_vpc_flow_log_group: str = ""

    # Optional Security Analyst AI Copilot Configuration (Phase 10)
    # Providers: "none" (default, deterministic synthesis), "groq", "openai"
    ai_provider: str = "none"
    llm_provider: str = "none"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_model: str = ""

    # Authentication & User Management Configuration (Phase 13)
    auth_jwt_secret: str = "adaptive-gateway-jwt-super-secret-key-change-in-production-min-32-chars"
    auth_jwt_algorithm: str = "HS256"
    auth_access_token_expire_minutes: int = 60
    auth_refresh_token_expire_days: int = 7
    google_oauth_enabled: bool = False
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:5173/auth/google/callback"

    # Default Administrator Bootstrap Credentials
    admin_email: str = "admin@gateway.local"
    admin_password: str = "AdminSecret2026!"
    admin_name: str = "SecOps Administrator"

    # Frontend Client Configuration
    vite_api_base_url: str = "/api"

    @field_validator(
        "cors_origins",
        "management_allowlist",
        "on_prem_cidrs",
        "aws_vpc_cidrs",
        mode="before",
    )
    @classmethod
    def parse_comma_or_json_list(cls, v: Any) -> List[str]:
        """
        Parses both standard comma-separated environment strings and JSON array strings
        into a clean, normalized List[str].
        """
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        if isinstance(v, str):
            v_clean = v.strip()
            if not v_clean:
                return []
            if v_clean.startswith("[") and v_clean.endswith("]"):
                try:
                    parsed = json.loads(v_clean)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            items = []
            for item in v_clean.split(","):
                cleaned = item.strip().strip("'\"")
                if cleaned:
                    items.append(cleaned)
            return items
        return [str(v)]

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, v: Any) -> str:
        """
        Normalizes legacy postgres:// scheme to postgresql:// for SQLAlchemy 2.0+ compatibility.
        """
        if isinstance(v, str):
            v_str = v.strip()
            if v_str.startswith("postgres://"):
                return "postgresql://" + v_str[len("postgres://"):]
            return v_str
        return str(v)

    @model_validator(mode="after")
    def sync_log_groups(self) -> "Settings":
        """
        Synchronizes AWS_VPC_FLOW_LOG_GROUP with aws_cloudwatch_log_group if explicitly set.
        """
        if self.aws_vpc_flow_log_group and self.aws_vpc_flow_log_group.strip():
            self.aws_cloudwatch_log_group = self.aws_vpc_flow_log_group.strip()
        return self

    model_config = SettingsConfigDict(
        env_file=get_env_file_path(),
        extra="ignore",
        env_file_encoding="utf-8",
    )


settings = Settings()
