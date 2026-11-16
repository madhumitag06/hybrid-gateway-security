"""
Backend Application Configuration
=================================
Loads environment variables and sets path references for ML artifacts, database connections,
security secrets, and CORS settings with robust comma-delimited/JSON list parsing.
"""

import ipaddress
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
        for p in [exe_path.parent] + list(exe_path.parents):
            if (p / "backend").is_dir() and (p / "ml").is_dir():
                return p
        return exe_path.parent
    return Path(__file__).resolve().parent.parent.parent


def get_env_file_path() -> Optional[str]:
    """
    Discovers the appropriate .env file based on explicit override or environment search order:
    1. ENV_FILE environment variable
    2. Current working directory .env
    3. Executable directory .env (alongside AdaptiveSecurityGateway.exe)
    4. Any parent ancestor directory of the executable containing .env (up to workspace root)
    5. Bundled _MEIPASS .env (if frozen)
    6. Workspace root .env based on module path and its ancestors
    7. Default fallback to .env
    """
    explicit = os.getenv("ENV_FILE")
    if explicit and Path(explicit).is_file():
        return str(Path(explicit).resolve())
    
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return str(cwd_env.resolve())
        
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        for p in [exe_path.parent] + list(exe_path.parents):
            candidate = p / ".env"
            if candidate.is_file():
                return str(candidate.resolve())
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            cand = Path(meipass) / ".env"
            if cand.is_file():
                return str(cand.resolve())
            
    for p in [Path(__file__).resolve().parent] + list(Path(__file__).resolve().parents):
        candidate = p / ".env"
        if candidate.is_file():
            return str(candidate.resolve())
        
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
        internal_dir = Path(sys.executable).resolve().parent / "_internal" / "ml" / "models"
        if internal_dir.is_dir():
            return internal_dir
        exe_dir = Path(sys.executable).resolve().parent / "ml" / "models"
        if exe_dir.is_dir():
            return exe_dir

    return Path(__file__).resolve().parent.parent.parent / "ml" / "models"


def get_default_shadow_artifacts_dir() -> Path:
    """
    Resolves the candidate XGBoost V2 model artifacts directory for Shadow Mode.
    """
    explicit = os.getenv("SHADOW_ARTIFACTS_DIR")
    if explicit:
        return Path(explicit).resolve()

    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bundled_dir = Path(meipass) / "ml" / "models" / "candidates" / "bigdata_v2"
            if bundled_dir.is_dir():
                return bundled_dir
        internal_dir = Path(sys.executable).resolve().parent / "_internal" / "ml" / "models" / "candidates" / "bigdata_v2"
        if internal_dir.is_dir():
            return internal_dir
        exe_dir = Path(sys.executable).resolve().parent / "ml" / "models" / "candidates" / "bigdata_v2"
        if exe_dir.is_dir():
            return exe_dir

    return Path(__file__).resolve().parent.parent.parent / "ml" / "models" / "candidates" / "bigdata_v2"


def get_frontend_dist_dir(require_exists: bool = False) -> Optional[Path]:
    """
    Resolves the frontend distribution directory across standalone packaged (frozen)
    and development environments.
    """
    candidates: List[Path] = []

    # 0. Explicit environment variable override
    explicit = os.getenv("FRONTEND_DIST_DIR")
    if explicit:
        candidates.append(Path(explicit).resolve())

    # 1. PyInstaller frozen runtime (_MEIPASS or _internal)
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "dist")
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "dist")
        candidates.append(exe_dir / "dist")
        candidates.append(exe_dir.parent / "dist")

    # 2. Workspace root dist (development & standard python execution)
    ws_root = Path(__file__).resolve().parent.parent.parent
    candidates.append(ws_root / "dist")
    candidates.append(Path.cwd() / "dist")

    # Check candidates in priority order
    for cand in candidates:
        try:
            if cand.is_dir() and (cand / "index.html").is_file():
                return cand.resolve()
        except Exception:
            continue

    if require_exists:
        searched = ", ".join(str(c) for c in candidates)
        raise RuntimeError(
            f"Frontend production distribution ('dist/index.html') not found. Searched locations: {searched}. "
            "Please run 'npm run build' before launching the standalone application."
        )

    return None


WORKSPACE_ROOT = get_workspace_root()
DEFAULT_ML_ARTIFACTS_DIR = get_default_ml_artifacts_dir()
DEFAULT_SHADOW_ARTIFACTS_DIR = get_default_shadow_artifacts_dir()


class Settings(BaseSettings):
    app_name: str = "Adaptive AI Hybrid Security Gateway API"
    app_version: str = "1.0.0"
    app_env: str = "development"
    debug: bool = False
    enable_production_docs: bool = False

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    # Server binding
    host: str = "127.0.0.1"
    port: int = 8000

    # Model Registry & Lifecycle Configuration (Phase 5: Controlled Promotion & Rollback)
    active_model_version: str = os.getenv("ACTIVE_MODEL_VERSION", "candidate_xgboost_v2")
    standby_model_version: str = os.getenv("STANDBY_MODEL_VERSION", "production_rf")

    # ML Artifacts directory
    ml_artifacts_dir: Path = DEFAULT_ML_ARTIFACTS_DIR

    # Shadow Mode Candidate Model Configuration (Phase 3: XGBoost V2 Shadow Evaluation)
    shadow_mode_enabled: bool = True
    shadow_artifacts_dir: Path = DEFAULT_SHADOW_ARTIFACTS_DIR
    shadow_shap_threshold: int = 50
    shadow_persist_records: bool = True

    # Database Configuration (PostgreSQL with psycopg3)
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5434/hybrid_gateway_db"
    secret_key: str = "adaptive-hybrid-gateway-dev-insecure-secret-key-change-in-prod"
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Ingestion & Evaluation Performance Optimization Configuration
    pcap_max_evaluated_flows: int = 500  # Maximum flows for detailed ML inference and persistence
    pcap_max_response_flows: int = 50    # Maximum flow details returned in API response results
    shap_risk_threshold: int = 50        # Continuous risk score threshold to trigger SHAP TreeExplainer calculation
    pcap_db_batch_size: int = 100        # Batch size for PostgreSQL persistence flushes

    # Allowed CORS origins (Supports JSON list or comma-separated strings)
    cors_origins: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Dedicated Management Network Trust Configuration (Phase 22.3 SEC-09)
    # Explicitly permitted CIDR blocks for machine-to-machine API administration.
    # Independent of firewall traffic allowlists. Defaults to loopback only.
    trusted_management_networks: Union[List[str], str] = [
        "127.0.0.1/32",
        "::1/128",
        "10.30.10.0/24",
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
        "10.10.10.2/32",
        "10.20.10.2/32",
        "10.30.10.0/24",
    ]

    # Observable SSH Brute-Force Safeguard Configuration (V2 Policy Guardrail)
    ssh_safeguard_enabled: bool = True
    ssh_burst_window_seconds: float = 60.0
    ssh_monitor_burst_threshold: int = 3
    ssh_restrict_burst_threshold: int = 6
    ssh_block_burst_threshold: int = 12
    ssh_max_bytes_per_probe: int = 10000

    # Hybrid Cloud & AWS Telemetry Configuration (Phase 6 & Virtual Hybrid Lab)
    on_prem_cidrs: Union[List[str], str] = ["192.168.0.0/16", "10.0.0.0/16", "10.10.10.0/24"]
    aws_vpc_cidrs: Union[List[str], str] = ["10.100.0.0/16", "172.31.0.0/16", "10.20.10.0/24"]
    aws_telemetry_mode: str = "AWS_FIXTURE"  # "AWS_FIXTURE" or "AWS_READ_ONLY"
    aws_enabled: bool = True
    aws_account_id: str = "aws-production-01"
    aws_region: str = "us-east-1"
    aws_role_arn: str = ""
    aws_oidc_role_arn: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_cloudwatch_log_group: str = "/aws/vpc/flow-logs"
    aws_vpc_flow_log_group: str = ""

    # Google Cloud Platform (GCP - Google Builders Hub) Configuration
    gcp_enabled: bool = True
    gcp_project_id: str = "gcp-builders-hub-prod"
    gcp_region: str = "us-central1"
    gcp_workload_identity_pool: str = ""
    gcp_workload_identity_provider: str = ""
    gcp_service_account_email: str = ""
    gcp_vpc_cidrs: Union[List[str], str] = ["10.40.0.0/16", "10.40.10.0/24"]

    # Microsoft Azure Configuration
    azure_enabled: bool = True
    azure_subscription_id: str = "sub-azure-enterprise-prod"
    azure_tenant_id: str = "tenant-entra-id-01"
    azure_client_id: str = ""
    azure_region: str = "eastus"
    azure_vnet_cidrs: Union[List[str], str] = ["10.50.0.0/16", "10.50.10.0/24"]

    # Multi-Cloud Containment Safeguard (False = safe dry-run simulation)
    cloud_enforcement_enabled: bool = False

    # Virtual Hybrid-Cloud Docker Lab Integration (Isolated Data/Telemetry Plane)
    hybrid_lab_mode: str = "SIMULATED_HYBRID_LAB"
    lab_router_url: str = "http://10.30.10.2:8099"
    lab_enforcement_enabled: bool = False  # Requires explicit opt-in; defaults to safe SANDBOX/DRY_RUN
    lab_allowed_target_cidrs: Union[List[str], str] = ["10.10.10.0/24", "10.20.10.0/24"]
    lab_telemetry_dir: str = "/var/lib/hybrid-lab/telemetry"

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
    gateway_service_key: Optional[str] = None
    allow_mock_auth: bool = False

    # Default Administrator Bootstrap Credentials
    admin_email: str = "test10@gmail.com"
    admin_password: str = "test@123"
    admin_name: str = "SecOps Administrator"

    # Frontend Client Configuration
    vite_api_base_url: str = "/api"

    @field_validator(
        "cors_origins",
        "management_allowlist",
        "trusted_management_networks",
        "on_prem_cidrs",
        "aws_vpc_cidrs",
        "lab_allowed_target_cidrs",
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

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """
        Enforce fail-closed production security posture:
        - In production, GATEWAY_SERVICE_KEY, AUTH_JWT_SECRET, and SECRET_KEY must be explicitly
          provided, non-empty, minimum 32 characters, and cannot equal any development default string.
        - In production, if ADMIN_EMAIL is set, ADMIN_PASSWORD must be at least 12 characters and
          cannot use development defaults ('test@123', etc.).
        - In production, allow_mock_auth cannot be True.
        - In development / testing, explicitly marked development keys are used if not provided,
          preserving local developer ergonomics.
        """
        env_raw = os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or os.getenv("ENV") or self.app_env or "development"
        env_lower = env_raw.strip().lower()
        self.app_env = env_lower
        is_production = env_lower in ("production", "prod")

        raw_key = self.gateway_service_key
        key_str = raw_key.strip() if isinstance(raw_key, str) else ""

        insecure_dev_keys = {
            "adaptive-gateway-internal-service-key-2026",
            "dev-insecure-gateway-service-key-local-testing-only",
            "changeme",
            "secret",
            "password",
            "admin",
        }
        insecure_jwt_secrets = {
            "adaptive-gateway-jwt-super-secret-key-change-in-production-min-32-chars",
            "hybrid-gateway-production-jwt-signing-key-replace-with-entropy-secret",
            "replace-with-high-entropy-lab-jwt-signing-secret-key-2026",
            "secret",
            "changeme",
            "password",
            "default",
        }
        insecure_secret_keys = {
            "adaptive-hybrid-gateway-dev-insecure-secret-key-change-in-prod",
            "replace-with-high-entropy-lab-secret-key-min-32-chars",
            "secret",
            "changeme",
            "password",
            "default",
        }
        insecure_admin_passwords = {
            "test@123",
            "AdminSecOps2026!",
            "AdminSecret2026!",
            "admin",
            "password",
            "ChangeMe_SecOpsAdmin2026!",
            "ChangeMe_HybridLabDbPass_2026!",
        }

        if is_production:
            if self.allow_mock_auth:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: allow_mock_auth cannot be True in production. Refusing to start."
                )

            # Validate GATEWAY_SERVICE_KEY
            if not key_str:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: GATEWAY_SERVICE_KEY is missing or empty. "
                    "Production deployments require an explicitly configured, high-entropy service key. "
                    "Refusing to start."
                )
            if key_str in insecure_dev_keys or len(key_str) < 32:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: GATEWAY_SERVICE_KEY cannot use development "
                    "defaults and must be at least 32 characters in production. Refusing to start."
                )
            self.gateway_service_key = key_str

            # Validate AUTH_JWT_SECRET
            raw_jwt_secret = self.auth_jwt_secret.strip() if isinstance(self.auth_jwt_secret, str) else ""
            if not raw_jwt_secret:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: AUTH_JWT_SECRET is missing or empty. "
                    "Production deployments require an explicitly configured, high-entropy JWT secret. "
                    "Refusing to start."
                )
            if raw_jwt_secret in insecure_jwt_secrets or len(raw_jwt_secret) < 32:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: AUTH_JWT_SECRET cannot use development "
                    "defaults and must be at least 32 characters in production. Refusing to start."
                )
            self.auth_jwt_secret = raw_jwt_secret

            # Validate SECRET_KEY
            raw_secret_key = self.secret_key.strip() if isinstance(self.secret_key, str) else ""
            if not raw_secret_key:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: SECRET_KEY is missing or empty. "
                    "Production deployments require an explicitly configured, high-entropy secret key. "
                    "Refusing to start."
                )
            if raw_secret_key in insecure_secret_keys or len(raw_secret_key) < 32:
                raise RuntimeError(
                    "CRITICAL PRODUCTION CONFIGURATION ERROR: SECRET_KEY cannot use development "
                    "defaults and must be at least 32 characters in production. Refusing to start."
                )
            self.secret_key = raw_secret_key

            # Validate ADMIN_PASSWORD if automated admin bootstrap is configured
            if self.admin_email and self.admin_email.strip():
                raw_admin_pwd = self.admin_password.strip() if isinstance(self.admin_password, str) else ""
                if not raw_admin_pwd or raw_admin_pwd in insecure_admin_passwords or len(raw_admin_pwd) < 12:
                    raise RuntimeError(
                        "CRITICAL PRODUCTION CONFIGURATION ERROR: ADMIN_PASSWORD cannot use development "
                        "defaults ('test@123') and must be at least 12 characters in production. "
                        "Set an explicit, strong ADMIN_PASSWORD or unset ADMIN_EMAIL to disable automated bootstrap."
                    )
                self.admin_password = raw_admin_pwd
        else:
            if not key_str:
                self.gateway_service_key = "dev-insecure-gateway-service-key-local-testing-only"
            else:
                self.gateway_service_key = key_str

        return self

    def get_trusted_management_networks(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """
        Parses and returns validated IPv4/IPv6 networks configured for trusted API access (SEC-09).
        Fails safely if any entry is invalid by ignoring malformed strings.
        """
        raw_list = self.trusted_management_networks
        if isinstance(raw_list, str):
            raw_list = [item.strip() for item in raw_list.split(",") if item.strip()]
        networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for item in raw_list:
            if not isinstance(item, str) or not item.strip():
                continue
            try:
                net = ipaddress.ip_network(item.strip(), strict=False)
                networks.append(net)
            except ValueError:
                # Invalid CIDR: fail safely by ignoring
                pass
        return networks

    model_config = SettingsConfigDict(
        env_file=get_env_file_path(),
        extra="ignore",
        env_file_encoding="utf-8",
    )


settings = Settings()
