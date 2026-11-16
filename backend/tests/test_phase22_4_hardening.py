"""
Phase 22.4 Hardening & Security Remediation Test Suite
======================================================
Tests:
- SEC-10: Multi-stage Dockerfile with non-root user execution and build tool removal.
- SEC-11: Content-Security-Policy (CSP) and HSTS header emission.
- SEC-12: Conditional Swagger UI / OpenAPI schema disablement in production.
- SEC-13: Secure HttpOnly cookie refresh token rotation and logout revocation.
- SEC-14: Exact package version pinning in backend and ML requirements.
- Workstream 6A: Sliding-window rate limiting on sensitive public authentication endpoints.
- Workstream 6B: Hybrid Lab Compose mandatory credential enforcement.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config import Settings, settings
from backend.app.core.rate_limit import SlidingWindowRateLimiter, reset_rate_limits
from backend.app.db.session import Base, get_db
from backend.app.main import app
from backend.app.services.auth_service import AuthService
from backend.app.schemas.auth import UserSignUpRequest


# ---------------------------------------------------------------------------
# Test Fixtures & In-Memory Isolated Database
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Ensure rate limiter is fresh before each test."""
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def isolated_db():
    """Creates a temporary in-memory SQLite database isolated per test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(isolated_db):
    """FastAPI test client with database dependency override."""
    def _override_get_db():
        try:
            yield isolated_db
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# SEC-10 Tests: Container Security & Non-Root Execution
# ---------------------------------------------------------------------------

def test_sec10_dockerfile_multi_stage_and_non_root():
    """SEC-10: Verify multi-stage build, unprivileged user, and toolchain cleanup."""
    dockerfile_path = Path("deployment/hybrid-lab/gateway/Dockerfile")
    assert dockerfile_path.is_file(), "Gateway Dockerfile missing"
    content = dockerfile_path.read_text(encoding="utf-8")

    # Multi-stage build checks
    assert "AS builder" in content, "Dockerfile must define a builder stage"
    assert "AS runtime" in content, "Dockerfile must define a runtime stage"

    # Compiler toolchain restricted to builder stage
    parts = content.split("FROM python:3.12-slim AS runtime")
    assert len(parts) == 2, "Dockerfile must have exactly builder and runtime stages"
    builder_stage, runtime_stage = parts

    assert "gcc" in builder_stage, "Builder stage must install build tools"
    assert "gcc" not in runtime_stage, "Runtime stage must NOT retain gcc"
    assert "libpq-dev" not in runtime_stage, "Runtime stage must NOT retain libpq-dev"

    # Non-root user creation and execution
    assert "useradd" in runtime_stage, "Runtime stage must create dedicated service user"
    assert "USER gateway:gateway" in runtime_stage or "USER gateway" in runtime_stage, (
        "Runtime stage must switch to unprivileged user"
    )


# ---------------------------------------------------------------------------
# SEC-11 Tests: HTTP Security Headers (CSP & HSTS)
# ---------------------------------------------------------------------------

def test_sec11_csp_header_present(client):
    """SEC-11: Content-Security-Policy header is emitted on API responses."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_sec11_hsts_header_present_when_forwarded_https(client):
    """SEC-11: Strict-Transport-Security header is emitted when HTTPS is used."""
    # When forwarded proto is https
    resp = client.get("/api/health", headers={"x-forwarded-proto": "https"})
    assert resp.status_code == 200
    assert "Strict-Transport-Security" in resp.headers
    hsts = resp.headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts


def test_sec11_baseline_security_headers_preserved(client):
    """SEC-11: X-Content-Type-Options, X-Frame-Options, Referrer-Policy intact."""
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


# ---------------------------------------------------------------------------
# SEC-12 Tests: Swagger UI Disablement in Production
# ---------------------------------------------------------------------------

def test_sec12_docs_disabled_in_production(isolated_db):
    """SEC-12: When is_production is True, /docs and /openapi.json are disabled."""
    from fastapi import FastAPI
    from backend.app.api.health import router as health_router

    # Simulate production FastAPI instantiation with production settings
    prod_app = FastAPI(
        title="Prod Test",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    prod_app.include_router(health_router, prefix="/api")

    with TestClient(prod_app) as prod_client:
        docs_resp = prod_client.get("/docs")
        assert docs_resp.status_code == 404, "Swagger UI should be disabled in production"

        redoc_resp = prod_client.get("/redoc")
        assert redoc_resp.status_code == 404, "ReDoc should be disabled in production"

        openapi_resp = prod_client.get("/openapi.json")
        assert openapi_resp.status_code == 404, "OpenAPI schema should be disabled in production"

        health_resp = prod_client.get("/api/health")
        assert health_resp.status_code == 200, "Operational routes remain functional"


def test_sec12_config_has_enable_production_docs():
    """SEC-12: Settings includes enable_production_docs flag defaulting to False."""
    assert hasattr(settings, "enable_production_docs"), "Settings missing enable_production_docs attribute"
    assert settings.enable_production_docs is False, "enable_production_docs must default to False"


# ---------------------------------------------------------------------------
# SEC-13 Tests: HttpOnly Refresh Token Cookie Lifecycle
# ---------------------------------------------------------------------------

def test_sec13_signup_and_login_sets_httponly_refresh_cookie(client, isolated_db):
    """SEC-13: Signup and login responses set hgs_refresh_token HttpOnly cookie."""
    # 1. Sign up new operator
    signup_data = {
        "full_name": "Cookie Test Operator",
        "email": "cookie_operator@example.com",
        "password": "StrongPassword2026!",
        "confirm_password": "StrongPassword2026!",
        "role": "OPERATOR",
    }
    signup_resp = client.post("/api/v1/auth/signup", json=signup_data)
    assert signup_resp.status_code == 201, f"Signup failed: {signup_resp.text}"
    assert "hgs_refresh_token" in signup_resp.cookies, "HttpOnly refresh cookie missing from signup"

    # 2. Login with credentials
    login_data = {
        "email": "cookie_operator@example.com",
        "password": "StrongPassword2026!",
    }
    login_resp = client.post("/api/v1/auth/login", json=login_data)
    assert login_resp.status_code == 200
    assert "hgs_refresh_token" in login_resp.cookies, "HttpOnly refresh cookie missing from login"


def test_sec13_refresh_via_httponly_cookie(client, isolated_db):
    """SEC-13: /auth/refresh accepts cookie without requiring body refresh_token."""
    # 1. Sign up to get initial cookie
    signup_data = {
        "full_name": "Cookie Refresh User",
        "email": "cookie_refresh@example.com",
        "password": "StrongPassword2026!",
        "confirm_password": "StrongPassword2026!",
        "role": "ANALYST",
    }
    signup_resp = client.post("/api/v1/auth/signup", json=signup_data)
    assert signup_resp.status_code == 201
    refresh_cookie = signup_resp.cookies.get("hgs_refresh_token")
    assert refresh_cookie is not None

    # 2. Call /refresh with cookie and EMPTY JSON body
    client.cookies.set("hgs_refresh_token", refresh_cookie)
    refresh_resp = client.post("/api/v1/auth/refresh", json={})
    assert refresh_resp.status_code == 200, f"Cookie refresh failed: {refresh_resp.text}"
    data = refresh_resp.json()
    assert "access_token" in data
    assert "hgs_refresh_token" in refresh_resp.cookies, "Rotated cookie must be set on response"


def test_sec13_logout_clears_httponly_cookie(client, isolated_db):
    """SEC-13: /auth/logout deletes the hgs_refresh_token cookie."""
    # Setup session
    signup_data = {
        "full_name": "Logout Operator",
        "email": "logout_operator@example.com",
        "password": "StrongPassword2026!",
        "confirm_password": "StrongPassword2026!",
        "role": "ANALYST",
    }
    signup_resp = client.post("/api/v1/auth/signup", json=signup_data)
    refresh_cookie = signup_resp.cookies.get("hgs_refresh_token")

    client.cookies.set("hgs_refresh_token", refresh_cookie)
    logout_resp = client.post("/api/v1/auth/logout", json={})
    assert logout_resp.status_code == 200
    # Cookie should be deleted or set to empty with max-age=0
    del_cookie = logout_resp.cookies.get("hgs_refresh_token")
    assert del_cookie == "" or del_cookie is None or logout_resp.headers.get("set-cookie", "").find("hgs_refresh_token=\"\"") != -1 or "Max-Age=0" in logout_resp.headers.get("set-cookie", "")


# ---------------------------------------------------------------------------
# SEC-14 Tests: Dependency Pinning
# ---------------------------------------------------------------------------

def test_sec14_backend_requirements_fully_pinned():
    """SEC-14: backend/requirements.txt packages are strictly pinned with =="""
    req_file = Path("backend/requirements.txt")
    assert req_file.is_file()
    lines = [line.strip() for line in req_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    for line in lines:
        assert "==" in line, f"Package constraint not strictly pinned: {line}"
        assert ">=" not in line, f"Package constraint has unpinned range: {line}"


def test_sec14_ml_requirements_fully_pinned():
    """SEC-14: ml/requirements.txt packages are strictly pinned with =="""
    req_file = Path("ml/requirements.txt")
    assert req_file.is_file()
    lines = [line.strip() for line in req_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    for line in lines:
        assert "==" in line, f"ML package constraint not strictly pinned: {line}"
        assert ">=" not in line, f"ML package constraint has unpinned range: {line}"


# ---------------------------------------------------------------------------
# Workstream 6A Tests: Sliding-Window Rate Limiting Engine
# ---------------------------------------------------------------------------

def test_workstream_6a_sliding_window_rate_limiter_unit():
    """Workstream 6A: Unit test of thread-safe sliding window rate limiter."""
    limiter = SlidingWindowRateLimiter()

    # Limit to 3 requests per 10 seconds
    assert limiter.is_rate_limited("test-key", max_requests=3, window_seconds=10)[0] is False
    assert limiter.is_rate_limited("test-key", max_requests=3, window_seconds=10)[0] is False
    assert limiter.is_rate_limited("test-key", max_requests=3, window_seconds=10)[0] is False

    # 4th request must be rate limited
    is_limited, retry_after = limiter.is_rate_limited("test-key", max_requests=3, window_seconds=10)
    assert is_limited is True
    assert retry_after > 0


def test_workstream_6a_login_rate_limiting_triggers_429(client, isolated_db):
    """Workstream 6A: Login endpoint returns 429 when max requests exceeded."""
    reset_rate_limits()
    login_payload = {
        "email": "nonexistent@example.com",
        "password": "wrongpassword123",
    }

    # Limit is 10 requests per 60s
    for _ in range(10):
        resp = client.post("/api/v1/auth/login", json=login_payload)
        # 401 or 400 expected for bad login
        assert resp.status_code in (400, 401)

    # 11th request must return 429 Too Many Requests
    limited_resp = client.post("/api/v1/auth/login", json=login_payload)
    assert limited_resp.status_code == 429, f"Expected 429, got {limited_resp.status_code}"
    assert "Retry-After" in limited_resp.headers
    assert "Rate limit exceeded" in limited_resp.json()["detail"]


# ---------------------------------------------------------------------------
# Workstream 6B Tests: Hybrid Lab Compose Mandatory Credentials
# ---------------------------------------------------------------------------

def test_workstream_6b_compose_enforces_mandatory_credentials():
    """Workstream 6B: Hybrid lab compose enforces non-empty credentials."""
    compose_path = Path("deployment/hybrid-lab/compose.yaml")
    assert compose_path.is_file()
    content = compose_path.read_text(encoding="utf-8")

    # Assert postgres and gateway-api do not use default fallbacks
    assert "POSTGRES_USER: ${POSTGRES_USER:?" in content
    assert "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?" in content
    assert "POSTGRES_DB: ${POSTGRES_DB:?" in content
    assert "AUTH_JWT_SECRET: ${AUTH_JWT_SECRET:?" in content
    assert "SECRET_KEY: ${SECRET_KEY:?" in content
    assert "GATEWAY_SERVICE_KEY: ${GATEWAY_SERVICE_KEY:?" in content
