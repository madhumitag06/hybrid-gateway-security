"""
Phase 22.0 Security Regression Test Suite:
Service Key Hardening, Fail-Closed Production Configuration, and Constant-Time Verification.
"""
import os
import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import patch
from starlette.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import app
from backend.app.core.security import create_access_token
from backend.app.db.session import SessionLocal
from backend.app.models.user import UserModel


@pytest.fixture
def test_settings():
    """Returns the active test configuration."""
    from backend.app.config import settings
    return settings


@pytest.fixture
def remote_client():
    """Simulates an untrusted remote client connecting from an external IP address."""
    return TestClient(app, client=("198.51.100.25", 54321))


@pytest.fixture
def loopback_client():
    """Simulates a trusted local client on the loopback interface."""
    return TestClient(app, client=("127.0.0.1", 54321))


SAMPLE_FLOW = {
    "flow_id": "phase22-hardening-test-01",
    "source_ip": "198.51.100.25",
    "destination_ip": "10.0.0.15",
    "source_port": 54321,
    "destination_port": 443,
    "protocol": "TCP",
    "duration": 0.5,
    "packet_count": 10,
    "byte_count": 1200,
}


# ==============================================================================
# 1. Production Startup Configuration Tests (Fail-Closed Enforcement)
# ==============================================================================

def test_production_startup_fails_when_service_key_missing(monkeypatch):
    """Production startup must raise RuntimeError if GATEWAY_SERVICE_KEY is unset."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("GATEWAY_SERVICE_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "GATEWAY_SERVICE_KEY is missing or empty" in str(exc_info.value)


def test_production_startup_fails_when_service_key_empty(monkeypatch):
    """Production startup must raise RuntimeError if GATEWAY_SERVICE_KEY is whitespace/empty."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "   ")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "GATEWAY_SERVICE_KEY is missing or empty" in str(exc_info.value)


def test_production_startup_fails_with_insecure_dev_default(monkeypatch):
    """Production startup must reject known development default keys."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "dev-insecure-gateway-service-key-local-testing-only")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "cannot use development defaults" in str(exc_info.value)


def test_production_startup_fails_when_key_too_short(monkeypatch):
    """Production startup must reject service keys shorter than 32 characters."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "short-key-under-32-chars")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "at least 32 characters" in str(exc_info.value)


def test_production_startup_succeeds_with_strong_key(monkeypatch):
    """Production startup must succeed when APP_ENV=production and a 32+ char key is supplied."""
    monkeypatch.setenv("APP_ENV", "production")
    strong_key = "a" * 32 + "-production-entropy-service-key"
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", strong_key)
    monkeypatch.setenv("AUTH_JWT_SECRET", "super-secret-production-jwt-token-key-min-32-bytes!")
    monkeypatch.setenv("SECRET_KEY", "super-secret-production-app-secret-key-min-32-bytes!")
    monkeypatch.setenv("ADMIN_PASSWORD", "SuperSecureProductionAdminPass2026!")

    cfg = Settings()
    assert cfg.gateway_service_key == strong_key
    assert cfg.app_env == "production"


def test_non_production_startup_uses_safe_dev_default(monkeypatch):
    """Development/testing mode allows missing key by substituting safe local dev key."""
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("GATEWAY_SERVICE_KEY", raising=False)

    cfg = Settings()
    assert cfg.gateway_service_key == "dev-insecure-gateway-service-key-local-testing-only"


# ==============================================================================
# 2. Service Key Authentication & Constant-Time Validation Tests
# ==============================================================================

def test_remote_untrusted_client_missing_key_rejected(remote_client):
    """Remote caller without any authentication headers must receive 401 Unauthorized."""
    resp = remote_client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_remote_untrusted_client_invalid_key_rejected(remote_client):
    """Remote caller with invalid X-API-Key must receive 401 Unauthorized."""
    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": "completely-invalid-attacker-key"},
    )
    assert resp.status_code == 401
    assert "Invalid service API key" in resp.json().get("detail", "")


def test_remote_untrusted_client_empty_key_header_rejected(remote_client):
    """Remote caller with empty X-API-Key header must receive 401 Unauthorized."""
    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": ""},
    )
    assert resp.status_code == 401
    assert "Invalid service API key" in resp.json().get("detail", "")


def test_remote_untrusted_client_whitespace_key_header_rejected(remote_client):
    """Remote caller with whitespace-only X-API-Key header must receive 401 Unauthorized."""
    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": "     "},
    )
    assert resp.status_code == 401
    assert "Invalid service API key" in resp.json().get("detail", "")


def test_remote_untrusted_client_valid_api_key_accepted(remote_client, test_settings):
    """Remote caller with valid X-API-Key must receive 200 OK."""
    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": test_settings.gateway_service_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert "threat_level" in data


def test_remote_untrusted_client_valid_service_token_accepted(remote_client, test_settings):
    """Remote caller with valid X-Service-Token must receive 200 OK."""
    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-Service-Token": test_settings.gateway_service_key},
    )
    assert resp.status_code == 200
    assert "risk_score" in resp.json()


def test_zero_secret_leakage_in_error_responses(remote_client, test_settings):
    """Error responses must never echo or leak the configured service key."""
    key = test_settings.gateway_service_key
    assert key is not None and len(key) > 5

    # Test bad key
    resp_bad = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": "attempted-guess-12345"},
    )
    assert key not in resp_bad.text
    assert "attempted-guess-12345" not in resp_bad.text

    # Test empty key
    resp_empty = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": ""},
    )
    assert key not in resp_empty.text

    # Test headers
    for h_name, h_val in resp_bad.headers.items():
        assert key not in h_name
        assert key not in h_val


def test_constant_time_comparison_is_invoked(remote_client, test_settings):
    """Verify secrets.compare_digest is called during service key comparison."""
    with patch("secrets.compare_digest", wraps=__import__("secrets").compare_digest) as mock_compare:
        resp = remote_client.post(
            "/api/v1/predict",
            json=SAMPLE_FLOW,
            headers={"X-API-Key": test_settings.gateway_service_key},
        )
        assert resp.status_code == 200
        assert mock_compare.called
        # Check arguments passed to compare_digest
        args, kwargs = mock_compare.call_args
        assert args[0] == test_settings.gateway_service_key.strip()
        assert args[1] == test_settings.gateway_service_key.strip()


# ==============================================================================
# 3. Preservation of Existing Authentication Channels
# ==============================================================================

def test_loopback_trusted_client_permitted_without_key(loopback_client):
    """Local loopback caller (127.0.0.1) remains permitted via trusted-network rule."""
    resp = loopback_client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 200
    assert "risk_score" in resp.json()


def test_remote_client_with_valid_jwt_permitted_without_key(remote_client):
    """Remote caller with valid user Bearer JWT remains permitted without service key."""
    db = SessionLocal()
    try:
        user_id = str(uuid.uuid4())
        email = f"analyst_{uuid.uuid4().hex[:6]}@secops.local"
        user = UserModel(
            id=user_id,
            email=email,
            password_hash="$2b$12$eX4mpleHashNotUsedDirectlyForTokenTests000000000000000",
            full_name="SecOps Analyst",
            role="ANALYST",
            is_active=True,
            is_verified=True,
            auth_provider="LOCAL",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(
            subject=user.id,
            email=user.email,
            role=user.role,
        )
    finally:
        db.close()

    resp = remote_client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "risk_score" in resp.json()
