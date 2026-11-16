"""
Phase 22.2 Critical Security Remediation Test Suite (SEC-01 through SEC-04):
1. Google OAuth Token Verification & Mock Bypass Elimination
2. Public Self-Registration Least-Privilege Enforcement & Admin User Provisioning
3. Fail-Closed Production Secret Validation (AUTH_JWT_SECRET, SECRET_KEY, ADMIN_PASSWORD)
4. Packaging Artifact Verification & Secret Exclusion
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.config import Settings, settings
from backend.app.core.security import create_access_token
from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.models.user import UserModel
from backend.app.services.auth_service import AuthService
from backend.app.schemas.auth import AdminUserCreateRequest, UserSignUpRequest

client = TestClient(app)


def get_random_email(prefix: str = "sec_test") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}@secops.local"


def get_admin_token() -> str:
    """Helper to authenticate or create an admin and return a valid access token."""
    with SessionLocal() as db:
        admin_email = f"admin_{uuid.uuid4().hex[:6]}@secops.local"
        admin_user = UserModel(
            id=str(uuid.uuid4()),
            email=admin_email,
            password_hash="$2b$12$eX4mpleHashNotUsedDirectlyForTokenTests000000000000000",
            full_name="Root SecOps Admin",
            role="ADMIN",
            auth_provider="LOCAL",
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        token = create_access_token(
            subject=admin_user.id,
            email=admin_user.email,
            role="ADMIN",
        )
        return token


# ==============================================================================
# SEC-01: Google OAuth Security & Mock Bypass Elimination
# ==============================================================================

def test_production_rejects_mock_google_token(monkeypatch):
    """Production mode must reject mock_google_ tokens with 401 Unauthorized."""
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "allow_mock_auth", False)

    res = client.post(
        "/api/v1/auth/google/token",
        json={"id_token": "mock_google_:target@secops.local:Target:sub-999"},
    )
    assert res.status_code == 401
    assert "Mock Google authentication is disabled or forbidden" in res.json()["detail"]


def test_mock_google_token_cannot_claim_local_admin_account(monkeypatch):
    """Even if allow_mock_auth is enabled in dev, mock tokens cannot hijack an existing LOCAL ADMIN account."""
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "allow_mock_auth", True)

    target_admin_email = get_random_email("admin_target")
    with SessionLocal() as db:
        admin_user = UserModel(
            id=str(uuid.uuid4()),
            email=target_admin_email,
            password_hash="somehash",
            full_name="Target Administrator",
            role="ADMIN",
            auth_provider="LOCAL",
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(admin_user)
        db.commit()

    # Attempt to authenticate as the administrator using a mock Google token
    res = client.post(
        "/api/v1/auth/google/token",
        json={"id_token": f"mock_google_:{target_admin_email}:Attacker:attacker-google-sub"},
    )
    assert res.status_code == 403
    assert "Administrative and Operator accounts cannot be claimed" in res.json()["detail"]


def test_google_token_verification_validates_issuer_audience_and_signature(monkeypatch):
    """Real Google token path rejects invalid signatures, mismatched audiences, and wrong issuers."""
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "google_client_id", "expected-client-id.apps.googleusercontent.com")

    # 1. Invalid signature (HTTP 400 from Google endpoint)
    mock_resp_bad_sig = MagicMock()
    mock_resp_bad_sig.status_code = 400

    with patch("httpx.Client.get", return_value=mock_resp_bad_sig):
        res1 = client.post(
            "/api/v1/auth/google/token",
            json={"id_token": "invalid-crypto-signature-token-12345"},
        )
        assert res1.status_code == 401
        assert "Invalid Google ID token signature" in res1.json()["detail"]

    # 2. Audience mismatch
    mock_resp_bad_aud = MagicMock()
    mock_resp_bad_aud.status_code = 200
    mock_resp_bad_aud.json.return_value = {
        "email": "user@gmail.com",
        "sub": "sub-123",
        "aud": "wrong-client-id.apps.googleusercontent.com",
        "iss": "https://accounts.google.com",
        "email_verified": True,
    }
    with patch("httpx.Client.get", return_value=mock_resp_bad_aud):
        res2 = client.post(
            "/api/v1/auth/google/token",
            json={"id_token": "valid-token-wrong-aud"},
        )
        assert res2.status_code == 401
        assert "Google token audience mismatch" in res2.json()["detail"]

    # 3. Invalid issuer
    mock_resp_bad_iss = MagicMock()
    mock_resp_bad_iss.status_code = 200
    mock_resp_bad_iss.json.return_value = {
        "email": "user@gmail.com",
        "sub": "sub-123",
        "aud": "expected-client-id.apps.googleusercontent.com",
        "iss": "https://attacker.identity.provider.com",
        "email_verified": True,
    }
    with patch("httpx.Client.get", return_value=mock_resp_bad_iss):
        res3 = client.post(
            "/api/v1/auth/google/token",
            json={"id_token": "valid-token-wrong-iss"},
        )
        assert res3.status_code == 401
        assert "Invalid Google token issuer" in res3.json()["detail"]

    # 4. Unverified email
    mock_resp_unverified = MagicMock()
    mock_resp_unverified.status_code = 200
    mock_resp_unverified.json.return_value = {
        "email": "user@gmail.com",
        "sub": "sub-123",
        "aud": "expected-client-id.apps.googleusercontent.com",
        "iss": "https://accounts.google.com",
        "email_verified": False,
    }
    with patch("httpx.Client.get", return_value=mock_resp_unverified):
        res4 = client.post(
            "/api/v1/auth/google/token",
            json={"id_token": "valid-token-unverified-email"},
        )
        assert res4.status_code == 401
        assert "Google account email is not verified" in res4.json()["detail"]


# ==============================================================================
# SEC-02: Public Signup Least-Privilege & Administrative User Provisioning
# ==============================================================================

def test_public_signup_cannot_create_admin():
    """Attempting to specify role: ADMIN in public signup is forced to least-privileged role ANALYST."""
    email = get_random_email("hacker_admin")
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Wannabe Admin",
            "email": email,
            "password": "StrongPassword2026!",
            "confirm_password": "StrongPassword2026!",
            "role": "ADMIN",
        },
    )
    assert res.status_code == 201
    user_data = res.json()["user"]
    assert user_data["role"] == "ANALYST"
    assert user_data["role"] != "ADMIN"


def test_public_signup_cannot_create_operator():
    """Attempting to specify role: OPERATOR in public signup is forced to least-privileged role ANALYST."""
    email = get_random_email("hacker_operator")
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Wannabe Operator",
            "email": email,
            "password": "StrongPassword2026!",
            "confirm_password": "StrongPassword2026!",
            "role": "OPERATOR",
        },
    )
    assert res.status_code == 201
    user_data = res.json()["user"]
    assert user_data["role"] == "ANALYST"
    assert user_data["role"] != "OPERATOR"


def test_public_signup_cannot_create_auditor():
    """Attempting to specify role: AUDITOR in public signup is forced to least-privileged role ANALYST."""
    email = get_random_email("hacker_auditor")
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Wannabe Auditor",
            "email": email,
            "password": "StrongPassword2026!",
            "confirm_password": "StrongPassword2026!",
            "role": "AUDITOR",
        },
    )
    assert res.status_code == 201
    user_data = res.json()["user"]
    assert user_data["role"] == "ANALYST"
    assert user_data["role"] != "AUDITOR"


def test_public_signup_supports_designated_least_privileged_user_role():
    """Public signup allows requesting USER role, assigning standard observer permissions."""
    email = get_random_email("standard_user")
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Standard Observer",
            "email": email,
            "password": "StrongPassword2026!",
            "confirm_password": "StrongPassword2026!",
            "role": "USER",
        },
    )
    assert res.status_code == 201
    user_data = res.json()["user"]
    assert user_data["role"] == "USER"


def test_authorized_administrator_can_provision_operator_and_auditor():
    """Authenticated ADMIN can provision users with elevated roles via POST /api/v1/auth/admin/users."""
    admin_token = get_admin_token()

    # 1. Admin provisions OPERATOR
    op_email = get_random_email("legit_operator")
    res_op = client.post(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "full_name": "Legitimate SecOps Operator",
            "email": op_email,
            "password": "OperatorSecurePassword2026!",
            "role": "OPERATOR",
        },
    )
    assert res_op.status_code == 201
    assert res_op.json()["role"] == "OPERATOR"
    assert res_op.json()["email"] == op_email

    # 2. Admin provisions AUDITOR
    aud_email = get_random_email("legit_auditor")
    res_aud = client.post(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "full_name": "Compliance Auditor",
            "email": aud_email,
            "password": "AuditorSecurePassword2026!",
            "role": "AUDITOR",
        },
    )
    assert res_aud.status_code == 201
    assert res_aud.json()["role"] == "AUDITOR"


def test_non_admin_cannot_access_admin_user_provisioning():
    """Anonymous callers or non-admin users receive 401/403 on POST /api/v1/auth/admin/users."""
    # Anonymous caller -> 401
    res_unauth = client.post(
        "/api/v1/auth/admin/users",
        json={
            "full_name": "Unauthorized Provision",
            "email": "unauth@secops.local",
            "password": "Password123!",
            "role": "OPERATOR",
        },
    )
    assert res_unauth.status_code == 401

    # Standard analyst -> 403
    with SessionLocal() as db:
        analyst = UserModel(
            id=str(uuid.uuid4()),
            email=get_random_email("analyst"),
            password_hash="somehash",
            full_name="Analyst User",
            role="ANALYST",
            auth_provider="LOCAL",
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(analyst)
        db.commit()
        analyst_token = create_access_token(subject=analyst.id, email=analyst.email, role="ANALYST")

    res_forbidden = client.post(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "full_name": "Analyst Attempting Provision",
            "email": "attempt@secops.local",
            "password": "Password123!",
            "role": "ADMIN",
        },
    )
    assert res_forbidden.status_code == 403


# ==============================================================================
# SEC-03: Production Secret Fail-Closed Validation
# ==============================================================================

def test_production_fails_when_jwt_secret_is_development_default(monkeypatch):
    """Production startup must raise RuntimeError if AUTH_JWT_SECRET equals development default."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "a" * 32 + "-valid-service-key")
    monkeypatch.setenv("SECRET_KEY", "b" * 32 + "-valid-secret-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "adaptive-gateway-jwt-super-secret-key-change-in-production-min-32-chars")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "AUTH_JWT_SECRET cannot use development defaults" in str(exc_info.value)


def test_production_fails_when_jwt_secret_too_short(monkeypatch):
    """Production startup must raise RuntimeError if AUTH_JWT_SECRET is under 32 chars."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "a" * 32 + "-valid-service-key")
    monkeypatch.setenv("SECRET_KEY", "b" * 32 + "-valid-secret-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "short-secret-under-32-chars")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "AUTH_JWT_SECRET cannot use development defaults and must be at least 32 characters" in str(exc_info.value)


def test_production_fails_when_secret_key_is_development_default(monkeypatch):
    """Production startup must raise RuntimeError if SECRET_KEY equals development default."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "a" * 32 + "-valid-service-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "c" * 32 + "-valid-jwt-signing-secret")
    monkeypatch.setenv("SECRET_KEY", "adaptive-hybrid-gateway-dev-insecure-secret-key-change-in-prod")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "SECRET_KEY cannot use development defaults" in str(exc_info.value)


def test_production_fails_when_admin_password_is_development_default(monkeypatch):
    """Production startup must raise RuntimeError if ADMIN_EMAIL is set and ADMIN_PASSWORD is test@123."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "a" * 32 + "-valid-service-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "c" * 32 + "-valid-jwt-signing-secret")
    monkeypatch.setenv("SECRET_KEY", "b" * 32 + "-valid-secret-key")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@prod.enterprise.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "test@123")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "ADMIN_PASSWORD cannot use development defaults" in str(exc_info.value)


def test_production_fails_when_allow_mock_auth_is_true(monkeypatch):
    """Production startup must raise RuntimeError if allow_mock_auth is True."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "a" * 32 + "-valid-service-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "c" * 32 + "-valid-jwt-signing-secret")
    monkeypatch.setenv("SECRET_KEY", "b" * 32 + "-valid-secret-key")
    monkeypatch.setenv("ALLOW_MOCK_AUTH", "true")

    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "allow_mock_auth cannot be True in production" in str(exc_info.value)


def test_production_succeeds_with_strong_production_configuration(monkeypatch):
    """Production startup succeeds when all secrets are explicitly configured with high entropy."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("GATEWAY_SERVICE_KEY", "x" * 32 + "-custom-prod-service-key")
    monkeypatch.setenv("AUTH_JWT_SECRET", "y" * 32 + "-custom-prod-jwt-secret")
    monkeypatch.setenv("SECRET_KEY", "z" * 32 + "-custom-prod-app-secret")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@prod.enterprise.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "HighEntropyCustomPassword2026!#")
    monkeypatch.setenv("ALLOW_MOCK_AUTH", "false")

    cfg = Settings()
    assert cfg.app_env == "production"
    assert cfg.gateway_service_key == "x" * 32 + "-custom-prod-service-key"
    assert cfg.auth_jwt_secret == "y" * 32 + "-custom-prod-jwt-secret"
    assert cfg.secret_key == "z" * 32 + "-custom-prod-app-secret"
    assert cfg.admin_password == "HighEntropyCustomPassword2026!#"


# ==============================================================================
# SEC-04: Packaging Specification Verification
# ==============================================================================

def test_pyinstaller_spec_excludes_active_env_file():
    """Verify AdaptiveSecurityGateway.spec does NOT collect active .env file."""
    spec_path = Path("AdaptiveSecurityGateway.spec")
    assert spec_path.is_file(), "AdaptiveSecurityGateway.spec must exist"
    spec_content = spec_path.read_text(encoding="utf-8")

    # Must NOT contain datas.append((str(WORKSPACE_ROOT / ".env"), "."))
    assert 'datas.append((str(WORKSPACE_ROOT / ".env"), "."))' not in spec_content
    # Must explicitly mention SEC-04 exclusion
    assert "SEC-04" in spec_content


def test_build_script_excludes_active_env_file():
    """Verify build_exe.ps1 does NOT copy active .env and asserts zero .env in output."""
    build_script = Path("backend/build_exe.ps1")
    assert build_script.is_file(), "backend/build_exe.ps1 must exist"
    script_content = build_script.read_text(encoding="utf-8")

    assert r'Copy-Item -Path "$WorkspaceRoot\.env" -Destination "$DistPath\AdaptiveSecurityGateway\.env"' not in script_content
    assert "SEC-04 Verified: Zero .env secret files present in packaged output" in script_content
