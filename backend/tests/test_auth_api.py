"""
Authentication & Authorization End-to-End API Tests
=====================================================
Validates FastAPI auth endpoints including signup, login, session refresh,
logout, profile inspection, role-based admin authorization guards,
password change workflows, and mocked Google OAuth integration.
"""

import uuid
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.services.auth_service import AuthService

client = TestClient(app)


def get_unique_email(prefix: str = "testuser") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}@gateway.test"


def test_auth_signup_flow():
    email = get_unique_email("analyst")
    signup_payload = {
        "email": email,
        "password": "ValidSecOpsPassword2026!",
        "confirm_password": "ValidSecOpsPassword2026!",
        "full_name": "Test Analyst One",
        "role": "ANALYST",
    }

    response = client.post("/api/v1/auth/signup", json=signup_payload)
    assert response.status_code == 201
    data = response.json()

    assert "access_token" in data
    assert "refresh_token" in data
    assert "user" in data
    assert data["user"]["email"] == email
    assert data["user"]["full_name"] == "Test Analyst One"
    assert data["user"]["role"] == "ANALYST"
    assert data["token_type"] == "bearer"


def test_auth_signup_duplicate_email_rejected():
    email = get_unique_email("duplicate")
    signup_payload = {
        "email": email,
        "password": "ValidSecOpsPassword2026!",
        "confirm_password": "ValidSecOpsPassword2026!",
        "full_name": "Duplicate Tester",
        "role": "USER",
    }

    # First signup succeeds
    r1 = client.post("/api/v1/auth/signup", json=signup_payload)
    assert r1.status_code == 201

    # Second signup with same email must be rejected with 400
    r2 = client.post("/api/v1/auth/signup", json=signup_payload)
    assert r2.status_code == 400
    detail_lower = r2.json()["detail"].lower()
    assert "already" in detail_lower or "exists" in detail_lower


def test_auth_login_success_and_failures():
    email = get_unique_email("loginuser")
    password = "CorrectLoginPassword123!"

    # Create user
    client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": password,
            "confirm_password": password,
            "full_name": "Login Tester",
            "role": "ANALYST",
        },
    )

    # 1. Successful Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["user"]["email"] == email
    assert "access_token" in login_data
    assert "refresh_token" in login_data

    # 2. Incorrect Password
    bad_pwd_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword999!"},
    )
    assert bad_pwd_res.status_code == 401
    assert "invalid" in bad_pwd_res.json()["detail"].lower()

    # 3. Non-existent User
    unknown_res = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_operator@gateway.test", "password": password},
    )
    assert unknown_res.status_code == 401


def test_auth_me_endpoint_and_token_protection():
    email = get_unique_email("profileuser")
    password = "SecOpsProfilePassword123!"

    reg_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": password,
            "confirm_password": password,
            "full_name": "Profile Operator",
            "role": "ANALYST",
        },
    )
    access_token = reg_res.json()["access_token"]

    # 1. Protected endpoint without token -> 401 Unauthorized
    unauth_res = client.get("/api/v1/auth/me")
    assert unauth_res.status_code == 401

    # 2. Protected endpoint with Bearer token -> 200 OK
    auth_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert auth_res.status_code == 200
    user_data = auth_res.json()
    assert user_data["email"] == email
    assert user_data["full_name"] == "Profile Operator"


def test_auth_token_refresh_and_logout_flow():
    email = get_unique_email("refreshuser")
    password = "RefreshPassword123!"

    reg_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": password,
            "confirm_password": password,
            "full_name": "Session Refresh User",
            "role": "ANALYST",
        },
    )
    refresh_token = reg_res.json()["refresh_token"]

    # 1. Refresh token rotation
    ref_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert ref_res.status_code == 200
    ref_data = ref_res.json()
    assert "access_token" in ref_data
    new_refresh_token = ref_data["refresh_token"]

    # 2. Old refresh token cannot be reused
    old_reuse_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert old_reuse_res.status_code == 401

    # 3. Logout revokes active session
    logout_res = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": new_refresh_token},
    )
    assert logout_res.status_code == 200

    # 4. Revoked refresh token fails
    after_logout_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert after_logout_res.status_code == 401


def test_role_based_admin_authorization_guards():
    # 1. Create a standard Analyst user
    analyst_email = get_unique_email("analyst_guard")
    analyst_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": analyst_email,
            "password": "StandardUserPassword123!",
            "confirm_password": "StandardUserPassword123!",
            "full_name": "Analyst Guard Test",
            "role": "ANALYST",
        },
    )
    analyst_token = analyst_res.json()["access_token"]

    # 2. Analyst attempts to access Admin endpoint -> 403 Forbidden
    forbidden_res = client.get(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert forbidden_res.status_code == 403
    assert "administrator privileges required" in forbidden_res.json()["detail"].lower()

    # 3. Login with initial bootstrap Admin account
    admin_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": settings.admin_email,
            "password": settings.admin_password,
        },
    )
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]

    # 4. Admin accesses admin endpoint -> 200 OK
    admin_res = client.get(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"limit": 100},
    )
    assert admin_res.status_code == 200
    admin_data = admin_res.json()
    assert "users" in admin_data
    assert admin_data["total_users"] >= 1
    assert any(u["email"] == settings.admin_email or u["role"] == "ADMIN" for u in admin_data["users"])


def test_password_change_flow():
    email = get_unique_email("pwdchange")
    old_pwd = "OriginalPassword123!"
    new_pwd = "UpdatedSecOpsPassword2026!"

    reg_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": old_pwd,
            "confirm_password": old_pwd,
            "full_name": "Password Changer",
            "role": "USER",
        },
    )
    token = reg_res.json()["access_token"]

    # 1. Fail with invalid current password
    fail_res = client.post(
        "/api/v1/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WrongCurrentPassword123!", "new_password": new_pwd, "confirm_new_password": new_pwd},
    )
    assert fail_res.status_code == 400

    # 2. Succeed with correct current password
    succ_res = client.post(
        "/api/v1/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": old_pwd, "new_password": new_pwd, "confirm_new_password": new_pwd},
    )
    assert succ_res.status_code == 200

    # 3. Login with new password succeeds
    login_new = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": new_pwd},
    )
    assert login_new.status_code == 200


def test_google_oauth_init_and_mock_callback():
    # 1. Google login init returns JSON with status & URL info without crashing
    res = client.get("/api/v1/auth/google/login")
    assert res.status_code == 200
    data = res.json()
    assert "enabled" in data
    assert "client_id_configured" in data

    # 2. Mock Google ID Token verification directly in AuthService
    with SessionLocal() as db:
        mock_google_user = AuthService.handle_google_id_token(
            db=db,
            google_sub="google-mock-sub-12345",
            email="google.analyst@example.com",
            full_name="Google Workspace Analyst",
            avatar_url="https://example.com/avatar.png",
        )
        assert mock_google_user is not None
        assert mock_google_user.email == "google.analyst@example.com"
        assert mock_google_user.google_subject_id == "google-mock-sub-12345"
        auth_prov_str = mock_google_user.auth_provider.value if hasattr(mock_google_user.auth_provider, "value") else str(mock_google_user.auth_provider)
        assert auth_prov_str == "GOOGLE"


def test_user_role_forbidden_from_admin_operations():
    # Create an ordinary USER account
    user_email = get_unique_email("user_role")
    user_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": user_email,
            "password": "UserRolePassword123!",
            "confirm_password": "UserRolePassword123!",
            "full_name": "Standard Observer",
            "role": "USER",
        },
    )
    user_token = user_res.json()["access_token"]

    # Verify USER role cannot access admin endpoint
    res = client.get(
        "/api/v1/auth/admin/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403
    assert "administrator privileges required" in res.json()["detail"].lower()


def test_password_change_revokes_all_prior_refresh_tokens():
    email = get_unique_email("revoke_session")
    old_pwd = "OldPassword12345!"
    new_pwd = "NewPassword12345!"

    reg_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": old_pwd,
            "confirm_password": old_pwd,
            "full_name": "Session Invalidator",
            "role": "ANALYST",
        },
    )
    token = reg_res.json()["access_token"]
    refresh_token = reg_res.json()["refresh_token"]

    # Change password
    change_res = client.post(
        "/api/v1/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": old_pwd, "new_password": new_pwd, "confirm_new_password": new_pwd},
    )
    assert change_res.status_code == 200

    # Old refresh token MUST be revoked and fail
    ref_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert ref_res.status_code == 401


def test_inactive_account_blocked_from_authentication():
    email = get_unique_email("deactivated")
    pwd = "DeactivatedAccountPassword123!"

    reg_res = client.post(
        "/api/v1/auth/signup",
        json={
            "email": email,
            "password": pwd,
            "confirm_password": pwd,
            "full_name": "Deactivated User",
            "role": "ANALYST",
        },
    )
    user_id = reg_res.json()["user"]["id"]
    token = reg_res.json()["access_token"]

    # Deactivate user directly in PostgreSQL
    with SessionLocal() as db:
        from backend.app.repositories.user_repo import UserRepository
        repo = UserRepository(db)
        user = repo.get_by_id(user_id)
        assert user is not None
        user.is_active = False
        repo.update(user)
        db.commit()

    # 1. Login fails for deactivated user
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
    )
    assert login_res.status_code == 403
    assert "disabled" in login_res.json()["detail"].lower() or "deactivated" in login_res.json()["detail"].lower()

    # 2. Existing token rejected on protected route
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 403


def test_authoritative_security_pipeline_unaltered_by_auth():
    """
    Verifies that the deterministic PolicyEngine boundary and ML inference remain
    strictly independent and produce identical security actions.
    """
    from backend.app.schemas.predict import PredictionResponse
    from backend.app.services.policy_engine import PolicyEngine

    # High risk port scan flow -> must produce Block or Restrict regardless of auth context
    pred_high = PredictionResponse(
        attack_type="PORT_SCAN",
        is_anomaly=True,
        risk_score=92.0,
        threat_level="HIGH",
        action_recommendation="Block",
        confidence=0.95,
        class_probabilities={"PORT_SCAN": 0.95, "BENIGN": 0.05},
        flow_features={"unique_dst_ports": 80, "conn_rate": 150.0},
    )
    high_risk_decision = PolicyEngine.evaluate(
        prediction=pred_high,
        source_ip="198.51.100.42",
        destination_ip="10.0.0.5",
        dst_port=8080,
    )
    assert high_risk_decision.policy_action == "Block"
    assert high_risk_decision.enforcement_required is True

    # Management allowlist bypass -> must produce Allow
    pred_admin = PredictionResponse(
        attack_type="DDoS",
        is_anomaly=True,
        risk_score=95.0,
        threat_level="HIGH",
        action_recommendation="Block",
        confidence=0.98,
        class_probabilities={"DDoS": 0.98, "BENIGN": 0.02},
        flow_features={"packet_count": 5000},
    )
    allowlist_decision = PolicyEngine.evaluate(
        prediction=pred_admin,
        source_ip="192.168.1.1",  # Management Allowlist IP
        destination_ip="10.0.0.5",
        dst_port=443,
    )
    assert allowlist_decision.policy_action == "Allow"
    assert allowlist_decision.enforcement_required is False


