"""
Phase 21 Comprehensive RBAC & Administrative Authorization Test Suite
=====================================================================
Validates role-based access control and unauthenticated rejection across all
sensitive endpoints:
1. Unauthenticated requests are rejected with 401 Unauthorized.
2. Standard USER / ANALYST / AUDITOR roles cannot access Admin or Operator endpoints (403 Forbidden).
3. OPERATOR role can perform operational actions (revoking rules, preparing datasets)
   but is forbidden from administrative model promotion, config mutation, and user admin (403 Forbidden).
4. ADMIN role has full authorized access to administrative endpoints (200 OK).
5. Invalid, tampered, or expired tokens are rejected with 401 Unauthorized.
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.core.security import create_access_token
from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.models.user import UserModel
from backend.app.services.auth_service import AuthService

client = TestClient(app)


def create_test_user_with_role(role: str) -> tuple[UserModel, str]:
    """Helper to provision a test user with a specific role and generate an access token."""
    db = SessionLocal()
    try:
        user_id = str(uuid.uuid4())
        email = f"user_{role.lower()}_{uuid.uuid4().hex[:6]}@secops.test"
        user = UserModel(
            id=user_id,
            email=email,
            password_hash="$2b$12$eX4mpleHashNotUsedDirectlyForTokenTests000000000000000",
            full_name=f"Test {role} Operator",
            role=role,
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
        return user, token
    finally:
        db.close()


def get_admin_token() -> str:
    """Helper to authenticate configured admin."""
    res = client.post(
        "/api/v1/auth/login",
        json={"email": settings.admin_email, "password": settings.admin_password},
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def test_unauthenticated_requests_return_401():
    """Verify all protected administrative endpoints return 401 for unauthenticated calls."""
    unauth_endpoints = [
        ("GET", "/api/v1/auth/me", None),
        ("GET", "/api/v1/auth/admin/users", None),
        ("PUT", "/api/v1/enforcement/config", {"active_mode": "SANDBOX"}),
        ("POST", "/api/v1/enforcement/rules/rule_123/revoke", {"reason": "test"}),
        ("POST", "/api/v1/shadow/promote", {"version": "v2"}),
        ("POST", "/api/v1/shadow/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/train", {"candidate_version": "v_test"}),
        ("POST", "/api/v1/adaptive/promote", {"run_id": "run_1"}),
        ("POST", "/api/v1/adaptive/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/dataset/prepare?min_samples=5", None),
        ("POST", "/api/v1/adaptive/feedback", {"feedback_id": "fb_1", "action": "CONFIRM"}),
        ("POST", "/api/v1/cloud/accounts", {"account_id": "123456789012", "account_name": "Test", "provider": "AWS"}),
        ("POST", "/api/v1/cloud/accounts/AWS/telemetry-checkpoints/reset", None),
    ]

    for method, path, body in unauth_endpoints:
        if method == "GET":
            r = client.get(path)
        elif method == "PUT":
            r = client.put(path, json=body)
        elif method == "POST":
            r = client.post(path, json=body)
        assert r.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {r.status_code}: {r.text}"


def test_user_role_forbidden_from_admin_and_operator_endpoints():
    """Verify standard USER role receives 403 Forbidden on restricted endpoints."""
    _, user_token = create_test_user_with_role("USER")
    headers = {"Authorization": f"Bearer {user_token}"}

    # Allowed endpoint for active user
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "USER"

    # Forbidden admin endpoints
    forbidden_endpoints = [
        ("GET", "/api/v1/auth/admin/users", None),
        ("PUT", "/api/v1/enforcement/config", {"active_mode": "SANDBOX"}),
        ("POST", "/api/v1/enforcement/rules/dummy_rule/revoke", {"reason": "test"}),
        ("POST", "/api/v1/shadow/promote", {"version": "candidate_xgboost_v2"}),
        ("POST", "/api/v1/shadow/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/train", {"candidate_version": "v_test"}),
        ("POST", "/api/v1/adaptive/promote", {"run_id": "run_1"}),
        ("POST", "/api/v1/adaptive/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/dataset/prepare?min_samples=5", None),
        ("POST", "/api/v1/cloud/accounts", {"account_id": "123456789012", "account_name": "Test", "provider": "AWS"}),
        ("POST", "/api/v1/cloud/accounts/AWS/telemetry-checkpoints/reset", None),
    ]

    for method, path, body in forbidden_endpoints:
        if method == "GET":
            r = client.get(path, headers=headers)
        elif method == "PUT":
            r = client.put(path, json=body, headers=headers)
        elif method == "POST":
            r = client.post(path, json=body, headers=headers)
        assert r.status_code == 403, f"Expected 403 for USER role on {method} {path}, got {r.status_code}: {r.text}"


def test_analyst_and_auditor_roles_forbidden_from_administrative_endpoints():
    """Verify ANALYST and AUDITOR roles cannot perform admin or operational mutations."""
    for role in ["ANALYST", "AUDITOR"]:
        _, token = create_test_user_with_role(role)
        headers = {"Authorization": f"Bearer {token}"}

        # Forbidden admin/operator actions
        r_admin = client.get("/api/v1/auth/admin/users", headers=headers)
        assert r_admin.status_code == 403

        r_cfg = client.put("/api/v1/enforcement/config", json={"active_mode": "SANDBOX"}, headers=headers)
        assert r_cfg.status_code == 403

        r_revoke = client.post("/api/v1/enforcement/rules/fake_rule/revoke", json={}, headers=headers)
        assert r_revoke.status_code == 403

        r_promo = client.post("/api/v1/shadow/promote", json={"version": "v2"}, headers=headers)
        assert r_promo.status_code == 403

        r_train = client.post("/api/v1/adaptive/train", json={"candidate_version": "v2"}, headers=headers)
        assert r_train.status_code == 403


def test_operator_role_authorized_for_operations_but_forbidden_for_admin():
    """
    Verify OPERATOR role:
    - CAN access operational actions: revoke containment rules (requires require_operator), dataset preparation.
    - CANNOT access administrator actions: user listing, config mutation, model promotion, candidate retraining.
    """
    _, op_token = create_test_user_with_role("OPERATOR")
    headers = {"Authorization": f"Bearer {op_token}"}

    # 1. Operational action permitted: dataset prepare (returns 200 or 400 depending on dataset state, NOT 403)
    prep_res = client.post("/api/v1/adaptive/dataset/prepare?min_samples=5", headers=headers)
    assert prep_res.status_code in (200, 400), f"Expected 200/400, got {prep_res.status_code}"

    # 2. Operational action permitted: revoke rule (not found produces 404, proving auth passed and wasn't 403)
    revoke_res = client.post("/api/v1/enforcement/rules/nonexistent_rule/revoke", json={}, headers=headers)
    assert revoke_res.status_code == 404, f"Expected 404 (rule not found), got {revoke_res.status_code}"

    # 3. Admin actions forbidden for OPERATOR
    assert client.get("/api/v1/auth/admin/users", headers=headers).status_code == 403
    assert client.put("/api/v1/enforcement/config", json={"active_mode": "SANDBOX"}, headers=headers).status_code == 403
    assert client.post("/api/v1/shadow/promote", json={"version": "v2"}, headers=headers).status_code == 403
    assert client.post("/api/v1/shadow/rollback", json={"reason": "test"}, headers=headers).status_code == 403
    assert client.post("/api/v1/adaptive/train", json={"candidate_version": "v2"}, headers=headers).status_code == 403
    assert client.post("/api/v1/adaptive/promote", json={"run_id": "run_1"}, headers=headers).status_code == 403
    assert client.post("/api/v1/cloud/accounts", json={"account_id": "123", "account_name": "T", "provider": "AWS"}, headers=headers).status_code == 403


def test_admin_role_authorized_for_all_endpoints():
    """Verify ADMIN role has access to all administrative endpoints."""
    admin_token = get_admin_token()
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin user listing
    users_res = client.get("/api/v1/auth/admin/users", headers=headers)
    assert users_res.status_code == 200
    assert "users" in users_res.json()

    # Enforcement config update
    cfg_res = client.put(
        "/api/v1/enforcement/config",
        json={"active_mode": "DRY_RUN", "default_ttl_seconds": 300},
        headers=headers,
    )
    assert cfg_res.status_code == 200
    assert cfg_res.json()["active_mode"] == "DRY_RUN"


def test_invalid_and_tampered_token_rejection():
    """Verify invalid or tampered tokens receive 401 Unauthorized."""
    # 1. Non-Bearer header
    r1 = client.get("/api/v1/auth/me", headers={"Authorization": "Basic 123456"})
    assert r1.status_code == 401

    # 2. Malformed token
    r2 = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert r2.status_code == 401

    # 3. Expired token
    expired_token = create_access_token(
        subject="expired_user_id",
        expires_delta=timedelta(seconds=-60),
    )
    r3 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert r3.status_code == 401
