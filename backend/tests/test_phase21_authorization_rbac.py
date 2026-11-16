"""
Phase 21 & 21.1 Comprehensive RBAC & Service Authorization Test Suite
=====================================================================
Validates role-based access control and machine-to-machine service authentication:
1. Missing token / unauthenticated requests are rejected with 401 Unauthorized across all protected routes.
2. Machine-to-machine service authentication (X-API-Key / X-Service-Token) verifies automated telemetry ingestion from remote origins.
3. Untrusted remote IPs without credentials receive 401 Unauthorized on prediction and ingestion endpoints.
4. Standard USER role cannot access Analyst, Operator, or Admin endpoints (403 Forbidden).
5. ANALYST and AUDITOR roles have read access to analytics/events/dashboards, but cannot perform Operator or Admin mutations (403 Forbidden).
6. OPERATOR role can perform operational actions (revoking rules, preparing datasets, discovering cloud resources) but is forbidden from administrative model promotion, config mutation, and user admin (403 Forbidden).
7. ADMIN role has full authorized access to administrative endpoints (200 OK).
8. Invalid, tampered, or expired tokens are rejected with 401 Unauthorized.
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
remote_untrusted_client = TestClient(app, client=("198.51.100.25", 50000))


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
    """Verify all protected endpoints return 401 for unauthenticated calls."""
    unauth_endpoints = [
        # Auth & Profile
        ("GET", "/api/v1/auth/me", None),
        ("GET", "/api/v1/auth/admin/users", None),
        # Enforcement & Policy
        ("GET", "/api/v1/enforcement/rules", None),
        ("GET", "/api/v1/enforcement/config", None),
        ("GET", "/api/v1/enforcement/audit", None),
        ("PUT", "/api/v1/enforcement/config", {"active_mode": "SANDBOX"}),
        ("POST", "/api/v1/enforcement/rules/rule_123/revoke", {"reason": "test"}),
        # Analytics & Events
        ("GET", "/api/v1/analytics/summary", None),
        ("POST", "/api/v1/analytics/explain-flow", {"flow": {"packet_count": 5, "byte_count": 500, "duration": 1.0, "conn_rate": 5.0, "dst_port": 443, "unique_dst_ports": 1, "failed_auth_count": 0}}),
        ("GET", "/api/v1/events", None),
        ("GET", "/api/v1/dashboard", None),
        ("GET", "/api/v1/system/profile", None),
        # Shadow & Model Promotion
        ("GET", "/api/v1/shadow/status", None),
        ("GET", "/api/v1/shadow/comparison", None),
        ("GET", "/api/v1/shadow/records", None),
        ("GET", "/api/v1/shadow/registry", None),
        ("POST", "/api/v1/shadow/promote", {"version": "v2"}),
        ("POST", "/api/v1/shadow/rollback", {"reason": "test"}),
        # Adaptive ML
        ("GET", "/api/v1/adaptive/telemetry", None),
        ("GET", "/api/v1/adaptive/feedbacks", None),
        ("GET", "/api/v1/adaptive/runs", None),
        ("POST", "/api/v1/adaptive/train", {"candidate_version": "v_test"}),
        ("POST", "/api/v1/adaptive/promote", {"run_id": "run_1"}),
        ("POST", "/api/v1/adaptive/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/dataset/prepare?min_samples=5", None),
        ("POST", "/api/v1/adaptive/feedback", {"feedback_id": "fb_1", "action": "CONFIRM"}),
        # Multi-Cloud & Hybrid
        ("GET", "/api/v1/cloud/providers", None),
        ("GET", "/api/v1/cloud/accounts", None),
        ("GET", "/api/v1/cloud/resources", None),
        ("GET", "/api/v1/cloud/inventory/summary", None),
        ("GET", "/api/v1/cloud/health", None),
        ("POST", "/api/v1/cloud/accounts", {"account_id": "123456789012", "account_name": "Test", "provider": "AWS"}),
        ("POST", "/api/v1/cloud/accounts/AWS/discover", None),
        ("POST", "/api/v1/cloud/accounts/AWS/telemetry-checkpoints/reset", None),
        ("GET", "/api/v1/hybrid/topology", None),
        ("GET", "/api/v1/hybrid/telemetry-status", None),
        ("GET", "/api/v1/hybrid/lab-status", None),
        ("GET", "/api/v1/hybrid/samples", None),
        # Ingestion & Evaluation
        ("GET", "/api/v1/ingest/status", None),
        ("GET", "/api/v1/ingest/samples", None),
        ("GET", "/api/v1/ingest/latest", None),
        ("GET", "/api/v1/ingest/history", None),
        ("GET", "/api/v1/evaluation/suites", None),
        ("GET", "/api/v1/evaluation/export", None),
        ("POST", "/api/v1/evaluation/run", {"suite_name": "PORT_SCAN_RECON", "sample_count": 25}),
    ]

    for method, path, body in unauth_endpoints:
        if method == "GET":
            r = client.get(path)
        elif method == "PUT":
            r = client.put(path, json=body)
        elif method == "POST":
            r = client.post(path, json=body)
        assert r.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {r.status_code}: {r.text}"


def test_machine_to_machine_service_authentication_and_remote_network_guard():
    """
    Verify machine-to-machine telemetry ingestion authorization:
    1. Untrusted remote IPs without credentials receive 401 Unauthorized.
    2. Valid X-API-Key allows machine-to-machine ingestion from any origin.
    3. Invalid X-API-Key is rejected with 401 Unauthorized.
    4. Valid X-Service-Token is accepted.
    """
    flow_payload = {
        "packet_count": 10,
        "byte_count": 1500,
        "duration": 1.2,
        "conn_rate": 5.0,
        "dst_port": 443,
        "unique_dst_ports": 1,
        "failed_auth_count": 0,
        "source_ip": "198.51.100.99",
        "destination_ip": "10.100.1.50",
        "persist": False,
    }

    # 1. Untrusted remote origin without credentials receives 401
    r_unauth = remote_untrusted_client.post("/api/v1/predict", json=flow_payload)
    assert r_unauth.status_code == 401
    assert "Authentication required" in r_unauth.text

    # 2. Invalid service key receives 401
    r_bad_key = remote_untrusted_client.post(
        "/api/v1/predict",
        json=flow_payload,
        headers={"X-API-Key": "invalid-service-key-wrong"},
    )
    assert r_bad_key.status_code == 401
    assert "Invalid service API key" in r_bad_key.text

    # 3. Valid X-API-Key succeeds
    service_key = settings.gateway_service_key
    r_good_key = remote_untrusted_client.post(
        "/api/v1/predict",
        json=flow_payload,
        headers={"X-API-Key": service_key},
    )
    assert r_good_key.status_code == 200
    assert "risk_score" in r_good_key.json()

    # 4. Valid X-Service-Token header succeeds
    r_good_token = remote_untrusted_client.post(
        "/api/v1/predict",
        json=flow_payload,
        headers={"X-Service-Token": service_key},
    )
    assert r_good_token.status_code == 200

    # 5. Policy evaluation endpoint guarded similarly
    r_pol_unauth = remote_untrusted_client.post("/api/v1/policies/evaluate", json=flow_payload)
    assert r_pol_unauth.status_code == 401

    r_pol_auth = remote_untrusted_client.post(
        "/api/v1/policies/evaluate",
        json=flow_payload,
        headers={"X-API-Key": service_key},
    )
    assert r_pol_auth.status_code == 200
    assert "policy_action" in r_pol_auth.json() or "action" in r_pol_auth.json()


def test_user_role_forbidden_from_admin_operator_and_analyst_endpoints():
    """Verify standard USER role receives 403 Forbidden on analyst, operator, and admin endpoints."""
    _, user_token = create_test_user_with_role("USER")
    headers = {"Authorization": f"Bearer {user_token}"}

    # Allowed endpoint for active user profile
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "USER"

    # Forbidden analyst endpoints for USER
    forbidden_for_user = [
        ("GET", "/api/v1/analytics/summary", None),
        ("GET", "/api/v1/dashboard", None),
        ("GET", "/api/v1/events", None),
        ("GET", "/api/v1/cloud/providers", None),
        ("GET", "/api/v1/cloud/accounts", None),
        ("GET", "/api/v1/hybrid/topology", None),
        ("GET", "/api/v1/ingest/status", None),
        ("GET", "/api/v1/evaluation/suites", None),
        ("POST", "/api/v1/adaptive/feedback", {"feedback_id": "fb_1", "action": "CONFIRM"}),
        # Forbidden operator endpoints
        ("POST", "/api/v1/enforcement/rules/dummy_rule/revoke", {"reason": "test"}),
        ("POST", "/api/v1/cloud/accounts/AWS/discover", None),
        ("POST", "/api/v1/adaptive/dataset/prepare?min_samples=5", None),
        # Forbidden admin endpoints
        ("GET", "/api/v1/auth/admin/users", None),
        ("PUT", "/api/v1/enforcement/config", {"active_mode": "SANDBOX"}),
        ("POST", "/api/v1/shadow/promote", {"version": "candidate_xgboost_v2"}),
        ("POST", "/api/v1/shadow/rollback", {"reason": "test"}),
        ("POST", "/api/v1/adaptive/train", {"candidate_version": "v_test"}),
        ("POST", "/api/v1/adaptive/promote", {"run_id": "run_1"}),
        ("POST", "/api/v1/adaptive/rollback", {"reason": "test"}),
        ("POST", "/api/v1/cloud/accounts", {"account_id": "123456789012", "account_name": "Test", "provider": "AWS"}),
    ]

    for method, path, body in forbidden_for_user:
        if method == "GET":
            r = client.get(path, headers=headers)
        elif method == "PUT":
            r = client.put(path, json=body, headers=headers)
        elif method == "POST":
            r = client.post(path, json=body, headers=headers)
        assert r.status_code == 403, f"Expected 403 for USER role on {method} {path}, got {r.status_code}: {r.text}"


def test_analyst_and_auditor_roles_authorized_for_read_forbidden_from_mutations():
    """Verify ANALYST and AUDITOR roles can read analytics/events but cannot perform admin or operational mutations."""
    for role in ["ANALYST", "AUDITOR"]:
        _, token = create_test_user_with_role(role)
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Allowed read endpoints for ANALYST / AUDITOR
        r_dash = client.get("/api/v1/dashboard", headers=headers)
        assert r_dash.status_code == 200, f"Expected 200 for {role} on dashboard, got {r_dash.status_code}"

        r_analytics = client.get("/api/v1/analytics/summary", headers=headers)
        assert r_analytics.status_code == 200, f"Expected 200 for {role} on analytics, got {r_analytics.status_code}"

        r_events = client.get("/api/v1/events", headers=headers)
        assert r_events.status_code == 200, f"Expected 200 for {role} on events, got {r_events.status_code}"

        r_cloud = client.get("/api/v1/cloud/providers", headers=headers)
        assert r_cloud.status_code == 200, f"Expected 200 for {role} on cloud providers, got {r_cloud.status_code}"

        # 2. Forbidden operator actions for ANALYST / AUDITOR
        r_revoke = client.post("/api/v1/enforcement/rules/fake_rule/revoke", json={}, headers=headers)
        assert r_revoke.status_code == 403

        r_eval_run = client.post("/api/v1/evaluation/run", json={"suite_name": "PORT_SCAN_RECON", "sample_count": 25}, headers=headers)
        assert r_eval_run.status_code == 403

        r_discover = client.post("/api/v1/cloud/accounts/AWS/discover", headers=headers)
        assert r_discover.status_code == 403

        # 3. Forbidden admin actions for ANALYST / AUDITOR
        r_admin = client.get("/api/v1/auth/admin/users", headers=headers)
        assert r_admin.status_code == 403

        r_cfg = client.put("/api/v1/enforcement/config", json={"active_mode": "SANDBOX"}, headers=headers)
        assert r_cfg.status_code == 403

        r_promo = client.post("/api/v1/shadow/promote", json={"version": "v2"}, headers=headers)
        assert r_promo.status_code == 403

        r_train = client.post("/api/v1/adaptive/train", json={"candidate_version": "v2"}, headers=headers)
        assert r_train.status_code == 403


def test_operator_role_authorized_for_operations_but_forbidden_for_admin():
    """
    Verify OPERATOR role:
    - CAN access operational actions: revoke containment rules, dataset preparation, cloud discovery.
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
    """Verify ADMIN role has access to all administrative and operational endpoints."""
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

    # Dashboard and events access
    dash_res = client.get("/api/v1/dashboard", headers=headers)
    assert dash_res.status_code == 200


def test_invalid_and_tampered_token_rejection():
    """Verify invalid, expired, or tampered tokens receive 401 Unauthorized."""
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
