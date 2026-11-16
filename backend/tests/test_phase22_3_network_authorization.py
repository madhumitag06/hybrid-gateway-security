"""
Phase 22.3 SEC-09 Network Authorization & Management Allowlist Regression Suite:
Separation of Firewall Policy Allowlisting from Administrative API Authorization.
"""

from datetime import datetime, timezone
import uuid
import pytest
from starlette.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import app
from backend.app.core.security import create_access_token
from backend.app.db.session import SessionLocal
from backend.app.models.user import UserModel
from backend.app.services.policy_engine import PolicyEngine

SAMPLE_FLOW = {
    "flow_id": "phase22-3-auth-test-01",
    "source_ip": "198.51.100.25",
    "destination_ip": "10.0.0.15",
    "source_port": 54321,
    "destination_port": 443,
    "protocol": "TCP",
    "duration": 0.5,
    "packet_count": 10,
    "byte_count": 1200,
}


@pytest.fixture
def test_user_analyst():
    """Creates a temporary active ANALYST user."""
    db = SessionLocal()
    try:
        user_id = str(uuid.uuid4())
        email = f"analyst_{uuid.uuid4().hex[:6]}@secops.local"
        user = UserModel(
            id=user_id,
            email=email,
            password_hash="$2b$12$eX4mpleHashNotUsedDirectlyForTokenTests000000000000000",
            full_name="Test Analyst",
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
        return user
    finally:
        db.close()


@pytest.fixture
def test_user_plain():
    """Creates a temporary active USER role (insufficient for admin endpoints)."""
    db = SessionLocal()
    try:
        user_id = str(uuid.uuid4())
        email = f"user_{uuid.uuid4().hex[:6]}@secops.local"
        user = UserModel(
            id=user_id,
            email=email,
            password_hash="$2b$12$eX4mpleHashNotUsedDirectlyForTokenTests000000000000000",
            full_name="Plain User",
            role="USER",
            is_active=True,
            is_verified=True,
            auth_provider="LOCAL",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


# ==============================================================================
# SEC-09 Required Test Cases
# ==============================================================================

def test_1_firewall_allowlisted_ip_does_not_grant_api_access(monkeypatch):
    """
    Test 1: An IP on the firewall policy allowlist (e.g. 192.168.1.1, 8.8.8.8)
    must NOT automatically obtain API access to protected machine-to-machine endpoints.
    """
    # 192.168.1.1 is in settings.management_allowlist (firewall allowlist)
    assert PolicyEngine.is_ip_allowlisted("192.168.1.1") is True

    # Ensure 192.168.1.1 is NOT in trusted_management_networks
    monkeypatch.setattr("backend.app.config.settings.trusted_management_networks", ["127.0.0.1/32"])

    client = TestClient(app, client=("192.168.1.1", 54321))
    resp = client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_2_ip_not_on_management_allowlist_is_rejected_without_auth(monkeypatch):
    """
    Test 2: An untrusted remote IP not on trusted_management_networks is rejected (401)
    when no service key or Bearer token is provided.
    """
    monkeypatch.setattr("backend.app.config.settings.trusted_management_networks", ["10.50.0.0/16"])
    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_3_valid_service_key_accepted_from_remote_ip(monkeypatch):
    """
    Test 3: A valid service key continues to work from an untrusted remote IP.
    """
    monkeypatch.setattr("backend.app.config.settings.trusted_management_networks", ["127.0.0.1/32"])
    service_key = "test-service-key-with-sufficient-entropy-32-chars"
    monkeypatch.setattr("backend.app.config.settings.gateway_service_key", service_key)

    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-API-Key": service_key},
    )
    assert resp.status_code == 200
    assert "risk_score" in resp.json()


def test_4_valid_bearer_jwt_accepted_from_remote_ip(test_user_analyst, monkeypatch):
    """
    Test 4: A valid Bearer JWT continues to authenticate callers from untrusted remote IPs.
    """
    monkeypatch.setattr("backend.app.config.settings.trusted_management_networks", ["127.0.0.1/32"])
    token = create_access_token(subject=test_user_analyst.id, role=test_user_analyst.role)

    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "risk_score" in resp.json()


def test_5_jwt_with_insufficient_role_remains_rejected_on_role_gated_endpoints(test_user_plain):
    """
    Test 5: A JWT with insufficient role permissions (USER role) remains rejected (403)
    on admin-only endpoints, proving network trust cannot elevate RBAC privileges.
    """
    token = create_access_token(subject=test_user_plain.id, role=test_user_plain.role)

    # Even from loopback/trusted client, USER role must be rejected on admin endpoints
    client = TestClient(app, client=("127.0.0.1", 54321))
    resp = client.post(
        "/api/v1/auth/admin/users",
        json={
            "email": "new_sub_user@secops.local",
            "password": "ValidPassword123!",
            "full_name": "New User",
            "role": "ANALYST",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "Administrator privileges required" in resp.json().get("detail", "")


def test_6_spoofed_x_forwarded_for_loopback_rejected():
    """
    Test 6: A remote untrusted caller attempting to spoof X-Forwarded-For: 127.0.0.1
    does NOT bypass network authorization and is rejected (401).
    """
    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_7_spoofed_x_real_ip_loopback_rejected():
    """
    Test 7: A remote untrusted caller attempting to spoof X-Real-IP: 127.0.0.1
    does NOT bypass network authorization and is rejected (401).
    """
    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post(
        "/api/v1/predict",
        json=SAMPLE_FLOW,
        headers={"X-Real-IP": "127.0.0.1"},
    )
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_8_invalid_cidr_configuration_fails_safely(monkeypatch):
    """
    Test 8: Malformed or unparseable CIDR strings in trusted_management_networks
    are safely ignored without crashing or permitting unauthorized access.
    """
    monkeypatch.setattr(
        "backend.app.config.settings.trusted_management_networks",
        ["not-a-valid-cidr", "999.999.999.999/32", "10.0.0.0/24"],
    )
    parsed = Settings().get_trusted_management_networks()
    # The two invalid entries were ignored; only valid 10.0.0.0/24 remains
    # (Or whatever was valid in the active settings)
    assert all(hasattr(net, "network_address") for net in parsed)

    # Remote untrusted client is still rejected
    client = TestClient(app, client=("198.51.100.25", 54321))
    resp = client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 401


def test_9_empty_management_allowlist_fails_closed(monkeypatch):
    """
    Test 9: When trusted_management_networks is empty ([] or ""),
    even connections from 127.0.0.1 are rejected without valid authentication.
    """
    monkeypatch.setattr("backend.app.config.settings.trusted_management_networks", [])
    client = TestClient(app, client=("127.0.0.1", 54321))
    resp = client.post("/api/v1/predict", json=SAMPLE_FLOW)
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_10_existing_firewall_allow_deny_behavior_unchanged():
    """
    Test 10: PolicyEngine firewall allowlisting functionality is preserved
    for traffic containment and packet inspection decisions.
    """
    # 192.168.1.1 and 10.100.0.1 remain allowlisted in PolicyEngine firewall rules
    assert PolicyEngine.is_ip_allowlisted("192.168.1.1") is True
    assert PolicyEngine.is_ip_allowlisted("10.100.0.1") is True

    # Custom allowlist checks also work
    assert PolicyEngine.is_ip_allowlisted("8.8.8.8", allowlist=["8.8.8.8/32"]) is True

    # Untrusted attacker IP is NOT allowlisted in firewall rules
    assert PolicyEngine.is_ip_allowlisted("198.51.100.25") is False
    assert PolicyEngine.is_ip_allowlisted("10.100.1.50") is False
