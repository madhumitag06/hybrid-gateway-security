"""
Phase 5 Enforcement API Test Suite
==================================
Tests REST endpoints for enforcement rules, configuration, manual revocation,
and static vs adaptive policy comparison.
"""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.schemas.predict import NetworkFlowRequest


def test_get_and_update_enforcement_config():
    """Test GET and PUT /api/v1/enforcement/config."""
    client = TestClient(app)

    # 1. GET config
    resp = client.get("/api/v1/enforcement/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "active_mode" in data
    assert "management_allowlist" in data

    # 2. PUT config: set mode to SANDBOX
    update_resp = client.put("/api/v1/enforcement/config", json={"active_mode": "SANDBOX", "default_ttl_seconds": 450})
    assert update_resp.status_code == 200
    updated_data = update_resp.json()
    assert updated_data["active_mode"] == "SANDBOX"
    assert updated_data["default_ttl_seconds"] == 450

    # Reset back to safe DRY_RUN
    client.put("/api/v1/enforcement/config", json={"active_mode": "DRY_RUN", "default_ttl_seconds": 300})


def test_evaluate_policy_endpoint():
    """Test POST /api/v1/policies/evaluate."""
    client = TestClient(app)
    flow_req = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.08,
        "conn_rate": 120.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
        "source_ip": "192.168.1.77",
        "destination_ip": "10.100.4.12",
    }
    resp = client.post("/api/v1/policies/evaluate", json=flow_req)
    assert resp.status_code == 200
    decision = resp.json()
    assert decision["policy_action"] == "Block"
    assert decision["enforcement_required"] is True
    assert decision["target_ip"] == "192.168.1.77"


def test_compare_policies_endpoint():
    """Test POST /api/v1/policies/compare."""
    client = TestClient(app)
    # Slow stealth port scan (conn_rate 15 < 100, ports=75)
    flow_req = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.5,
        "conn_rate": 15.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
        "source_ip": "192.168.1.77",
        "destination_ip": "10.100.4.12",
    }
    resp = client.post("/api/v1/policies/compare", json=flow_req)
    assert resp.status_code == 200
    comparison = resp.json()
    assert comparison["static_decision"] == "Allow"
    assert comparison["adaptive_decision"] == "Block"
    assert comparison["decision_divergence"] is True
    assert len(comparison["divergence_rationale"]) > 0


def test_list_and_revoke_enforcement_rules():
    """Test listing rules and revoking an active rule."""
    client = TestClient(app)
    # 1. Switch to SANDBOX and execute a high-risk prediction with persist=true
    client.put("/api/v1/enforcement/config", json={"active_mode": "SANDBOX"})
    flow_req = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.08,
        "conn_rate": 120.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
        "source_ip": "198.51.100.77",
        "destination_ip": "10.100.4.12",
        "persist": True,
    }
    pred_resp = client.post("/api/v1/predict", json=flow_req)
    assert pred_resp.status_code == 200

    # 2. List rules
    rules_resp = client.get("/api/v1/enforcement/rules?status_filter=ACTIVE")
    assert rules_resp.status_code == 200
    rules = rules_resp.json()
    assert len(rules) >= 1

    rule_to_revoke = next(r for r in rules if r["target_ip"] == "198.51.100.77")
    rule_id = rule_to_revoke["rule_id"]

    # 3. Revoke rule
    revoke_resp = client.post(
        f"/api/v1/enforcement/rules/{rule_id}/revoke",
        json={"actor": "test_analyst", "reason": "Test rollback"},
    )
    assert revoke_resp.status_code == 200
    rev_data = revoke_resp.json()
    assert rev_data["status"] == "REVOKED"
    assert rev_data["rule_id"] == rule_id

    # Reset mode to DRY_RUN
    client.put("/api/v1/enforcement/config", json={"active_mode": "DRY_RUN"})
