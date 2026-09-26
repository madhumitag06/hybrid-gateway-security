"""
Dashboard API Tests
===================
Validates the dashboard aggregation telemetry and policy action update endpoints.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_get_dashboard():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()

    assert "riskScore" in data
    assert 0 <= data["riskScore"] <= 100
    assert data["riskState"] in ["Allow", "Monitor", "Restrict", "Block"]
    assert "events" in data
    assert len(data["events"]) > 0
    assert "reasons" in data
    assert len(data["reasons"]) > 0

    # Verify event structure derived from ML model
    event = data["events"][0]
    assert "id" in event
    assert "risk" in event
    assert "severity" in event
    assert "action" in event
    assert "description" in event


def test_apply_policy_action():
    response = client.post(
        "/api/events/evt-1001/action",
        json={"action": "Block"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["eventId"] == "evt-1001"
    assert data["action"] == "Block"
    assert data["status"] == "Applied"
