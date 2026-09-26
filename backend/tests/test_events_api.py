"""
Security Events API Tests
=========================
Tests the GET /api/v1/events, detail, and history endpoints against PostgreSQL.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_list_events_endpoint():
    response = client.get("/api/v1/events?limit=10")
    assert response.status_code == 200
    data = response.json()

    assert "events" in data
    assert "total" in data
    assert data["limit"] == 10
    assert len(data["events"]) > 0

    first_event = data["events"][0]
    assert "id" in first_event
    assert "risk" in first_event
    assert "severity" in first_event
    assert "action" in first_event


def test_events_filtering():
    # Filter for high threat level
    response = client.get("/api/v1/events?threat_level=HIGH")
    assert response.status_code == 200
    data = response.json()
    for ev in data["events"]:
        assert ev["risk"] >= 40

    # Filter for min_risk = 80
    response_risk = client.get("/api/v1/events?min_risk=80")
    assert response_risk.status_code == 200
    data_risk = response_risk.json()
    for ev in data_risk["events"]:
        assert ev["risk"] >= 80


def test_get_event_detail_and_not_found():
    # List first event to get valid ID
    list_res = client.get("/api/v1/events?limit=1")
    assert list_res.status_code == 200
    events = list_res.json()["events"]
    assert len(events) > 0
    valid_id = events[0]["id"]

    detail_res = client.get(f"/api/v1/events/{valid_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == valid_id
    assert "flow_features" in detail
    assert "class_probabilities" in detail

    # Test 404 for nonexistent event
    not_found_res = client.get("/api/v1/events/nonexistent-99999")
    assert not_found_res.status_code == 404


def test_get_event_history():
    list_res = client.get("/api/v1/events?limit=1")
    valid_id = list_res.json()["events"][0]["id"]

    # Apply an action to generate an audit entry
    action_res = client.post(
        f"/api/events/{valid_id}/action",
        json={"action": "Block", "actor": "test_suite"},
    )
    assert action_res.status_code == 200

    # Fetch history
    history_res = client.get(f"/api/v1/events/{valid_id}/history")
    assert history_res.status_code == 200
    data = history_res.json()
    assert data["event_id"] == valid_id
    assert len(data["history"]) >= 1
    assert data["history"][0]["requested_action"] == "Block"
