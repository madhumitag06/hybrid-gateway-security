"""
Prediction API Tests
====================
Validates that the FastAPI endpoint interacts directly with the Phase 1 ML model
and returns real predictions, class probability estimates, and continuous risk scores.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_predict_benign_traffic():
    payload = {
        "packet_count": 25,
        "byte_count": 15000,
        "duration": 2.5,
        "conn_rate": 2.0,
        "dst_port": 443,
        "unique_dst_ports": 1,
        "failed_auth_count": 0,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["attack_type"] == "BENIGN"
    assert data["is_anomaly"] is False
    assert data["risk_score"] < 40
    assert data["threat_level"] == "LOW"
    assert data["action_recommendation"] == "Allow"
    assert data["confidence"] > 0.5
    assert "BENIGN" in data["class_probabilities"]


def test_predict_port_scan():
    payload = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.08,
        "conn_rate": 120.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["attack_type"] == "PORT_SCAN"
    assert data["is_anomaly"] is True
    assert data["risk_score"] >= 40
    assert data["threat_level"] in ["MEDIUM", "HIGH"]
    assert len(data["top_contributing_features"]) > 0


def test_predict_brute_force():
    from backend.app.services.ml_service import MLService
    if MLService.get_active_version() == "candidate_xgboost_v2":
        payload = {
            "packet_count": 43,
            "byte_count": 4593,
            "duration": 0.364,
            "conn_rate": 118.21,
            "dst_port": 22,
            "unique_dst_ports": 1,
            "failed_auth_count": 12,
            "bytes_per_sec": 12626.7,
            "packets_per_sec": 118.21,
            "avg_packet_size": 106.81,
        }
    else:
        payload = {
            "packet_count": 35,
            "byte_count": 8500,
            "duration": 1.8,
            "conn_rate": 18.0,
            "dst_port": 22,
            "unique_dst_ports": 1,
            "failed_auth_count": 12,
        }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["attack_type"] == "BRUTE_FORCE"
    assert data["is_anomaly"] is True
    assert data["risk_score"] >= 40


def test_predict_traffic_spike():
    from backend.app.services.ml_service import MLService
    if MLService.get_active_version() == "candidate_xgboost_v2":
        payload = {
            "packet_count": 4,
            "byte_count": 0,
            "duration": 0.001,
            "conn_rate": 500.0,
            "dst_port": 61083,
            "unique_dst_ports": 1,
            "failed_auth_count": 0,
            "bytes_per_sec": 0.0,
            "packets_per_sec": 4000.0,
            "avg_packet_size": 0.0,
        }
    else:
        payload = {
            "packet_count": 4500,
            "byte_count": 4500000,
            "duration": 4.0,
            "conn_rate": 60.0,
            "dst_port": 80,
            "unique_dst_ports": 1,
            "failed_auth_count": 0,
        }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["attack_type"] == "TRAFFIC_SPIKE"
    assert data["is_anomaly"] is True
    assert data["risk_score"] >= 40


def test_predict_borderline_flow():
    payload = {
        "packet_count": 8,
        "byte_count": 600,
        "duration": 0.8,
        "conn_rate": 15.0,
        "dst_port": 8080,
        "unique_dst_ports": 5,
        "failed_auth_count": 0,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert 0 <= data["risk_score"] <= 100
    assert "class_probabilities" in data
    assert sum(data["class_probabilities"].values()) > 0.95


def test_predict_invalid_input():
    # Negative packet count and invalid port number
    payload = {
        "packet_count": -5,
        "byte_count": 100,
        "duration": 1.0,
        "conn_rate": 1.0,
        "dst_port": 99999,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 422  # Pydantic validation error


def test_batch_prediction():
    batch_payload = {
        "flows": [
            {
                "packet_count": 25,
                "byte_count": 15000,
                "duration": 2.5,
                "conn_rate": 2.0,
                "dst_port": 443,
            },
            {
                "packet_count": 2,
                "byte_count": 120,
                "duration": 0.08,
                "conn_rate": 120.0,
                "dst_port": 8080,
                "unique_dst_ports": 75,
            },
        ]
    }
    response = client.post("/api/v1/predict/batch", json=batch_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_evaluated"] == 2
    assert len(data["results"]) == 2
    assert data["results"][0]["attack_type"] == "BENIGN"
    assert data["results"][1]["attack_type"] == "PORT_SCAN"


def test_presets_endpoint():
    response = client.get("/api/v1/predict/presets")
    assert response.status_code == 200
    data = response.json()
    assert "BENIGN_HTTPS" in data
    assert "PORT_SCAN" in data
    assert "BRUTE_FORCE_SSH" in data
    assert "TRAFFIC_SPIKE" in data
    assert "BORDERLINE_FLOW" in data
    assert "SUSPICIOUS_TRANSFER" in data


def test_predict_decimal_durations_support():
    """Verify that various supported decimal durations succeed without precision rejection."""
    durations = [0.08, 0.09, 0.10, 0.101, 0.25, 1.0, 120.0]
    for dur in durations:
        payload = {
            "packet_count": 2,
            "byte_count": 120,
            "duration": dur,
            "conn_rate": 120.0,
            "dst_port": 8080,
            "unique_dst_ports": 75,
            "failed_auth_count": 0,
            "persist": False,
        }
        res = client.post("/api/v1/predict", json=payload)
        assert res.status_code == 200, f"Duration {dur} failed with status {res.status_code}: {res.text}"
        data = res.json()
        assert data["attack_type"] == "PORT_SCAN"
        assert 0 <= data["risk_score"] <= 100


def test_predict_negative_duration_rejected():
    """Verify that negative durations are rejected by backend Pydantic validation."""
    payload = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": -0.05,
        "conn_rate": 120.0,
        "dst_port": 8080,
    }
    res = client.post("/api/v1/predict", json=payload)
    assert res.status_code == 422


def test_all_six_scenario_presets_executable():
    """Verify that all six standard scenarios execute inference successfully."""
    presets_res = client.get("/api/v1/predict/presets")
    assert presets_res.status_code == 200
    presets = presets_res.json()

    for name, flow_data in presets.items():
        flow_data["persist"] = False
        res = client.post("/api/v1/predict", json=flow_data)
        assert res.status_code == 200, f"Preset {name} failed: {res.text}"
        pred = res.json()
        assert "attack_type" in pred
        assert 0 <= pred["risk_score"] <= 100
        assert 0.0 <= pred["confidence"] <= 1.0


def test_predict_and_verify_database_persistence():
    payload = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.08,
        "conn_rate": 120.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
        "source_ip": "192.168.1.200",
        "destination_ip": "10.100.4.55",
        "persist": True,
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["event_id"] is not None
    event_id = data["event_id"]

    # Retrieve from PostgreSQL events endpoint
    get_res = client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == 200
    event_data = get_res.json()
    assert event_data["id"] == event_id
    assert event_data["source"] == "192.168.1.200"
    assert event_data["destination"] == "10.100.4.55"
    assert event_data["attack_type"] == "PORT_SCAN"
    assert event_data["risk"] == data["risk_score"]

