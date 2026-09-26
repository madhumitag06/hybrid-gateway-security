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
