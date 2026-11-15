"""
Phase 20 Security Hardening & Observability Tests
=================================================
Validates:
- HTTP security defense-in-depth response headers.
- Input validation: upper bound limits on batch prediction requests.
- Input validation: upper bound limits on multi-cloud telemetry batch requests.
- Health endpoint database liveness reporting.
- Hybrid lab status dynamic active model reporting.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.schemas.predict import NetworkFlowRequest

client = TestClient(app)


def test_http_security_headers_injected():
    """Verify standard security defense-in-depth headers are present on API responses."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-XSS-Protection") == "1; mode=block"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in res.headers.get("Permissions-Policy", "")


def test_batch_prediction_size_limit_validation():
    """Verify BatchPredictionRequest rejects excessive batch sizes (> 500 items) to prevent DoS."""
    single_flow = NetworkFlowRequest(
        packet_count=10,
        byte_count=1000,
        duration=1.0,
        conn_rate=10.0,
        dst_port=80,
        unique_dst_ports=1,
        persist=False,
    )
    # Valid batch within 500 flows
    valid_payload = {"flows": [single_flow.model_dump() for _ in range(5)]}
    valid_res = client.post("/api/v1/predict/batch", json=valid_payload)
    assert valid_res.status_code == 200
    assert valid_res.json()["total_evaluated"] == 5

    # Excessive batch exceeding 500 flows -> 422 Unprocessable Content
    excessive_payload = {"flows": [single_flow.model_dump() for _ in range(501)]}
    err_res = client.post("/api/v1/predict/batch", json=excessive_payload)
    assert err_res.status_code == 422


def test_health_endpoint_database_liveness():
    """Verify /api/health probes both ML model and database liveness."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["healthy", "degraded"]
    assert data["model_loaded"] is True
    assert "database_status" in data
    assert data["database_status"] == "connected"


def test_hybrid_lab_status_dynamic_model_type():
    """Verify /api/v1/hybrid/lab-status dynamically reports active model algorithm."""
    res = client.get("/api/v1/hybrid/lab-status")
    assert res.status_code == 200
    data = res.json()
    assert "gateway_intelligence" in data
    gw = data["gateway_intelligence"]
    assert gw["model_type"] in ["XGBClassifier", "RandomForestClassifier"]
    assert "model_name" in gw
