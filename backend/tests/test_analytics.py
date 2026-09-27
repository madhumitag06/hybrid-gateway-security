"""
Integration Tests for Security Analytics & Explanation Endpoints
================================================================
Tests PostgreSQL analytics aggregations, histogram buckets, provenance segregation,
and REST API endpoints (/api/v1/analytics/summary, /api/v1/events/{id}/explanation).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.models.security_event import SecurityEventModel
from backend.app.services.analytics_service import AnalyticsService, HISTOGRAM_BUCKETS
from backend.app.services.dashboard_service import DashboardService


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    DashboardService.seed_initial_data_if_empty(db)
    yield db
    db.close()


def test_analytics_summary_service_and_histogram_buckets(db_session: Session):
    """Verify AnalyticsService produces 5 histogram buckets (0-19, 20-39, 40-59, 60-79, 80-100)."""
    summary = AnalyticsService.get_summary(db_session)
    assert summary.total_events_evaluated > 0
    assert len(summary.histogram_buckets) == 5

    expected_labels = ["0-19", "20-39", "40-59", "60-79", "80-100"]
    actual_labels = [b.bin_label for b in summary.histogram_buckets]
    assert actual_labels == expected_labels

    # Verify percentages sum to approx 100%
    total_pct = sum(b.percentage for b in summary.histogram_buckets)
    assert 99.0 <= total_pct <= 101.0


def test_analytics_provenance_segregation(db_session: Session):
    """Verify distinct labeling of real telemetry vs fixtures/seeds."""
    summary = AnalyticsService.get_summary(db_session)
    assert summary.total_events_evaluated == summary.real_telemetry_events + summary.fixture_demo_events

    for prov in summary.telemetry_provenance_distribution:
        if prov.telemetry_source in ["AWS_VPC_FLOW_LOG", "LIVE_PCAP_STREAM", "LIVE_NETWORK_STREAM"]:
            assert prov.is_real_telemetry is True
        else:
            assert prov.is_real_telemetry is False


def test_get_analytics_summary_endpoint(client: TestClient):
    """Verify GET /api/v1/analytics/summary returns HTTP 200 with structured statistics."""
    resp = client.get("/api/v1/analytics/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events_evaluated" in data
    assert "histogram_buckets" in data
    assert "attack_type_distribution" in data
    assert "zone_traffic_distribution" in data
    assert "telemetry_provenance_distribution" in data
    assert "top_sensitive_features" in data
    assert len(data["histogram_buckets"]) == 5


def test_explain_arbitrary_flow_endpoint(client: TestClient):
    """Verify POST /api/v1/analytics/explain-flow computes on-demand SHAP attribution with real Phase 5 rule."""
    payload = {
        "flow": {
            "packet_count": 2,
            "byte_count": 120,
            "duration": 0.08,
            "conn_rate": 120.0,
            "dst_port": 8080,
            "unique_dst_ports": 75,
            "failed_auth_count": 0,
            "source_ip": "192.168.10.55",
            "destination_ip": "10.100.1.50",
        }
    }
    resp = client.post("/api/v1/analytics/explain-flow", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "attack_type" in data
    assert "risk_score" in data
    assert "feature_attributions" in data
    assert len(data["feature_attributions"]) == 10
    assert "top_positive_contributors" in data
    assert "disclaimer" in data
    assert "causality" in data["disclaimer"].lower()

    # Verify Phase 5 rule name integrity
    verified_rules = {
        "MANAGEMENT_ALLOWLIST_PROTECTION",
        "CONFIDENCE_GATING_MONITOR",
        "BASELINE_TRAFFIC_ALLOW",
        "GRADUATED_SERVICE_RESTRICTION",
        "RECON_PORT_SCAN_QUARANTINE",
        "BRUTE_FORCE_AUTHENTICATION_QUARANTINE",
        "VOLUMETRIC_SPIKE_RATE_LIMIT",
        "HIGH_RISK_ANOMALY_QUARANTINE",
    }
    assert data["policy_rule_name"] in verified_rules


def test_get_event_explanation_endpoint_and_404(client: TestClient, db_session: Session):
    """Verify GET /api/v1/events/{id}/explanation returns on-demand event waterfall with Phase 5 rule name."""
    first_event = db_session.query(SecurityEventModel).first()
    assert first_event is not None

    resp = client.get(f"/api/v1/events/{first_event.id}/explanation")
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_id"] == first_event.id
    assert "feature_attributions" in data
    assert len(data["feature_attributions"]) == 10
    assert "policy_reasoning" in data
    assert data["policy_reasoning"]["enacted_policy_action"] == first_event.current_policy_action

    verified_rules = {
        "MANAGEMENT_ALLOWLIST_PROTECTION",
        "CONFIDENCE_GATING_MONITOR",
        "BASELINE_TRAFFIC_ALLOW",
        "GRADUATED_SERVICE_RESTRICTION",
        "RECON_PORT_SCAN_QUARANTINE",
        "BRUTE_FORCE_AUTHENTICATION_QUARANTINE",
        "VOLUMETRIC_SPIKE_RATE_LIMIT",
        "HIGH_RISK_ANOMALY_QUARANTINE",
    }
    assert data["policy_reasoning"]["policy_rule_name"] in verified_rules

    # Test 404
    resp_404 = client.get("/api/v1/events/non-existent-event-id/explanation")
    assert resp_404.status_code == 404
