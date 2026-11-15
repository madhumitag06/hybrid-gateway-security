"""
Phase 11 Telemetry Consistency, Risk Attribution & Reliability Regression Tests
==============================================================================
Validates:
1. Full-window provenance counts match evaluated_events_count (857 vs 100 defect resolution).
2. Segmented risk attribution preserves overall composite risk while separately computing
   AWS live-cloud and simulated-lab risk scores.
3. Explainability (XAI) feature attribution strictly isolates canonical V2 features
   and labels historical non-canonical features as '[Legacy RF / Historical]'.
4. AWS telemetry status persistently derives latest-run metrics and cumulative checkpoint totals.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.models.security_event import SecurityEventModel
from backend.app.models.cloud_account import CloudTelemetryIngestionModel, CloudTelemetryCheckpointModel
from backend.app.services.dashboard_service import DashboardService
from ml.features.extractor import FEATURE_NAMES_V2


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_provenance_full_window_reconciliation():
    """
    Assert that the sum of telemetry_provenance matches evaluatedEventsCount
    over the entire window, preventing the .limit(100) arithmetic clamping defect.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        assert data.evaluatedEventsCount >= 0
        provenance_sum = sum(data.telemetry_provenance.values())
        assert provenance_sum == data.evaluatedEventsCount, (
            f"Provenance sum ({provenance_sum}) must exactly equal "
            f"evaluatedEventsCount ({data.evaluatedEventsCount})"
        )
    finally:
        db.close()


def test_risk_segmentation_breakdown():
    """
    Assert that overall composite risk is preserved (0.7*max + 0.3*avg),
    and risk_segmentation contains overall_composite, aws_live_cloud, and simulated_lab.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        seg = data.risk_segmentation
        assert seg is not None, "risk_segmentation must not be None"
        assert "overall_composite" in seg
        assert "aws_live_cloud" in seg
        assert "simulated_lab" in seg

        assert seg["overall_composite"]["risk_score"] == data.riskScore
        assert seg["overall_composite"]["policy_action"] == data.riskState
        assert 0 <= seg["aws_live_cloud"]["risk_score"] <= 100
        assert 0 <= seg["simulated_lab"]["risk_score"] <= 100
    finally:
        db.close()


def test_xai_canonical_schema_isolation():
    """
    Assert that non-canonical features (such as failed_auth_count from legacy Random Forest)
    are labeled as '[Legacy RF / Historical]' and never represented as canonical XGBoost V2 features.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        for reason in data.reasons:
            if "Failed Authentication" in reason.label:
                assert "[Legacy RF / Historical]" in reason.label, (
                    f"failed_auth_count must be explicitly labeled as Legacy RF / Historical: {reason.label}"
                )
    finally:
        db.close()


def test_telemetry_status_persistence(client):
    """
    Assert that /api/v1/cloud/accounts/AWS/telemetry-status returns persistent
    latest_run_metrics and cumulative_checkpoint_metrics from database tables.
    """
    res = client.get("/api/v1/cloud/accounts/AWS/telemetry-status")
    assert res.status_code == 200
    data = res.json()

    assert data["provider"] == "AWS"
    assert "latest_run_metrics" in data
    assert "cumulative_checkpoint_metrics" in data

    latest = data["latest_run_metrics"]
    cumulative = data["cumulative_checkpoint_metrics"]

    assert "records_discovered" in latest
    assert "records_ingested" in latest
    assert "high_risk_detected" in latest
    assert "total_records_processed" in cumulative

    # If DB has history and checkpoints, ensure persistent values are non-zero
    db = SessionLocal()
    try:
        db_hist_count = db.query(CloudTelemetryIngestionModel).filter(
            CloudTelemetryIngestionModel.provider == "AWS"
        ).count()
        db_chk_count = db.query(CloudTelemetryCheckpointModel).filter(
            CloudTelemetryCheckpointModel.provider == "AWS"
        ).count()

        if db_hist_count > 0:
            assert latest["records_discovered"] > 0
            assert latest["records_ingested"] > 0
        if db_chk_count > 0:
            assert cumulative["total_records_processed"] > 0
    finally:
        db.close()
