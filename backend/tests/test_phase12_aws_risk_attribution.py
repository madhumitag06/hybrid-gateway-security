"""
Phase 12 AWS Live Risk Attribution Integrity Regression Tests
============================================================
Validates:
1. Genuine AWS CloudWatch records are attributed to aws_live_cloud.
2. AWS sandbox fixtures (is_demo=True, AWS_VPC_FLOW_LOG_FIXTURE) are attributed to simulated_lab.
3. Sandbox attack fixtures cannot inflate AWS live risk.
4. Missing provenance remains UNKNOWN / LEGACY unless reliable metadata establishes source.
5. Genuine AWS records retain all nine canonical ML features.
6. Telemetry metadata never enters the model feature vector.
7. Risk calculations use only the appropriate source records.
8. Historical composite risk remains mathematically preserved.
9. Existing provenance totals reconcile 100% against total evaluated window events.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.models.security_event import SecurityEventModel
from backend.app.services.dashboard_service import DashboardService
from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from ml.features.extractor import FEATURE_NAMES_V2


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_genuine_aws_records_attributed_to_aws_live_cloud():
    """
    Test 1: Verify that genuine AWS records in the database are classified
    as AWS_VPC_FLOW_LOG and attributed to aws_live_cloud.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        seg = data.risk_segmentation
        assert seg is not None
        assert "aws_live_cloud" in seg
        aws_seg = seg["aws_live_cloud"]

        # If live AWS records exist in the 24h window, ensure they are attributed
        if data.telemetry_provenance.get("AWS_VPC_FLOW_LOG", 0) > 0:
            assert aws_seg["evaluated_flows_count"] == data.telemetry_provenance["AWS_VPC_FLOW_LOG"]
            assert 0 <= aws_seg["risk_score"] <= 100
            assert aws_seg["policy_action"] in ("Allow", "Monitor", "Restrict", "Block")
    finally:
        db.close()


def test_aws_sandbox_fixtures_attributed_to_simulated_lab():
    """
    Test 2 & 3: Verify that AWS sandbox fixtures (AWS_VPC_FLOW_LOG_FIXTURE or is_demo=True)
    are attributed to simulated_lab and cannot inflate aws_live_cloud risk.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        seg = data.risk_segmentation
        assert seg is not None
        aws_seg = seg["aws_live_cloud"]
        lab_seg = seg["simulated_lab"]

        # Fixture count must be tracked under simulated_lab, not aws_live_cloud
        fixture_count = data.telemetry_provenance.get("AWS_VPC_FLOW_LOG_FIXTURE", 0)
        if fixture_count > 0:
            # Lab flows must encompass fixtures
            assert lab_seg["evaluated_flows_count"] >= fixture_count
            # AWS live cloud evaluated count must strictly match genuine AWS flow logs
            assert aws_seg["evaluated_flows_count"] == data.telemetry_provenance.get("AWS_VPC_FLOW_LOG", 0)
            # Simulated lab risk must absorb the fixtures
            assert lab_seg["risk_score"] >= 70
    finally:
        db.close()


def test_missing_provenance_remains_unknown_legacy():
    """
    Test 4: Verify that events with missing or unestablished provenance remain UNKNOWN / LEGACY.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        prov = data.telemetry_provenance
        # The database contains legacy records without reliable telemetry metadata
        assert "UNKNOWN / LEGACY" in prov
        assert prov["UNKNOWN / LEGACY"] > 0
    finally:
        db.close()


def test_genuine_aws_records_retain_canonical_features_and_metadata_isolation():
    """
    Test 5 & 6: Verify that TelemetryNormalizer produces records retaining all 9 canonical
    features, and that provenance metadata is stored in flow_features without contaminating
    the canonical ML vector.
    """
    raw_rec = CanonicalFlowRecord(
        flow_id="test-canonical-aws-flow-01",
        provider="AWS",
        src_ip="10.20.10.15",
        dst_ip="10.20.10.2",
        src_port=44321,
        dst_port=443,
        protocol="TCP",
        packet_count=10,
        byte_count=8500,
        duration=1.5,
        action="ACCEPT",
        log_status="OK",
    )

    port_tracker = {}
    enriched, feat_dict = TelemetryNormalizer.normalize_flow_record(raw_rec, port_tracker)

    # 5. Exactly 9 canonical features must be present
    for feat in FEATURE_NAMES_V2:
        assert feat in feat_dict, f"Missing canonical feature: {feat}"
    assert len(feat_dict) == len(FEATURE_NAMES_V2)

    # 6. Metadata must not be in feat_dict (the ML vector)
    assert "telemetry_source" not in feat_dict
    assert "provider" not in feat_dict

    # Verify batch processing produces correct metadata in stored payload
    batch_res = TelemetryNormalizer.process_canonical_batch(
        records=[raw_rec],
        provider="AWS",
        account_id="123456789012",
        persist=False,
    )
    assert batch_res.provider == "AWS"
    assert len(batch_res.flows) == 1
    assert batch_res.flows[0].threat_level in ["BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_risk_calculations_use_only_appropriate_sources():
    """
    Test 7 & 8: Verify that risk calculations segregate source records cleanly,
    and historical overall composite risk calculation is mathematically preserved.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        seg = data.risk_segmentation
        assert seg is not None

        # Overall composite risk must match data.riskScore exactly
        assert seg["overall_composite"]["risk_score"] == data.riskScore
        assert seg["overall_composite"]["policy_action"] == data.riskState

        # AWS live cloud risk must be distinct from simulated lab risk
        if seg["aws_live_cloud"]["evaluated_flows_count"] > 0:
            assert seg["aws_live_cloud"]["risk_score"] != seg["simulated_lab"]["risk_score"]
            assert seg["aws_live_cloud"]["risk_score"] < seg["simulated_lab"]["risk_score"]
    finally:
        db.close()


def test_provenance_totals_reconciliation():
    """
    Test 9: Verify that the sum of telemetry_provenance matches evaluatedEventsCount 100%.
    """
    db = SessionLocal()
    try:
        data = DashboardService.get_dashboard_data(db, time_range="24h")
        prov_sum = sum(data.telemetry_provenance.values())
        assert prov_sum == data.evaluatedEventsCount, (
            f"Provenance sum ({prov_sum}) must exactly equal evaluatedEventsCount ({data.evaluatedEventsCount})"
        )
    finally:
        db.close()
