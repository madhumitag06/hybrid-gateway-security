"""
Unit tests for Canonical Telemetry Normalization & 9-Feature Parity across AWS, GCP, Azure, and Docker Lab.
"""

from datetime import datetime, timezone
from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from ml.features.extractor import FEATURE_NAMES_V2


def test_canonical_9_feature_normalization_parity():
    """Verify that TelemetryNormalizer extracts exactly the 9 canonical features without failed_auth_count."""
    now = datetime.now(timezone.utc)
    rec = CanonicalFlowRecord(
        flow_id="test-parity-01",
        provider="AWS",
        account_id="aws-prod",
        src_ip="10.20.10.15",
        dst_ip="10.20.10.2",
        src_port=44321,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        packet_count=50,
        byte_count=40000,
        duration=2.5,
        conn_rate=20.0,
        bytes_per_sec=16000.0,
        packets_per_sec=20.0,
        avg_packet_size=800.0,
        unique_dst_ports=1,
        timestamp=now,
    )

    enriched, feat_dict = TelemetryNormalizer.normalize_flow_record(rec)

    # 1. Feature key count and exact membership check
    assert len(feat_dict) == 9
    assert list(feat_dict.keys()) == FEATURE_NAMES_V2

    # 2. Strict verification: failed_auth_count is NOT in feature_dict
    assert "failed_auth_count" not in feat_dict

    # 3. Mathematical validation of derived features
    assert feat_dict["packet_count"] == 50.0
    assert feat_dict["byte_count"] == 40000.0
    assert feat_dict["duration"] == 2.5
    assert feat_dict["conn_rate"] == 50.0 / 2.5
    assert feat_dict["bytes_per_sec"] == 40000.0 / 2.5
    assert feat_dict["packets_per_sec"] == 50.0 / 2.5
    assert feat_dict["avg_packet_size"] == 40000.0 / 50.0


def test_stateful_port_diversity_tracking():
    """Verify stateful destination port diversity tracking per source IP."""
    tracker = {}
    now = datetime.now(timezone.utc)

    # Flow 1 targeting port 80
    r1 = CanonicalFlowRecord(
        flow_id="flw-01",
        provider="GCP",
        account_id="gcp-prod",
        src_ip="198.51.100.5",
        dst_ip="10.40.10.2",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        protocol_number=6,
        packet_count=10,
        byte_count=1000,
        duration=1.0,
        timestamp=now,
    )
    _, f1 = TelemetryNormalizer.normalize_flow_record(r1, stateful_port_tracker=tracker)
    assert f1["unique_dst_ports"] == 1.0

    # Flow 2 from same source targeting port 443
    r2 = CanonicalFlowRecord(
        flow_id="flw-02",
        provider="GCP",
        account_id="gcp-prod",
        src_ip="198.51.100.5",
        dst_ip="10.40.10.2",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        packet_count=10,
        byte_count=1000,
        duration=1.0,
        timestamp=now,
    )
    _, f2 = TelemetryNormalizer.normalize_flow_record(r2, stateful_port_tracker=tracker)
    assert f2["unique_dst_ports"] == 2.0

    # Flow 3 from same source targeting port 8080
    r3 = CanonicalFlowRecord(
        flow_id="flw-03",
        provider="GCP",
        account_id="gcp-prod",
        src_ip="198.51.100.5",
        dst_ip="10.40.10.2",
        src_port=50002,
        dst_port=8080,
        protocol="TCP",
        protocol_number=6,
        packet_count=10,
        byte_count=1000,
        duration=1.0,
        timestamp=now,
    )
    _, f3 = TelemetryNormalizer.normalize_flow_record(r3, stateful_port_tracker=tracker)
    assert f3["unique_dst_ports"] == 3.0


def test_batch_normalization_across_all_providers():
    """Verify batch processing and normalization across AWS, GCP, Azure, and Docker Lab records."""
    now = datetime.now(timezone.utc)
    records = [
        CanonicalFlowRecord(
            flow_id="aws-flw",
            provider="AWS",
            account_id="aws-prod",
            src_ip="10.20.10.15",
            dst_ip="10.20.10.2",
            src_port=49000,
            dst_port=443,
            protocol="TCP",
            protocol_number=6,
            packet_count=20,
            byte_count=15000,
            duration=1.0,
            timestamp=now,
        ),
        CanonicalFlowRecord(
            flow_id="gcp-flw",
            provider="GCP",
            account_id="gcp-prod",
            src_ip="10.40.10.15",
            dst_ip="10.40.10.2",
            src_port=49001,
            dst_port=80,
            protocol="TCP",
            protocol_number=6,
            packet_count=15,
            byte_count=12000,
            duration=1.2,
            timestamp=now,
        ),
        CanonicalFlowRecord(
            flow_id="az-flw",
            provider="AZURE",
            account_id="az-prod",
            src_ip="10.50.10.15",
            dst_ip="10.50.10.2",
            src_port=49002,
            dst_port=22,
            protocol="TCP",
            protocol_number=6,
            packet_count=8,
            byte_count=800,
            duration=0.5,
            timestamp=now,
        ),
        CanonicalFlowRecord(
            flow_id="lab-flw",
            provider="DOCKER_LAB",
            account_id="lab-prod",
            src_ip="10.10.10.15",
            dst_ip="10.20.10.2",
            src_port=49003,
            dst_port=8080,
            protocol="TCP",
            protocol_number=6,
            packet_count=25,
            byte_count=20000,
            duration=1.5,
            timestamp=now,
        ),
    ]

    response = TelemetryNormalizer.process_canonical_batch(
        records=records,
        provider="MULTI_CLOUD",
        account_id="agg-batch",
        db=None,
        persist=False,
    )

    assert response.status == "SUCCESS"
    assert response.records_received == 4
    assert len(response.flows) == 4
    assert response.normalization_report.schema_version == "v2_canonical"
    assert response.normalization_report.failed_auth_synthesized is False
    assert response.normalization_report.features_extracted == FEATURE_NAMES_V2

