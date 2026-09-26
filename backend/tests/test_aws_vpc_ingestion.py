"""
Unit Tests for AWS VPC Flow Log Ingestion & Normalization
=========================================================
Tests parsing, strict feature provenance (failed_auth_count == 0),
session aggregation, and Phase 1 ML inference over VPC flow records.
"""

import pytest
from backend.app.db.session import SessionLocal
from backend.app.schemas.aws_flow import VpcFlowLogRecordSchema
from backend.app.services.aws_sample_fixtures import ensure_aws_sample_fixtures, AWS_FIXTURE_DIR
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_parse_raw_v2_line():
    """Verify standard AWS VPC Flow Log v2 line parsing."""
    raw_line = "2 123456789012 eni-0a1b2c3d4e5f67890 192.168.1.100 10.100.1.10 54321 443 6 25 15000 1710000000 1710000005 ACCEPT OK"
    rec = AwsVpcFlowParser.parse_raw_log_line(raw_line)

    assert rec is not None
    assert rec.version == 2
    assert rec.account_id == "123456789012"
    assert rec.interface_id == "eni-0a1b2c3d4e5f67890"
    assert rec.src_addr == "192.168.1.100"
    assert rec.dst_addr == "10.100.1.10"
    assert rec.src_port == 54321
    assert rec.dst_port == 443
    assert rec.protocol == 6
    assert rec.packets == 25
    assert rec.bytes == 15000
    assert rec.action == "ACCEPT"
    assert rec.log_status == "OK"


def test_parse_header_and_nodata_filtered():
    """Verify headers, comments, and NODATA/SKIPDATA records are filtered out."""
    header_line = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    assert AwsVpcFlowParser.parse_raw_log_line(header_line) is None

    nodata_line = "2 123456789012 eni-1111 - - - - - - - 1710000000 1710000060 - NODATA"
    assert AwsVpcFlowParser.parse_raw_log_line(nodata_line) is None

    short_line = "2 123456789012 eni-1111"
    assert AwsVpcFlowParser.parse_raw_log_line(short_line) is None


def test_feature_provenance_failed_auth_zero():
    """Verify failed_auth_count is strictly 0 for AWS VPC flow logs without exception."""
    raw_log = "2 123456789012 eni-001 192.168.1.50 10.100.1.10 40000 22 6 50 4000 1710000000 1710000002 REJECT OK"
    resp = AwsVpcFlowParser.ingest_vpc_flow_records(raw_log, is_fixture=False, persist=False)

    assert resp.total_flows_aggregated == 1
    flow_item = resp.results[0]
    assert flow_item.failed_auth_count == 0


def test_port_scan_recon_fixture_ingestion(db_session):
    """Verify multi-port reconnaissance probe fixture is aggregated and detected as PORT_SCAN."""
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_port_scan_recon_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_text,
        is_fixture=True,
        source_label="aws_port_scan_recon_fixture.log",
        persist=True,
        db=db_session,
    )

    assert resp.telemetry_source == "AWS_VPC_FLOW_LOG_FIXTURE"
    assert resp.is_fixture is True
    assert resp.total_records_parsed == 60
    assert resp.total_flows_aggregated == 1  # Aggregated into 1 session (same src/dst/proto)

    flow = resp.results[0]
    assert flow.unique_dst_ports == 60
    assert flow.prediction.attack_type == "PORT_SCAN"
    assert flow.prediction.risk_score >= 70
    assert flow.prediction.threat_level == "HIGH"
    assert flow.source_zone == "ON_PREMISE"
    assert flow.destination_zone == "AWS_VPC"
    assert flow.traffic_direction == "ON_PREM_TO_CLOUD"
    assert flow.persisted_event_id is not None


def test_volumetric_traffic_spike_fixture_ingestion(db_session):
    """Verify 1500-packet throughput surge fixture is classified as TRAFFIC_SPIKE."""
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_volumetric_burst_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_text,
        is_fixture=True,
        source_label="aws_volumetric_burst_fixture.log",
        persist=True,
        db=db_session,
    )

    assert resp.total_flows_aggregated == 1
    flow = resp.results[0]
    assert flow.packet_count == 1500
    assert flow.prediction.attack_type == "TRAFFIC_SPIKE"
    assert flow.traffic_direction in ["INGRESS_EXTERNAL", "ON_PREM_TO_CLOUD"]


def test_benign_transit_fixture_ingestion(db_session):
    """Verify benign hybrid transit fixture is classified as BENIGN."""
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_benign_transit_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_text,
        is_fixture=True,
        source_label="aws_benign_transit_fixture.log",
        persist=True,
        db=db_session,
    )

    assert resp.total_flows_aggregated == 1
    flow = resp.results[0]
    assert flow.prediction.attack_type == "BENIGN"
    assert flow.prediction.risk_score < 40
    assert flow.source_zone == "ON_PREMISE"
    assert flow.destination_zone == "AWS_VPC"


def test_telemetry_source_distinct_labeling():
    """Verify distinct labeling: AWS_VPC_FLOW_LOG vs AWS_VPC_FLOW_LOG_FIXTURE."""
    raw_log = "2 123456789012 eni-001 192.168.1.50 10.100.1.10 40000 80 6 10 1000 1710000000 1710000002 ACCEPT OK"

    # Fixture upload
    resp_fixture = AwsVpcFlowParser.ingest_vpc_flow_records(raw_log, is_fixture=True, persist=False)
    assert resp_fixture.telemetry_source == "AWS_VPC_FLOW_LOG_FIXTURE"

    # Real telemetry upload
    resp_real = AwsVpcFlowParser.ingest_vpc_flow_records(raw_log, is_fixture=False, persist=False)
    assert resp_real.telemetry_source == "AWS_VPC_FLOW_LOG"
