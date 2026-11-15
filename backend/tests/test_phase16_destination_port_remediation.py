"""
Phase 16 — Destination-Port Aggregation Remediation Regression Suite
===================================================================
Covers all 14 mandatory verification criteria from Workstream D:
1. 60 destination ports are preserved.
2. Individual destination-port values survive parsing and aggregation.
3. unique_dst_ports remains 60 across the correct temporal window.
4. Repeated packets to the same port do not inflate unique-port counts.
5. Multiple source hosts remain isolated.
6. Multiple destination hosts remain correctly separated.
7. Different protocols are not incorrectly combined.
8. Temporal window expiration works.
9. Port-scan fixture detection remains correct.
10. Benign hybrid transit remains BENIGN.
11. Volumetric burst remains TRAFFIC_SPIKE.
12. All nine model features remain in exact order.
13. No failed_auth_count is introduced into the XGBoost V2 feature vector.
14. Existing CloudWatch live-ingestion behavior remains unchanged.
"""

from pathlib import Path
import time
import pytest

from backend.app.services.aws_sample_fixtures import ensure_aws_sample_fixtures, AWS_FIXTURE_DIR
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
from backend.app.services.flow_aggregator import HostPortTracker
from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from backend.app.services.ml_service import MLService
from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor, NetworkFlowInput


@pytest.fixture(autouse=True)
def reset_tracker():
    """Ensure clean temporal host tracker and authoritative primary model before each test."""
    MLService.promote_model("candidate_xgboost_v2", reason="Phase 16 authoritative primary model")
    AwsVpcFlowParser.reset_host_tracker()
    yield
    AwsVpcFlowParser.reset_host_tracker()


def test_01_02_03_09_port_scan_fixture_preservation_and_detection():
    """
    Criteria 1, 2, 3, 9:
    - 60 destination ports are preserved.
    - Individual destination-port values survive parsing and aggregation.
    - unique_dst_ports remains 60 across the temporal window.
    - Port-scan fixture detection remains correct (PORT_SCAN detected, risk elevated).
    """
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_port_scan_recon_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(raw_text, is_fixture=True, persist=False)

    # 1. Exactly 60 flows produced matching the 60 distinct destination ports
    assert resp.total_records_parsed == 60
    assert resp.total_flows_aggregated == 60

    # 2. Individual destination port values survive parsing and aggregation
    ports_survived = [f.dst_port for f in resp.results]
    assert len(set(ports_survived)) == 60
    assert set(ports_survived) == set(range(21, 81))

    # 3. unique_dst_ports remains 60 across all resulting flows
    for f in resp.results:
        assert f.unique_dst_ports == 60

    # 9. Port-scan detection remains correct
    scan_flows = [f for f in resp.results if f.prediction.attack_type == "PORT_SCAN"]
    assert len(scan_flows) >= 30
    assert resp.high_risk_flows_count >= 30
    # Scanner host is contained with Block actions
    block_actions = [f for f in resp.results if f.policy_decision and f.policy_decision.policy_action == "Block"]
    assert len(block_actions) >= 30


def test_04_repeated_packets_same_port_do_not_inflate_unique_ports():
    """
    Criterion 4: Repeated packets to the same destination port do not inflate unique-port counts,
    and multiple records for the same directed session are properly aggregated.
    """
    raw_lines = [
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 50000 443 6 5 2500 1710000000 1710000010 ACCEPT OK",
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 50000 443 6 10 5000 1710000010 1710000020 ACCEPT OK",
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 50000 443 6 15 7500 1710000020 1710000030 ACCEPT OK",
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 50001 80 6 2 120 1710000000 1710000001 ACCEPT OK",
    ]
    resp = AwsVpcFlowParser.ingest_vpc_flow_records("\n".join(raw_lines), is_fixture=True, persist=False)

    # 3 records for port 443 merge into 1 flow; 1 record for port 80 produces 1 flow -> Total 2 flows
    assert resp.total_flows_aggregated == 2

    # Port 443 flow should aggregate packets and bytes correctly
    flow_443 = next(f for f in resp.results if f.dst_port == 443)
    assert flow_443.packet_count == 30  # 5 + 10 + 15
    assert flow_443.byte_count == 15000  # 2500 + 5000 + 7500
    assert flow_443.duration == 30.0  # 1710000030 - 1710000000

    # Total unique destination ports observed for 10.0.0.1 is exactly 2 (443 and 80), NOT 4
    assert flow_443.unique_dst_ports == 2
    flow_80 = next(f for f in resp.results if f.dst_port == 80)
    assert flow_80.unique_dst_ports == 2


def test_05_multiple_source_hosts_isolated():
    """
    Criterion 5: Multiple source hosts maintain completely isolated destination-port tracking.
    """
    raw_lines = [
        # Host A probes 5 ports
        "2 123456789012 eni-01 192.168.1.10 10.0.0.2 50001 21 6 2 120 1710000000 1710000001 REJECT OK",
        "2 123456789012 eni-01 192.168.1.10 10.0.0.2 50002 22 6 2 120 1710000000 1710000001 REJECT OK",
        "2 123456789012 eni-01 192.168.1.10 10.0.0.2 50003 23 6 2 120 1710000000 1710000001 REJECT OK",
        "2 123456789012 eni-01 192.168.1.10 10.0.0.2 50004 25 6 2 120 1710000000 1710000001 REJECT OK",
        "2 123456789012 eni-01 192.168.1.10 10.0.0.2 50005 80 6 2 120 1710000000 1710000001 REJECT OK",
        # Host B accesses only 1 port
        "2 123456789012 eni-01 192.168.1.20 10.0.0.2 60001 443 6 10 5000 1710000000 1710000001 ACCEPT OK",
    ]
    resp = AwsVpcFlowParser.ingest_vpc_flow_records("\n".join(raw_lines), is_fixture=True, persist=False)

    flows_a = [f for f in resp.results if f.source_ip == "192.168.1.10"]
    flows_b = [f for f in resp.results if f.source_ip == "192.168.1.20"]

    assert len(flows_a) == 5
    assert len(flows_b) == 1

    # Host A flows must report exactly 5 unique destination ports
    for f in flows_a:
        assert f.unique_dst_ports == 5

    # Host B must report exactly 1 unique destination port and never be polluted by Host A
    assert flows_b[0].unique_dst_ports == 1
    assert flows_b[0].dst_port == 443


def test_06_multiple_destination_hosts_separated():
    """
    Criterion 6: Traffic from the same source to different destination hosts remains separated.
    """
    raw_lines = [
        "2 123456789012 eni-01 192.168.1.10 10.0.1.50 50001 80 6 10 1000 1710000000 1710000005 ACCEPT OK",
        "2 123456789012 eni-01 192.168.1.10 10.0.2.99 50001 80 6 10 1000 1710000000 1710000005 ACCEPT OK",
    ]
    resp = AwsVpcFlowParser.ingest_vpc_flow_records("\n".join(raw_lines), is_fixture=True, persist=False)

    assert resp.total_flows_aggregated == 2
    dst_ips = {f.destination_ip for f in resp.results}
    assert dst_ips == {"10.0.1.50", "10.0.2.99"}


def test_07_different_protocols_not_combined():
    """
    Criterion 7: Different protocols between the same endpoints are not combined.
    """
    raw_lines = [
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 5353 53 17 5 500 1710000000 1710000001 ACCEPT OK",  # UDP (17)
        "2 123456789012 eni-01 10.0.0.1 10.0.0.2 5353 53 6 10 1000 1710000000 1710000001 ACCEPT OK",  # TCP (6)
    ]
    resp = AwsVpcFlowParser.ingest_vpc_flow_records("\n".join(raw_lines), is_fixture=True, persist=False)

    assert resp.total_flows_aggregated == 2
    protos = {f.protocol_name for f in resp.results}
    assert protos == {"TCP", "UDP"}


def test_08_temporal_window_expiration():
    """
    Criterion 8: Rolling temporal window (60 seconds) expires older target ports.
    """
    tracker = HostPortTracker(window_seconds=60.0)
    src_ip = "192.168.1.50"

    # t = 1000: Host probes 10 ports
    for port in range(20, 30):
        tracker.record_destination_port(src_ip, port, timestamp=1000.0)

    assert tracker.get_unique_dst_ports(src_ip, current_time=1010.0) == 10

    # t = 1070: 70 seconds later (> 60s window), previous 10 ports expire
    # Host probes 1 port at t = 1070
    tracker.record_destination_port(src_ip, 443, timestamp=1070.0)

    # At t = 1071, only port 443 is in the [1011, 1071] window
    assert tracker.get_unique_dst_ports(src_ip, current_time=1071.0) == 1


def test_10_benign_hybrid_transit_remains_benign():
    """
    Criterion 10: Benign hybrid transit fixture remains classified as BENIGN with low risk score.
    """
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_benign_transit_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(raw_text, is_fixture=True, persist=False)

    assert resp.total_flows_aggregated == 1
    flow = resp.results[0]
    assert flow.prediction.attack_type == "BENIGN"
    assert flow.prediction.risk_score < 40
    assert flow.dst_port == 443
    assert flow.unique_dst_ports == 1


def test_11_volumetric_burst_remains_traffic_spike():
    """
    Criterion 11: Volumetric HTTP burst fixture remains classified as TRAFFIC_SPIKE with high risk score.
    """
    ensure_aws_sample_fixtures()
    sample_file = AWS_FIXTURE_DIR / "aws_volumetric_burst_fixture.log"
    raw_text = sample_file.read_text(encoding="utf-8")

    resp = AwsVpcFlowParser.ingest_vpc_flow_records(raw_text, is_fixture=True, persist=False)

    assert resp.total_flows_aggregated == 1
    flow = resp.results[0]
    assert flow.prediction.attack_type == "TRAFFIC_SPIKE"
    assert flow.prediction.risk_score >= 85
    assert flow.dst_port == 80


def test_12_13_canonical_9_feature_schema_parity_and_no_auth():
    """
    Criteria 12, 13:
    - All nine features remain in exact canonical order matching FEATURE_NAMES_V2.
    - failed_auth_count is strictly excluded from the V2 vector.
    """
    flow_input = NetworkFlowInput(
        packet_count=2,
        byte_count=120,
        duration=1.0,
        conn_rate=2.0,
        dst_port=21,
        unique_dst_ports=60,
        failed_auth_count=0,
    )

    X = FeatureExtractor.extract_from_flow(flow_input, schema=FEATURE_NAMES_V2)

    # 12. Exact 9 features
    assert X.shape == (1, 9)
    assert len(FEATURE_NAMES_V2) == 9

    expected_names = [
        "packet_count",
        "byte_count",
        "duration",
        "conn_rate",
        "dst_port",
        "unique_dst_ports",
        "bytes_per_sec",
        "packets_per_sec",
        "avg_packet_size",
    ]
    assert FEATURE_NAMES_V2 == expected_names

    # 13. failed_auth_count is NOT in FEATURE_NAMES_V2
    assert "failed_auth_count" not in FEATURE_NAMES_V2


def test_14_existing_cloudwatch_live_ingestion_behavior_unchanged():
    """
    Criterion 14: TelemetryNormalizer for live CloudWatch ingestion retains its exact
    directed 7-tuple aggregation behavior and batch-level port diversity tracking.
    """
    raw_rec_1 = CanonicalFlowRecord(
        flow_id="cw-flow-01",
        provider="AWS",
        account_id="123456789012",
        interface_id="eni-live-01",
        src_ip="10.0.1.5",
        dst_ip="10.0.2.10",
        src_port=44321,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        packet_count=10,
        byte_count=8500,
        duration=1.5,
        start_time=1710000000,
        end_time=1710000002,
        action="ACCEPT",
        log_status="OK",
    )
    raw_rec_2 = CanonicalFlowRecord(
        flow_id="cw-flow-02",
        provider="AWS",
        account_id="123456789012",
        interface_id="eni-live-01",
        src_ip="10.0.1.5",
        dst_ip="10.0.2.10",
        src_port=44321,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        packet_count=15,
        byte_count=12000,
        duration=1.5,
        start_time=1710000002,
        end_time=1710000004,
        action="ACCEPT",
        log_status="OK",
    )

    batch_res = TelemetryNormalizer.process_canonical_batch(
        records=[raw_rec_1, raw_rec_2],
        provider="AWS",
        account_id="123456789012",
        persist=False,
    )

    # Identical directed 5-tuples on same interface merge into 1 flow
    assert len(batch_res.flows) == 1
    flow = batch_res.flows[0]
    assert flow.packet_count == 25
    assert flow.byte_count == 20500
    assert flow.dst_port == 443
    assert flow.provider == "AWS"
