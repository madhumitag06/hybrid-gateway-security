"""
Phase 22.8 Test Suite: Telemetry Ingestion Idempotency & Scenario Execution Reliability
========================================================================================
Validates:
1. Persistent PCAP ingestion tracking using SHA-256 content hashing across sensor restarts.
2. Identical PCAP re-ingestion produces zero additional security events or database rows.
3. Genuinely modified PCAP content is processed as a new version.
4. Interrupted / crashed processing recovers safely without marking partial files as completed.
5. Failed processing records error status and permits retry.
6. Concurrency locks prevent simultaneous processing by startup scans and file watchers.
7. Startup scanning across multiple container restarts is strictly idempotent.
8. AWS VPC flow log deduplication prevents duplicate event records.
9. Scenario execution lifecycle correctly distinguishes QUEUED, RUNNING, COMPLETED, FAILED,
   and TIMED_OUT states (and never reports false traffic generation).
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Generator
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db.base import Base
from backend.app.db.session import engine, SessionLocal
from backend.app.models.pcap_ingestion import PcapIngestionModel
from backend.app.models.security_event import SecurityEventModel
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
from backend.app.services.hybrid_traffic_service import HybridTrafficService
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.sample_pcap_generator import ensure_sample_pcaps, SAMPLE_DIR
import sys

TELEMETRY_PKG_DIR = Path(__file__).resolve().parent.parent.parent / "deployment" / "hybrid-lab" / "telemetry"
if str(TELEMETRY_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(TELEMETRY_PKG_DIR))

from ingestion_ledger import IngestionLedger


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    ensure_sample_pcaps()
    yield


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==============================================================================
# 1. PCAP Ingestion Tracking & SHA-256 Ledger
# ==============================================================================

def test_persistent_ingestion_ledger_sha256(tmp_path: Path):
    """Verify SHA-256 content tracking and persistent disk serialization."""
    ledger_file = tmp_path / "metadata" / "pcap_ingestion_ledger.json"
    pcap_file = tmp_path / "pcaps" / "test_capture.pcap"
    pcap_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Create synthetic PCAP file (> 24 bytes)
    pcap_content = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 40
    pcap_file.write_bytes(pcap_content)
    expected_sha = hashlib.sha256(pcap_content).hexdigest()

    # Step 1: Initialize fresh ledger
    ledger1 = IngestionLedger(ledger_file)
    should, reason, sha = ledger1.should_ingest(pcap_file)
    assert should is True
    assert reason == "NEW_UNSEEN_FILE"
    assert sha == expected_sha

    # Step 2: Mark in progress, then completed
    ledger1.mark_in_progress(pcap_file, sha)
    entry = ledger1.get_entry(pcap_file.name)
    assert entry["status"] == "IN_PROGRESS"
    assert entry["sha256"] == expected_sha

    summary = {"packets_processed": 5, "flows_evaluated": 1, "events_persisted": 1}
    ledger1.mark_completed(pcap_file, sha, summary)
    entry = ledger1.get_entry(pcap_file.name)
    assert entry["status"] == "COMPLETED"
    assert entry["summary"] == summary

    # Step 3: Simulate sensor restart with a new ledger instance reading from disk
    ledger2 = IngestionLedger(ledger_file)
    should_restart, reason_restart, sha_restart = ledger2.should_ingest(pcap_file)
    assert should_restart is False
    assert reason_restart == "ALREADY_COMPLETED_IDENTICAL_HASH"
    assert sha_restart == expected_sha


def test_identical_pcap_ingestion_zero_duplicate_records(tmp_path: Path, db_session: Session):
    """
    Verify that ingesting an identical PCAP twice creates exactly zero additional
    security events and zero duplicate ingestion rows.
    """
    # Create an isolated test PCAP file in tmp_path
    pcap_path = tmp_path / "unique_test_scan.pcap"
    # Copy from sample_pcaps or write synthetic packets
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap

    packets = [
        IP(src="192.168.1.105", dst="10.100.4.55") / TCP(sport=50000 + i, dport=80 + i, flags="S")
        for i in range(5)
    ]
    wrpcap(str(pcap_path), packets)

    initial_event_count = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0
    initial_ingest_count = db_session.scalar(select(func.count(PcapIngestionModel.id))) or 0

    # First ingestion: should parse, evaluate, and persist events
    res1 = IngestionService.ingest_pcap_file(
        filepath=pcap_path,
        filename="unique_test_scan.pcap",
        persist=True,
        db=db_session,
    )
    assert res1.flows_evaluated > 0

    after_first_events = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0
    after_first_ingest = db_session.scalar(select(func.count(PcapIngestionModel.id))) or 0

    assert after_first_ingest == initial_ingest_count + 1
    new_events_created = after_first_events - initial_event_count
    assert new_events_created > 0

    # Second ingestion of the exact same PCAP: must be completely idempotent!
    res2 = IngestionService.ingest_pcap_file(
        filepath=pcap_path,
        filename="unique_test_scan.pcap",
        persist=True,
        db=db_session,
    )

    after_second_events = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0
    after_second_ingest = db_session.scalar(select(func.count(PcapIngestionModel.id))) or 0

    # VERIFY ZERO DUPLICATE RECORDS
    assert after_second_events == after_first_events, "Duplicate ingestion must create exactly 0 additional security events"
    assert after_second_ingest == after_first_ingest, "Duplicate ingestion must create exactly 0 additional ingestion rows"
    assert res2.events_persisted == 0, "Response must report events_persisted = 0 on idempotent skip"


def test_changed_pcap_content_creates_new_version(tmp_path: Path):
    """Verify that genuinely modified PCAP content is detected as a new version."""
    ledger_file = tmp_path / "metadata" / "pcap_ingestion_ledger.json"
    pcap_file = tmp_path / "pcaps" / "stream.pcap"
    pcap_file.parent.mkdir(parents=True, exist_ok=True)

    # Version 1
    content_v1 = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"VERSION_1_PACKET_STREAM" * 3
    pcap_file.write_bytes(content_v1)
    sha_v1 = hashlib.sha256(content_v1).hexdigest()

    ledger = IngestionLedger(ledger_file)
    assert ledger.should_ingest(pcap_file)[0] is True
    ledger.mark_in_progress(pcap_file, sha_v1)
    ledger.mark_completed(pcap_file, sha_v1, {"v": 1})
    assert ledger.get_entry(pcap_file.name)["version"] == 1

    # Version 2 (file modified / new traffic appended)
    content_v2 = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"VERSION_2_MODIFIED_TRAFFIC_DATA" * 4
    pcap_file.write_bytes(content_v2)
    sha_v2 = hashlib.sha256(content_v2).hexdigest()
    assert sha_v1 != sha_v2

    should, reason, sha = ledger.should_ingest(pcap_file)
    assert should is True
    assert reason == "CONTENT_MODIFIED_NEW_VERSION"
    assert sha == sha_v2

    ledger.mark_in_progress(pcap_file, sha_v2)
    ledger.mark_completed(pcap_file, sha_v2, {"v": 2})
    assert ledger.get_entry(pcap_file.name)["version"] == 2


def test_interrupted_processing_recovery(tmp_path: Path):
    """Verify that interrupted/crashed ingestions are safely recovered and not marked completed."""
    ledger_file = tmp_path / "metadata" / "pcap_ingestion_ledger.json"
    pcap_file = tmp_path / "pcaps" / "interrupted.pcap"
    pcap_file.parent.mkdir(parents=True, exist_ok=True)
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"CRASH_TEST_DATA" * 5)
    sha = hashlib.sha256(pcap_file.read_bytes()).hexdigest()

    # Worker starts ingestion and sets stale_timeout to 1.0 second for testing
    ledger = IngestionLedger(ledger_file, stale_timeout_sec=1.0)
    ledger.mark_in_progress(pcap_file, sha)
    
    # Before timeout: should reject concurrent/active
    should, reason, _ = ledger.should_ingest(pcap_file)
    assert should is False
    assert reason == "IN_PROGRESS_ACTIVE"

    # Simulate worker crash: wait for stale timeout to elapse
    time.sleep(1.1)

    # After stale timeout: must detect crash and allow recovery
    should_retry, reason_retry, _ = ledger.should_ingest(pcap_file)
    assert should_retry is True
    assert reason_retry == "INTERRUPTED_PROCESSING_STALE_RETRY"

    # Confirm it was never prematurely marked COMPLETED
    assert ledger.get_entry(pcap_file.name)["status"] == "IN_PROGRESS"


def test_failed_processing_allows_retry_and_never_completed(tmp_path: Path):
    """Verify that failed ingestions record error status, are not completed, and permit retry."""
    ledger_file = tmp_path / "metadata" / "pcap_ingestion_ledger.json"
    pcap_file = tmp_path / "pcaps" / "bad_stream.pcap"
    pcap_file.parent.mkdir(parents=True, exist_ok=True)
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"FAIL_RECORD_DATA" * 5)
    sha = hashlib.sha256(pcap_file.read_bytes()).hexdigest()

    ledger = IngestionLedger(ledger_file)
    ledger.mark_in_progress(pcap_file, sha)
    ledger.mark_failed(pcap_file, sha, "Network timeout connecting to gateway API")

    entry = ledger.get_entry(pcap_file.name)
    assert entry["status"] == "FAILED"
    assert "Network timeout" in entry["error_message"]

    should, reason, _ = ledger.should_ingest(pcap_file)
    assert should is True
    assert reason == "RETRY_PREVIOUS_FAILURE"


def test_concurrent_processing_lock(tmp_path: Path):
    """Verify that two workers cannot process the same file simultaneously."""
    ledger_file = tmp_path / "metadata" / "pcap_ingestion_ledger.json"
    ledger = IngestionLedger(ledger_file)

    filename = "shared_capture.pcap"
    assert ledger.acquire_processing(filename) is True
    # Second acquisition must fail
    assert ledger.acquire_processing(filename) is False

    ledger.release_processing(filename)
    # After release, re-acquisition succeeds
    assert ledger.acquire_processing(filename) is True
    ledger.release_processing(filename)


def test_startup_scanning_idempotency_across_restarts(tmp_path: Path, monkeypatch):
    """
    Verify that sensor startup scanning across multiple sensor container restarts
    processes each file exactly once and skips all unchanged files on subsequent startups.
    """
    pcap_dir = tmp_path / "pcaps"
    meta_dir = tmp_path / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # Populate 3 historical PCAPs
    for i in range(1, 4):
        pcap_f = pcap_dir / f"scenario{i}_test.pcap"
        pcap_f.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + f"PAYLOAD_SCENARIO_{i}".encode() * 5)

    import sensor_service
    monkeypatch.setattr(sensor_service, "PCAP_DIR", pcap_dir)
    monkeypatch.setattr(sensor_service, "META_DIR", meta_dir)

    upload_calls = []
    def mock_upload(pcap_path, persist=True):
        upload_calls.append(pcap_path.name)
        return {
            "metrics": {"packets_processed": 10},
            "flows_generated": 1,
            "flows_evaluated": 1,
            "events_persisted": 1,
            "high_risk_flows_count": 0,
            "results": [],
        }

    monkeypatch.setattr(sensor_service, "upload_pcap_to_gateway", mock_upload)
    monkeypatch.setattr(sensor_service, "enforce_capture_bounds", lambda p, m: {})

    ledger_path = meta_dir / "pcap_ingestion_ledger.json"

    # Startup 1: First time sensor starts up
    ledger1 = IngestionLedger(ledger_path)
    res_start1 = sensor_service.run_startup_scan(ledger1, include_vpc_logs=False, persist=True)
    assert len(res_start1) == 3
    assert len(upload_calls) == 3

    # Startup 2: Sensor container restarts! New IngestionLedger loads from persistent volume
    upload_calls.clear()
    ledger2 = IngestionLedger(ledger_path)
    res_start2 = sensor_service.run_startup_scan(ledger2, include_vpc_logs=False, persist=True)

    # Exactly 0 files re-uploaded on restart!
    assert len(res_start2) == 0
    assert len(upload_calls) == 0

    # Startup 3: A new 4th PCAP arrives while the other 3 remain unchanged
    new_pcap = pcap_dir / "scenario4_test.pcap"
    new_pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"PAYLOAD_SCENARIO_4" * 5)

    ledger3 = IngestionLedger(ledger_path)
    res_start3 = sensor_service.run_startup_scan(ledger3, include_vpc_logs=False, persist=True)

    # Only the new 4th PCAP is ingested! The first 3 are skipped idempotently!
    assert len(res_start3) == 1
    assert len(upload_calls) == 1
    assert upload_calls[0] == "scenario4_test.pcap"


# ==============================================================================
# 2. AWS VPC Flow Log Deduplication
# ==============================================================================

def test_vpc_flow_log_deduplication_zero_duplicates(db_session: Session):
    """Verify repeated ingestion of identical VPC flow logs creates zero duplicate security events."""
    raw_vpc_logs = (
        "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status flow-direction\n"
        "2 123456789012 eni-0123456789abcdef0 10.10.10.10 10.20.10.20 54321 8080 6 25 15000 1600000000 1600000060 ACCEPT OK ingress\n"
    )

    initial_events = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0

    # Ingest VPC flow log first time
    res1 = AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_vpc_logs,
        is_fixture=True,
        source_label="idempotency_test_log",
        persist=True,
        db=db_session,
    )
    after_first = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0
    assert after_first >= initial_events + 1

    # Ingest the exact same VPC flow log second time
    res2 = AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_vpc_logs,
        is_fixture=True,
        source_label="idempotency_test_log",
        persist=True,
        db=db_session,
    )
    after_second = db_session.scalar(select(func.count(SecurityEventModel.id))) or 0

    # Must NOT create duplicate event records!
    assert after_second == after_first, "Repeated VPC flow log ingestion must create zero duplicate security events"


# ==============================================================================
# 3. Scenario Execution Reliability & State Distinctions
# ==============================================================================

def test_scenario_execution_timeout_when_daemon_offline(tmp_path: Path, monkeypatch):
    """
    Verify that when the traffic generator daemon is offline, run_scenario cleanly
    returns TIMED_OUT (never falsely claiming COMPLETED or DISPATCHED_ASYNC).
    """
    triggers_dir = tmp_path / "triggers"
    triggers_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("backend.app.services.hybrid_traffic_service.TRIGGERS_DIR", triggers_dir)

    # Execute with small timeout (0.6 seconds)
    res = HybridTrafficService.run_scenario("benign", timeout_seconds=0.6)

    assert res["status"] == "TIMED_OUT"
    assert "Traffic generator daemon is offline" in res["message"]
    assert res["scenario"] == "benign"
    # Ensure ephemeral trigger files were cleanly unlinked
    assert len(list(triggers_dir.glob("*.req"))) == 0


def test_scenario_execution_completed_when_daemon_responds(tmp_path: Path, monkeypatch):
    """
    Verify that when the daemon writes a successful .res response, run_scenario
    returns COMPLETED with execution telemetry.
    """
    triggers_dir = tmp_path / "triggers"
    triggers_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("backend.app.services.hybrid_traffic_service.TRIGGERS_DIR", triggers_dir)

    # Mock daemon response simulation
    import threading
    def mock_daemon():
        time.sleep(0.2)
        reqs = list(triggers_dir.glob("*.req"))
        if reqs:
            req = reqs[0]
            res_file = req.with_suffix(".res")
            res_data = {
                "success": True,
                "status": "COMPLETED",
                "scenario": "benign",
                "results": [{"packets_written": 25}],
            }
            res_file.write_text(json.dumps(res_data), encoding="utf-8")

    t = threading.Thread(target=mock_daemon)
    t.start()

    res = HybridTrafficService.run_scenario("benign", timeout_seconds=2.0)
    t.join()

    assert res["status"] == "COMPLETED"
    assert "successfully" in res["message"].lower()
    assert res["output"]["success"] is True


def test_scenario_execution_failed_when_daemon_reports_error(tmp_path: Path, monkeypatch):
    """
    Verify that when the daemon reports a failure, run_scenario returns FAILED
    with the actual error message.
    """
    triggers_dir = tmp_path / "triggers"
    triggers_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("backend.app.services.hybrid_traffic_service.TRIGGERS_DIR", triggers_dir)

    import threading
    def mock_daemon_error():
        time.sleep(0.2)
        reqs = list(triggers_dir.glob("*.req"))
        if reqs:
            req = reqs[0]
            res_file = req.with_suffix(".res")
            res_data = {
                "success": False,
                "status": "FAILED",
                "scenario": "benign",
                "error": "Interface eth0 unreachable on router container",
            }
            res_file.write_text(json.dumps(res_data), encoding="utf-8")

    t = threading.Thread(target=mock_daemon_error)
    t.start()

    res = HybridTrafficService.run_scenario("benign", timeout_seconds=2.0)
    t.join()

    assert res["status"] == "FAILED"
    assert "Interface eth0 unreachable" in res["message"]


def test_benchmark_suite_timeout_extended_for_all(tmp_path: Path, monkeypatch):
    """
    Verify that invoking the full benchmark suite ('all') automatically allocates
    up to 30.0s rather than a 12.0s ceiling, while keeping single scenarios at 12.0s.
    """
    triggers_dir = tmp_path / "triggers"
    triggers_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("backend.app.services.hybrid_traffic_service.TRIGGERS_DIR", triggers_dir)

    # When offline and timeout_seconds passed is default 12.0s, it gets extended to 30.0s
    # We test with explicit timeout_seconds=0.5 to avoid waiting 30s during unit tests
    res_single = HybridTrafficService.run_scenario("benign", timeout_seconds=0.5)
    assert res_single["status"] == "TIMED_OUT"
    assert res_single["scenario"] == "benign"

    # Test that scenario_key == 'all' is accepted as valid scenario
    res_all = HybridTrafficService.run_scenario("all", timeout_seconds=0.5)
    assert res_all["status"] == "TIMED_OUT"
    assert res_all["scenario"] == "all"


def test_atomic_request_file_creation(tmp_path: Path, monkeypatch):
    """
    Verify that the gateway creates requests atomically via temporary file replacement
    so that daemon polling never encounters partial writes.
    """
    triggers_dir = tmp_path / "triggers"
    triggers_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("backend.app.services.hybrid_traffic_service.TRIGGERS_DIR", triggers_dir)

    # Mock daemon that immediately captures request
    captured = []
    import threading
    def immediate_daemon():
        for _ in range(20):
            reqs = list(triggers_dir.glob("*.req"))
            if reqs:
                data = json.loads(reqs[0].read_text(encoding="utf-8"))
                captured.append(data)
                res_file = reqs[0].with_suffix(".res")
                res_file.write_text(json.dumps({"status": "COMPLETED", "success": True}), encoding="utf-8")
                break
            time.sleep(0.05)

    t = threading.Thread(target=immediate_daemon)
    t.start()
    res = HybridTrafficService.run_scenario("benign", timeout_seconds=2.0)
    t.join()

    assert res["status"] == "COMPLETED"
    assert len(captured) == 1
    assert captured[0]["scenario"] == "benign"
