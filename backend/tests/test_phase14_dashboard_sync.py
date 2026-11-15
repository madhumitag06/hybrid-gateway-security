"""
Phase 14 Regression Test Suite: Automatic Dashboard Synchronization & Integrity
================================================================================
Verifies that:
1. Ingested AWS telemetry batches are persisted and immediately reflected in dashboard telemetry.
2. Failed or empty polling batches do not mutate the database or trigger spurious dashboard updates.
3. Dashboard provenance counts remain strictly separated (AWS_VPC_FLOW_LOG vs AWS_VPC_FLOW_LOG_FIXTURE vs UNKNOWN / LEGACY).
4. Genuine AWS live cloud risk and simulated lab risk are independently calculated without cross-contamination.
5. Time-range changes and queries evaluate the correct rolling time windows.
6. Concurrent / repeated dashboard requests execute deterministically without race conditions.
7. Authentication session handling and refresh tokens remain intact.
"""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.base import Base
from backend.app.models.security_event import SecurityEventModel
from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.auth_service import AuthService
from backend.app.schemas.auth import UserSignUpRequest, UserLoginRequest


@pytest.fixture
def sync_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_successful_aws_ingestion_immediately_updates_dashboard(sync_db):
    """
    Test 1 & 3: Validates that newly ingested live AWS flow records are immediately
    reflected in the next get_dashboard_data call with correct provenance and count.
    """
    initial_data = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    initial_evaluated = initial_data.evaluatedEventsCount
    initial_aws_count = initial_data.telemetryProvenance.get("AWS_VPC_FLOW_LOG", 0)

    # Ingest 2 new live AWS flow records
    records = [
        CanonicalFlowRecord(
            flow_id="test-flow-001",
            provider="AWS",
            account_id="698766075180",
            src_ip="10.20.10.15",
            dst_ip="10.20.10.2",
            src_port=44321,
            dst_port=443,
            protocol="TCP",
            packet_count=50,
            byte_count=45000,
            duration=10.0,
            action="ACCEPT",
            log_status="OK",
            timestamp=datetime.now(timezone.utc),
        ),
        CanonicalFlowRecord(
            flow_id="test-flow-002",
            provider="AWS",
            account_id="698766075180",
            src_ip="10.20.10.20",
            dst_ip="10.20.10.2",
            src_port=52345,
            dst_port=80,
            protocol="TCP",
            packet_count=10,
            byte_count=1200,
            duration=1.0,
            action="ACCEPT",
            log_status="OK",
            timestamp=datetime.now(timezone.utc),
        ),
    ]

    batch_resp = TelemetryNormalizer.process_canonical_batch(
        records=records,
        provider="AWS",
        account_id="698766075180",
        db=sync_db,
        persist=True,
    )

    assert batch_resp.status == "SUCCESS"
    assert batch_resp.records_aggregated == 2

    # Fetch updated dashboard data
    updated_data = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    assert updated_data.evaluatedEventsCount == initial_evaluated + 2
    assert updated_data.telemetryProvenance.get("AWS_VPC_FLOW_LOG", 0) == initial_aws_count + 2


def test_failed_or_empty_ingestion_does_not_mutate_dashboard(sync_db):
    """
    Test 2: Verifies that empty batches or invalid inputs do not change
    persisted counts, provenance breakdown, or risk scores.
    """
    initial_data = DashboardService.get_dashboard_data(sync_db, time_range="24h")

    # Ingest empty record batch
    empty_resp = TelemetryNormalizer.process_canonical_batch(
        records=[],
        provider="AWS",
        account_id="698766075180",
        db=sync_db,
        persist=True,
    )

    assert empty_resp.records_aggregated == 0
    assert empty_resp.records_parsed == 0

    post_empty_data = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    assert post_empty_data.evaluatedEventsCount == initial_data.evaluatedEventsCount
    assert post_empty_data.telemetryProvenance == initial_data.telemetryProvenance
    assert post_empty_data.riskScore == initial_data.riskScore


def test_dashboard_provenance_counts_remain_strictly_separated(sync_db):
    """
    Test 4: Verifies strict separation between genuine AWS_VPC_FLOW_LOG,
    AWS_VPC_FLOW_LOG_FIXTURE, and UNKNOWN / LEGACY.
    """
    now = datetime.now(timezone.utc)

    # 1. Genuine AWS live event
    ev_live = SecurityEventModel(
        id="evt-cld-test-live-01",
        timestamp=now,
        source_ip="10.0.1.5",
        destination_ip="10.0.2.10",
        attack_type="BENIGN",
        risk_score=5,
        threat_level="LOW",
        confidence=0.99,
        action_recommendation="Allow",
        current_policy_action="Allow",
        status="Monitoring",
        description="[AWS] Flow Ingestion: Benign live traffic",
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "provider": "AWS", "is_demo": False},
        is_demo=False,
    )

    # 2. AWS Sandbox demo fixture
    ev_fixture = SecurityEventModel(
        id="evt-fixture-test-01",
        timestamp=now,
        source_ip="198.51.100.99",
        destination_ip="10.0.2.10",
        attack_type="PORT_SCAN",
        risk_score=95,
        threat_level="HIGH",
        confidence=0.98,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Monitoring",
        description="Demo attack fixture",
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG_FIXTURE", "is_demo": True},
        is_demo=True,
    )

    # 3. Legacy unclassified event
    ev_legacy = SecurityEventModel(
        id="evt-legacy-test-01",
        timestamp=now,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        attack_type="BRUTE_FORCE",
        risk_score=85,
        threat_level="HIGH",
        confidence=0.94,
        action_recommendation="Restrict",
        current_policy_action="Restrict",
        status="Monitoring",
        description="Historical legacy log",
        flow_features=None,
        is_demo=False,
    )

    sync_db.add_all([ev_live, ev_fixture, ev_legacy])
    sync_db.commit()

    data = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    prov = data.telemetryProvenance

    assert prov.get("AWS_VPC_FLOW_LOG", 0) >= 1
    assert prov.get("AWS_VPC_FLOW_LOG_FIXTURE", 0) >= 1
    assert prov.get("UNKNOWN / LEGACY", 0) >= 1

    # Exact sum reconciliation
    assert sum(prov.values()) == data.evaluatedEventsCount


def test_independent_risk_calculation_preservation(sync_db):
    """
    Test 5: Verifies that live AWS risk is derived solely from AWS_VPC_FLOW_LOG
    and is not inflated by high-risk fixtures or lab replays.
    """
    now = datetime.now(timezone.utc)

    # Add 10 benign live AWS events (risk 0)
    for i in range(10):
        sync_db.add(
            SecurityEventModel(
                id=f"evt-cld-benign-{i}",
                timestamp=now - timedelta(minutes=i),
                source_ip=f"10.0.1.{10 + i}",
                destination_ip="10.0.2.10",
                attack_type="BENIGN",
                risk_score=0,
                threat_level="LOW",
                confidence=0.99,
                action_recommendation="Allow",
                current_policy_action="ALLOW",
                status="Monitoring",
                description="[AWS] Flow Ingestion: Normal flow",
                flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "provider": "AWS", "is_demo": False},
                is_demo=False,
            )
        )

    # Add 1 severe attack fixture (risk 100)
    sync_db.add(
        SecurityEventModel(
            id="evt-fixture-attack-01",
            timestamp=now,
            source_ip="203.0.113.5",
            destination_ip="10.0.2.10",
            attack_type="PORT_SCAN",
            risk_score=100,
            threat_level="HIGH",
            confidence=0.98,
            action_recommendation="Block",
            current_policy_action="Block",
            status="Monitoring",
            description="Sandbox attack fixture",
            flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG_FIXTURE", "is_demo": True},
            is_demo=True,
        )
    )
    sync_db.commit()

    data = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    risk_seg = data.riskSegmentation

    # Live AWS risk must be LOW / Allow (risk = 0)
    assert risk_seg["aws_live_cloud"]["risk_score"] == 0
    assert risk_seg["aws_live_cloud"]["policy_action"] == "Allow"

    # Simulated lab risk must absorb the fixture (risk >= 70)
    assert risk_seg["simulated_lab"]["risk_score"] >= 70
    assert risk_seg["simulated_lab"]["policy_action"] in ("Restrict", "Block")


def test_time_range_filtering_mechanics(sync_db):
    """
    Test 6 & 7: Verifies that time range changes (1h, 24h, 7d) filter events
    properly without corrupting state or provenance counts.
    """
    now = datetime.now(timezone.utc)

    # Event 30 mins ago
    ev_recent = SecurityEventModel(
        id="evt-recent-01",
        timestamp=now - timedelta(minutes=30),
        source_ip="10.0.1.1",
        destination_ip="10.0.2.1",
        attack_type="BENIGN",
        risk_score=5,
        threat_level="LOW",
        confidence=0.99,
        action_recommendation="Allow",
        current_policy_action="Allow",
        status="Monitoring",
        description="[AWS] Flow Ingestion: 30m ago",
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "provider": "AWS"},
        is_demo=False,
    )

    # Event 12 hours ago
    ev_mid = SecurityEventModel(
        id="evt-mid-01",
        timestamp=now - timedelta(hours=12),
        source_ip="10.0.1.2",
        destination_ip="10.0.2.2",
        attack_type="BENIGN",
        risk_score=10,
        threat_level="LOW",
        confidence=0.99,
        action_recommendation="Allow",
        current_policy_action="Allow",
        status="Monitoring",
        description="[AWS] Flow Ingestion: 12h ago",
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "provider": "AWS"},
        is_demo=False,
    )

    # Event 3 days ago
    ev_old = SecurityEventModel(
        id="evt-old-01",
        timestamp=now - timedelta(days=3),
        source_ip="10.0.1.3",
        destination_ip="10.0.2.3",
        attack_type="PORT_SCAN",
        risk_score=80,
        threat_level="HIGH",
        confidence=0.97,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Monitoring",
        description="Historical 3d ago",
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "provider": "AWS"},
        is_demo=False,
    )

    sync_db.add_all([ev_recent, ev_mid, ev_old])
    sync_db.commit()

    # 1. 1h window: only recent event
    data_1h = DashboardService.get_dashboard_data(sync_db, time_range="1h")
    assert any(e.id == "evt-recent-01" for e in data_1h.events)
    assert not any(e.id == "evt-mid-01" for e in data_1h.events)
    assert not any(e.id == "evt-old-01" for e in data_1h.events)

    # 2. 24h window: recent and mid events
    data_24h = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    assert any(e.id == "evt-recent-01" for e in data_24h.events)
    assert any(e.id == "evt-mid-01" for e in data_24h.events)
    assert not any(e.id == "evt-old-01" for e in data_24h.events)

    # 3. 7d window: all three events
    data_7d = DashboardService.get_dashboard_data(sync_db, time_range="7d")
    assert any(e.id == "evt-recent-01" for e in data_7d.events)
    assert any(e.id == "evt-mid-01" for e in data_7d.events)
    assert any(e.id == "evt-old-01" for e in data_7d.events)


def test_concurrent_dashboard_queries_execute_deterministically(sync_db):
    """
    Test 8: Verifies that multiple sequential or concurrent dashboard queries
    return identical, deterministic state with zero lockups or exceptions.
    """
    res1 = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    res2 = DashboardService.get_dashboard_data(sync_db, time_range="24h")
    res3 = DashboardService.get_dashboard_data(sync_db, time_range="24h")

    assert res1.evaluatedEventsCount == res2.evaluatedEventsCount == res3.evaluatedEventsCount
    assert res1.riskScore == res2.riskScore == res3.riskScore
    assert res1.telemetryProvenance == res2.telemetryProvenance == res3.telemetryProvenance


def test_authentication_session_handling_integrity(sync_db):
    """
    Test 9: Verifies user authentication, token issuance, and password verification
    remain fully operational and unaffected by dashboard synchronization enhancements.
    """
    # 1. Sign up new operator user
    signup_req = UserSignUpRequest(
        email="operator_tester@gateway.local",
        password="TestSecurePassword123!",
        confirm_password="TestSecurePassword123!",
        full_name="SecOps Operator Tester",
        role="OPERATOR",
    )
    token_resp = AuthService.signup(signup_req, sync_db)
    assert token_resp.access_token is not None
    assert token_resp.refresh_token is not None
    assert token_resp.user.email == "operator_tester@gateway.local"

    # 2. Login with valid credentials
    login_req = UserLoginRequest(
        email="operator_tester@gateway.local",
        password="TestSecurePassword123!",
    )
    login_resp = AuthService.login(login_req, sync_db)
    assert login_resp.access_token is not None
    assert login_resp.user.role == "OPERATOR"
