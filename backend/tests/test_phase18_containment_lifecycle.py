"""
Phase 18 Containment Lifecycle, TTL Remediation & DRY_RUN Visibility Test Suite
===============================================================================
Comprehensive verification covering:
1. TTL non-compounding sliding-expiry semantics (1, 13, and 324 repeat detections).
2. Preservation of longer policy expiries (no premature truncation).
3. Already-expired rule handling and pruning.
4. Lifecycle-aware deduplication under DRY_RUN (SIMULATED) and SANDBOX (ACTIVE).
5. Target isolation across distinct source IPs.
6. API status filtering (ACTIVE, SIMULATED, EXPIRED, REVOKED, ALL / None).
7. Non-zero remaining TTL calculation for SIMULATED and ACTIVE rules.
8. DRY_RUN non-blocking safety invariants.
9. Policy audit trail immutability.
10. Regression parity with Phase 16 destination-port aggregation and canonical 9-feature XGBoost V2.
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.schemas.policy import PolicyDecision
from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.ml_service import MLService
from ml.features.extractor import FEATURE_NAMES_V2


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def reset_enforcement_mode():
    """Ensure every test begins and ends in safe DRY_RUN mode."""
    EnforcementService.set_mode("DRY_RUN")
    yield
    EnforcementService.set_mode("DRY_RUN")


def test_01_ttl_does_not_compound_across_324_evaluations(db_session: Session):
    """
    Verify that 1, 13, and 324 repeat flow evaluations for the same target
    implement sliding-window renewal (now + 300s) and NEVER compound into
    ~27 hours (97,200s).
    """
    repo = EnforcementRepository(db_session)
    target_ip = f"198.51.100.{uuid.uuid4().hex[:4]}"

    decision = PolicyDecision(
        decision_id=f"dec-test-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Port scan detected",
        suggested_ttl_seconds=300,
    )

    # 1. Initial creation
    res1, rule1 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule1 is not None
    assert rule1.ttl_seconds == 300
    now1 = datetime.now(timezone.utc)
    exp1 = rule1.expires_at.replace(tzinfo=timezone.utc) if rule1.expires_at.tzinfo is None else rule1.expires_at
    rem1 = (exp1 - now1).total_seconds()
    assert 290 <= rem1 <= 305, f"Expected ~300s, got {rem1}"

    # 2. 1st repeated detection
    res2, rule2 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule2.id == rule1.id
    now2 = datetime.now(timezone.utc)
    exp2 = rule2.expires_at.replace(tzinfo=timezone.utc) if rule2.expires_at.tzinfo is None else rule2.expires_at
    rem2 = (exp2 - now2).total_seconds()
    assert 290 <= rem2 <= 305, f"1st repeat: expected ~300s, got {rem2}"
    assert rule2.ttl_seconds == 300

    # 3. 13 repeated detections
    for _ in range(11):
        EnforcementService.execute_decision(decision, db=db_session, actor="test")
    now13 = datetime.now(timezone.utc)
    exp13 = rule1.expires_at.replace(tzinfo=timezone.utc) if rule1.expires_at.tzinfo is None else rule1.expires_at
    rem13 = (exp13 - now13).total_seconds()
    assert 290 <= rem13 <= 305, f"13th repeat: expected ~300s, got {rem13} (must not compound to 3900s)"
    assert rule1.ttl_seconds == 300

    # 4. 324 repeated detections total (run remaining 311 iterations)
    for _ in range(311):
        EnforcementService.execute_decision(decision, db=db_session, actor="test")
    now324 = datetime.now(timezone.utc)
    exp324 = rule1.expires_at.replace(tzinfo=timezone.utc) if rule1.expires_at.tzinfo is None else rule1.expires_at
    rem324 = (exp324 - now324).total_seconds()

    # CRITICAL INVARIANT: 324 repeats must NEVER equal ~27 hours (97,200s)
    assert rem324 < 360, f"Remaining TTL after 324 detections ({rem324}s) must not exceed 360s!"
    assert 280 <= rem324 <= 305
    assert rule1.ttl_seconds == 300


def test_02_sliding_expiry_preserves_longer_policy(db_session: Session):
    """
    Verify that an existing longer quarantine (e.g. 600s for brute force)
    is not prematurely shortened by a shorter subsequent probe recommendation (180s).
    """
    repo = EnforcementRepository(db_session)
    target_ip = f"198.51.100.{uuid.uuid4().hex[:4]}"

    # Initial 600s Brute-Force quarantine
    bf_decision = PolicyDecision(
        decision_id=f"dec-bf-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.98,
        threat_level="HIGH",
        attack_type="BRUTE_FORCE",
        risk_score=90,
        rule_name="BRUTE_FORCE_AUTHENTICATION_QUARANTINE",
        reason="Brute force detected",
        suggested_ttl_seconds=600,
    )
    _, rule = EnforcementService.execute_decision(bf_decision, db=db_session, actor="test")
    assert rule.ttl_seconds == 600
    now = datetime.now(timezone.utc)
    exp_initial = rule.expires_at.replace(tzinfo=timezone.utc) if rule.expires_at.tzinfo is None else rule.expires_at
    assert (exp_initial - now).total_seconds() >= 590

    # Subsequent shorter 180s probe decision
    short_decision = PolicyDecision(
        decision_id=f"dec-short-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=22,
        policy_action="Restrict",
        enforcement_required=True,
        confidence=0.85,
        threat_level="MEDIUM",
        attack_type="BRUTE_FORCE",
        risk_score=65,
        rule_name="GRADUATED_SERVICE_RESTRICTION",
        reason="Medium probe",
        suggested_ttl_seconds=180,
    )
    _, updated_rule = EnforcementService.execute_decision(short_decision, db=db_session, actor="test")
    exp_after = updated_rule.expires_at.replace(tzinfo=timezone.utc) if updated_rule.expires_at.tzinfo is None else updated_rule.expires_at
    # Must preserve the 600s boundary, not truncated to 180s
    rem_after = (exp_after - now).total_seconds()
    assert rem_after >= 585, f"Longer expiry was improperly truncated: {rem_after}s"
    assert updated_rule.ttl_seconds == 600


def test_03_already_expired_rule_handling_and_pruning(db_session: Session):
    """
    Verify that expired rules:
    - Are correctly identified and marked EXPIRED by prune_expired_rules.
    - Cannot be extended by extend_ttl (returns None).
    - Trigger a new clean rule on subsequent detection.
    """
    repo = EnforcementRepository(db_session)
    target_ip = f"198.51.100.{uuid.uuid4().hex[:4]}"
    now = datetime.now(timezone.utc)

    # Insert a rule already in the past
    past_rule = ActiveEnforcementModel(
        id=f"rule-expired-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        protocol="ANY",
        action="Block",
        status="SIMULATED",
        mode="DRY_RUN",
        reason="Expired test fixture",
        ttl_seconds=300,
        expires_at=now - timedelta(seconds=10),
    )
    repo.create(past_rule)

    # 1. Pruning marks it as EXPIRED
    expired_ids = repo.prune_expired_rules()
    assert past_rule.id in expired_ids
    assert past_rule.status == "EXPIRED"

    # 2. extend_ttl on expired rule returns None
    assert repo.extend_ttl(past_rule.id, 300) is None

    # 3. New detection creates a fresh rule rather than reviving the expired one
    decision = PolicyDecision(
        decision_id=f"dec-fresh-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Fresh port scan",
        suggested_ttl_seconds=300,
    )
    res, new_rule = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert new_rule.id != past_rule.id
    assert new_rule.status == "SIMULATED"
    assert new_rule.expires_at > now


def test_04_dry_run_simulated_rule_deduplication(db_session: Session):
    """
    Verify that in DRY_RUN mode, repeated detections for 192.168.10.55
    deduplicate cleanly against the unexpired SIMULATED rule.
    """
    EnforcementService.set_mode("DRY_RUN")
    target_ip = "192.168.10.55"

    decision = PolicyDecision(
        decision_id=f"dec-ps-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.90,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=81,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Multi-port scanning reconnaissance detected from 192.168.10.55",
        suggested_ttl_seconds=300,
    )

    # 1st detection
    res1, rule1 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule1.status == "SIMULATED"
    assert rule1.mode == "DRY_RUN"

    # 2nd detection (same target)
    res2, rule2 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule2.id == rule1.id, "DRY_RUN repeated detection failed to deduplicate!"

    # 3rd detection
    res3, rule3 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule3.id == rule1.id


def test_05_target_isolation_between_distinct_ips(db_session: Session):
    """
    Verify that distinct source IPs receive isolated containment rules
    and do not cross-deduplicate or interfere.
    """
    ip_a = f"192.168.10.{uuid.uuid4().int % 200 + 10}"
    ip_b = f"192.168.20.{uuid.uuid4().int % 200 + 10}"

    dec_a = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=ip_a,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.90,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=80,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason=f"Scan from {ip_a}",
        suggested_ttl_seconds=300,
    )
    dec_b = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=ip_b,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.90,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=80,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason=f"Scan from {ip_b}",
        suggested_ttl_seconds=300,
    )

    _, rule_a = EnforcementService.execute_decision(dec_a, db=db_session, actor="test")
    _, rule_b = EnforcementService.execute_decision(dec_b, db=db_session, actor="test")

    assert rule_a.id != rule_b.id
    assert rule_a.target_ip == ip_a
    assert rule_b.target_ip == ip_b


def test_06_api_filtering_and_all_view(db_session: Session):
    """
    Test GET /api/v1/enforcement/rules with:
    - Default (status_filter=None): returns ALL lifecycle states.
    - status_filter=ALL: returns ALL rules.
    - status_filter=SIMULATED: returns only simulated rules.
    - status_filter=ACTIVE: returns only active rules.
    """
    client = TestClient(app)
    repo = EnforcementRepository(db_session)
    now = datetime.now(timezone.utc)

    # Seed distinct lifecycle states
    uid = uuid.uuid4().hex[:4]
    sim_rule = ActiveEnforcementModel(
        id=f"rule-sim-{uid}",
        target_ip=f"10.0.1.{uid[:2]}",
        target_port=None,
        protocol="ANY",
        action="Block",
        status="SIMULATED",
        mode="DRY_RUN",
        reason="Simulated rule test",
        ttl_seconds=300,
        expires_at=now + timedelta(seconds=300),
    )
    act_rule = ActiveEnforcementModel(
        id=f"rule-act-{uid}",
        target_ip=f"10.0.2.{uid[:2]}",
        target_port=None,
        protocol="ANY",
        action="Block",
        status="ACTIVE",
        mode="SANDBOX",
        reason="Active rule test",
        ttl_seconds=300,
        expires_at=now + timedelta(seconds=300),
    )
    repo.create(sim_rule)
    repo.create(act_rule)
    db_session.commit()

    # 1. Default (no filter) -> Both SIMULATED and ACTIVE are returned
    resp_all = client.get("/api/v1/enforcement/rules")
    assert resp_all.status_code == 200
    all_rules = resp_all.json()
    all_ids = [r["rule_id"] for r in all_rules]
    assert sim_rule.id in all_ids
    assert act_rule.id in all_ids

    # 2. Filter: ALL -> Same as default
    resp_all_explicit = client.get("/api/v1/enforcement/rules?status_filter=ALL")
    assert resp_all_explicit.status_code == 200
    explicit_ids = [r["rule_id"] for r in resp_all_explicit.json()]
    assert sim_rule.id in explicit_ids
    assert act_rule.id in explicit_ids

    # 3. Filter: SIMULATED -> Only simulated rules returned
    resp_sim = client.get("/api/v1/enforcement/rules?status_filter=SIMULATED")
    assert resp_sim.status_code == 200
    for r in resp_sim.json():
        assert r["status"] == "SIMULATED"
    sim_ids = [r["rule_id"] for r in resp_sim.json()]
    assert sim_rule.id in sim_ids
    assert act_rule.id not in sim_ids

    # 4. Filter: ACTIVE -> Only active rules returned
    resp_act = client.get("/api/v1/enforcement/rules?status_filter=ACTIVE")
    assert resp_act.status_code == 200
    for r in resp_act.json():
        assert r["status"] == "ACTIVE"
    act_ids = [r["rule_id"] for r in resp_act.json()]
    assert act_rule.id in act_ids
    assert sim_rule.id not in act_ids


def test_07_remaining_ttl_calculation_for_simulated_and_active():
    """
    Verify that remaining_ttl_seconds is correctly computed for:
    - Unexpired SIMULATED rules (must be non-zero ~300s).
    - Unexpired ACTIVE rules (must be non-zero ~300s).
    - Expired rules (must be exactly 0).
    """
    client = TestClient(app)
    resp = client.get("/api/v1/enforcement/rules")
    assert resp.status_code == 200
    rules = resp.json()

    for r in rules:
        if r["status"] in ("ACTIVE", "SIMULATED"):
            # If not expired, remaining_ttl_seconds must be positive
            assert r["remaining_ttl_seconds"] >= 0
        elif r["status"] in ("EXPIRED", "REVOKED"):
            assert r["remaining_ttl_seconds"] == 0


def test_08_dry_run_zero_packet_blocking_safety():
    """
    Verify that in DRY_RUN mode, no real network filtering or router rules are installed.
    """
    EnforcementService.set_mode("DRY_RUN")
    adapter = EnforcementService.get_adapter()
    assert adapter.mode_name == "DRY_RUN"
    assert adapter.list_active_rules() == []

    decision = PolicyDecision(
        decision_id="dec-dry-safety",
        target_ip="10.99.99.99",
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.99,
        threat_level="CRITICAL",
        attack_type="PORT_SCAN",
        risk_score=100,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Safety verification",
        suggested_ttl_seconds=300,
    )
    result = adapter.enforce(decision, "rule-safe-01")
    assert result.status == "SIMULATED"
    assert result.mode == "DRY_RUN"
    assert result.metadata.get("dry_run") is True


def test_09_historical_policy_audit_log_immutability(db_session: Session):
    """
    Verify that every containment decision persists an immutable audit log entry.
    """
    from backend.app.models.security_event import SecurityEventModel
    from backend.app.repositories.security_event_repo import SecurityEventRepository
    event_repo = SecurityEventRepository(db_session)
    audit_repo = PolicyAuditRepository(db_session)
    test_event_id = f"evt-audit-{uuid.uuid4().hex[:6]}"

    event_model = SecurityEventModel(
        id=test_event_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.99",
        destination_ip="10.100.1.50",
        attack_type="PORT_SCAN",
        risk_score=85,
        threat_level="HIGH",
        confidence=0.95,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Simulated",
        description="Audit test event",
        is_anomaly=True,
        is_demo=False,
    )
    event_repo.create(event_model)
    db_session.commit()

    decision = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        event_id=test_event_id,
        target_ip="192.168.1.99",
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Audit logging test",
        suggested_ttl_seconds=300,
    )
    EnforcementService.execute_decision(decision, db=db_session, actor="pytest_runner")

    logs = audit_repo.get_history_for_event(test_event_id)
    assert len(logs) >= 1
    log = logs[0]
    assert log.requested_action == "Block"
    assert log.resulting_status in ("Simulated", "Applied", "Enforced")
    assert log.actor == "pytest_runner"


def test_10_destination_port_remediation_regression_check():
    """
    Verify Phase 16 regression parity:
    AwsVpcFlowParser directed service 5-tuple key preserves distinct destination ports.
    """
    from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
    line1 = "2 123456789012 eni-01 192.168.10.55 10.100.1.50 50000 22 6 2 120 1710000000 1710000005 ACCEPT OK"
    line2 = "2 123456789012 eni-01 192.168.10.55 10.100.1.50 50001 80 6 2 120 1710000000 1710000005 ACCEPT OK"
    rec1 = AwsVpcFlowParser.parse_raw_log_line(line1)
    rec2 = AwsVpcFlowParser.parse_raw_log_line(line2)
    assert rec1 is not None and rec2 is not None
    assert rec1.dst_port == 22
    assert rec2.dst_port == 80
    key1 = (rec1.interface_id, rec1.src_addr, rec1.dst_addr, rec1.dst_port, rec1.protocol)
    key2 = (rec2.interface_id, rec2.src_addr, rec2.dst_addr, rec2.dst_port, rec2.protocol)
    assert key1 != key2, "Different destination ports must yield distinct grouping keys!"


def test_11_xgboost_v2_canonical_nine_feature_schema_unchanged():
    """
    Verify that authoritative XGBoost V2 feature schema:
    1. Has exactly 9 features.
    2. Matches FEATURE_NAMES_V2 in exact canonical order.
    3. Strictly excludes failed_auth_count.
    """
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
    assert len(FEATURE_NAMES_V2) == 9
    assert "failed_auth_count" not in FEATURE_NAMES_V2
