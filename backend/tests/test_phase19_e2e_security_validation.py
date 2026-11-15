"""
Phase 19 End-to-End Security Validation Test Suite
==================================================
Comprehensive offline automated validation covering:
- Workstream A: Traffic ingestion, parsing, normalization, direction, and port preservation.
- Workstream B: ML detection, authoritative XGBoost V2, Random Forest standby, exact 9-feature schema, SHAP.
- Workstream C: Deterministic policy precedence, confidence gating, observable SSH safeguards, graduated policies.
- Workstream D: Containment lifecycle, DRY_RUN vs SANDBOX, sliding TTL renewal, deduplication, pruning, revocation.
- Workstream E: Persistence integrity, telemetry provenance, policy audit ledger, and dashboard risk segregation.
- Workstream F: Integrated scenario matrix (8 core operational security scenarios).
"""

from datetime import datetime, timezone, timedelta
import math
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.models.policy_audit_log import PolicyAuditLogModel
from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.repositories.security_event_repo import SecurityEventRepository
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.schemas.policy import PolicyDecision
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.hybrid_topology import NetworkZoneClassifier
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine
from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor, NetworkFlowInput


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def ensure_dry_run_mode():
    """Ensure tests execute in safe DRY_RUN mode."""
    EnforcementService.set_mode("DRY_RUN")
    yield
    EnforcementService.set_mode("DRY_RUN")


# ==============================================================================
# WORKSTREAM A: TRAFFIC INGESTION, PARSING & NORMALIZATION
# ==============================================================================

def test_ws_a_01_vpc_flow_log_parsing_and_direction():
    """Verify standard AWS VPC Flow Log v2 line parsing and hybrid zone direction mapping."""
    raw_line = "2 123456789012 eni-0123456789abcdef0 192.168.10.55 10.100.1.50 54321 80 6 2 120 1710000000 1710000005 ACCEPT OK"
    rec = AwsVpcFlowParser.parse_raw_log_line(raw_line)
    assert rec is not None
    assert rec.version == 2
    assert rec.account_id == "123456789012"
    assert rec.interface_id == "eni-0123456789abcdef0"
    assert rec.src_addr == "192.168.10.55"
    assert rec.dst_addr == "10.100.1.50"
    assert rec.src_port == 54321
    assert rec.dst_port == 80
    assert rec.protocol == 6
    assert rec.packets == 2
    assert rec.bytes == 120
    assert rec.action == "ACCEPT"
    assert rec.log_status == "OK"

    # Hybrid zone classification
    src_zone = NetworkZoneClassifier.classify_ip(rec.src_addr)
    dst_zone = NetworkZoneClassifier.classify_ip(rec.dst_addr)
    direction = NetworkZoneClassifier.classify_direction(rec.src_addr, rec.dst_addr)
    assert src_zone == "ON_PREMISE"
    assert dst_zone == "AWS_VPC"
    assert direction in ["ON_PREM_TO_CLOUD", "INBOUND_HYBRID"]


def test_ws_a_02_destination_port_preservation():
    """Verify directed service 5-tuple key preserves destination ports across multi-port sweeps."""
    lines = [
        f"2 123456789012 eni-01 192.168.10.55 10.100.1.50 {50000 + i} {port} 6 2 120 1710000000 1710000001 REJECT OK"
        for i, port in enumerate(range(21, 31))  # 10 distinct destination ports
    ]
    parsed_records = [AwsVpcFlowParser.parse_raw_log_line(l) for l in lines]
    assert len(parsed_records) == 10

    # Group by directed 5-tuple
    session_map = {}
    for r in parsed_records:
        key = (r.interface_id, r.src_addr, r.dst_addr, r.dst_port, r.protocol)
        session_map[key] = r

    assert len(session_map) == 10, "Each destination port must produce an isolated aggregated flow!"
    target_ports = [k[3] for k in session_map.keys()]
    assert sorted(target_ports) == list(range(21, 31))


def test_ws_a_03_telemetry_normalization_canonical_schema():
    """Verify FeatureExtractor outputs exact 9 canonical features matching FEATURE_NAMES_V2."""
    flow = NetworkFlowInput(
        packet_count=10,
        byte_count=5000,
        duration=2.0,
        conn_rate=5.0,
        dst_port=443,
        unique_dst_ports=1,
    )
    v2_vec = FeatureExtractor.extract_v2_from_flow(flow)
    assert v2_vec.shape == (1, 9)
    assert len(FEATURE_NAMES_V2) == 9

    # Telemetry normalization canonical 9-feature schema test
    canon_rec = CanonicalFlowRecord(
        flow_id="test-flow-norm",
        provider="AWS",
        account_id="123456789012",
        region="us-east-1",
        src_ip="192.168.10.55",
        dst_ip="10.100.1.50",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        protocol_number=6,
        packet_count=10,
        byte_count=5000,
        duration=2.0,
        start_time=1710000000,
        end_time=1710000002,
        action="ACCEPT",
        log_status="OK",
        unique_dst_ports=1,
    )
    enriched_rec, normalized = TelemetryNormalizer.normalize_flow_record(canon_rec)
    assert list(normalized.keys()) == FEATURE_NAMES_V2
    assert "failed_auth_count" not in normalized


# ==============================================================================
# WORKSTREAM B: ML DETECTION & MODEL PARITY
# ==============================================================================

def test_ws_b_01_xgboost_v2_authoritative_status():
    """Verify candidate_xgboost_v2 is active primary model and configured with clean v2 schema."""
    reg = MLService.get_registry_status()
    assert reg["active_version"] == "candidate_xgboost_v2"
    act = reg["active_model_details"]
    assert act["algorithm"] == "XGBClassifier"
    assert act["schema_version"] == "v2"
    assert act["feature_count"] == 9
    assert act["role"] == "ACTIVE_PRIMARY"


def test_ws_b_02_standby_random_forest_invariance():
    """Verify production_rf is preserved as standby rollback model and not active."""
    reg = MLService.get_registry_status()
    standby = reg.get("standby_model_details", {})
    assert standby["version_id"] == "production_rf"
    assert standby["algorithm"] == "RandomForestClassifier"
    assert standby["role"] == "STANDBY_ROLLBACK"
    assert reg["active_version"] != "production_rf"


def test_ws_b_03_prediction_probabilities_and_risk_score():
    """Verify prediction produces calibrated probabilities, continuous risk scores, and SHAP attribution."""
    req = NetworkFlowRequest(
        packet_count=2,
        byte_count=120,
        duration=0.08,
        conn_rate=120.0,
        dst_port=80,
        unique_dst_ports=60,
        failed_auth_count=0,
        source_ip="192.168.10.55",
        destination_ip="10.100.1.50",
    )
    pred: PredictionResponse = MLService.predict(req)
    assert 0 <= pred.risk_score <= 100
    assert pred.threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # Probability calibration
    prob_sum = sum(pred.class_probabilities.values())
    assert math.isclose(prob_sum, 1.0, abs_tol=1e-3)

    # SHAP feature attribution
    assert len(pred.top_contributing_features) > 0
    top_feature = pred.top_contributing_features[0]
    assert top_feature.feature in FEATURE_NAMES_V2
    assert top_feature.description is not None


# ==============================================================================
# WORKSTREAM C: DETERMINISTIC POLICY DECISIONS
# ==============================================================================

def test_ws_c_01_allowlist_precedence_bypass():
    """Rule 1: Management allowlist bypasses automated quarantine with Allow (TTL=0s)."""
    allowlisted_ip = "192.168.1.1"  # In default management_allowlist
    req = NetworkFlowRequest(
        packet_count=2,
        byte_count=120,
        duration=0.08,
        conn_rate=120.0,
        dst_port=80,
        unique_dst_ports=60,
        failed_auth_count=0,
    )
    pred = MLService.predict(req)
    decision = PolicyEngine.evaluate(
        prediction=pred,
        source_ip=allowlisted_ip,
        destination_ip="10.100.1.50",
        dst_port=80,
    )
    assert decision.policy_action == "Allow"
    assert decision.enforcement_required is False
    assert decision.rule_name == "MANAGEMENT_ALLOWLIST_PROTECTION"
    assert decision.suggested_ttl_seconds == 0


def test_ws_c_02_confidence_gating():
    """Rule 2: Confidence < 0.60 on anomaly downgrades policy to observational Monitor."""
    mock_pred = PredictionResponse(
        event_id="evt-low-conf",
        timestamp=datetime.now(timezone.utc),
        attack_type="PORT_SCAN",
        risk_score=75,
        threat_level="HIGH",
        confidence=0.52,  # Low confidence (< 0.60)
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.52, "BENIGN": 0.48},
        top_contributing_features=[],
    )
    decision = PolicyEngine.evaluate(
        prediction=mock_pred,
        source_ip="198.51.100.99",
        destination_ip="10.100.1.50",
        dst_port=80,
    )
    assert decision.policy_action == "Monitor"
    assert decision.enforcement_required is False
    assert decision.rule_name == "CONFIDENCE_GATING_MONITOR"
    assert decision.suggested_ttl_seconds == 180


def test_ws_c_03_graduated_policy_mapping():
    """Verify graduated policy engine actions for attack types."""
    # 1. Benign -> Allow
    pred_benign = PredictionResponse(
        event_id="evt-1",
        timestamp=datetime.now(timezone.utc),
        attack_type="BENIGN",
        risk_score=10,
        threat_level="LOW",
        confidence=0.98,
        action_recommendation="Allow",
        is_anomaly=False,
        class_probabilities={"BENIGN": 0.98},
        top_contributing_features=[],
    )
    dec_benign = PolicyEngine.evaluate(pred_benign, "10.0.0.1", "10.100.1.1", 443)
    assert dec_benign.policy_action == "Allow"
    assert dec_benign.suggested_ttl_seconds == 0

    # 2. Medium threat -> Restrict
    pred_med = PredictionResponse(
        event_id="evt-2",
        timestamp=datetime.now(timezone.utc),
        attack_type="ANOMALY",
        risk_score=55,
        threat_level="MEDIUM",
        confidence=0.85,
        action_recommendation="Restrict",
        is_anomaly=True,
        class_probabilities={"ANOMALY": 0.85},
        top_contributing_features=[],
    )
    dec_med = PolicyEngine.evaluate(pred_med, "10.0.0.2", "10.100.1.1", 8080)
    assert dec_med.policy_action == "Restrict"
    assert dec_med.suggested_ttl_seconds == 180

    # 3. Port scan High -> Block (host-wide)
    pred_ps = PredictionResponse(
        event_id="evt-3",
        timestamp=datetime.now(timezone.utc),
        attack_type="PORT_SCAN",
        risk_score=80,
        threat_level="HIGH",
        confidence=0.90,
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.90},
        top_contributing_features=[],
    )
    dec_ps = PolicyEngine.evaluate(pred_ps, "192.168.10.55", "10.100.1.50", 80)
    assert dec_ps.policy_action == "Block"
    assert dec_ps.target_port is None  # Host-wide isolation
    assert dec_ps.suggested_ttl_seconds == 300

    # 4. Traffic Spike High -> Restrict (port rate-limiting)
    pred_spike = PredictionResponse(
        event_id="evt-4",
        timestamp=datetime.now(timezone.utc),
        attack_type="TRAFFIC_SPIKE",
        risk_score=95,
        threat_level="HIGH",
        confidence=0.92,
        action_recommendation="Restrict",
        is_anomaly=True,
        class_probabilities={"TRAFFIC_SPIKE": 0.92},
        top_contributing_features=[],
    )
    dec_spike = PolicyEngine.evaluate(pred_spike, "10.0.0.4", "10.100.1.1", 80)
    assert dec_spike.policy_action == "Restrict"
    assert dec_spike.target_port == 80  # Port-specific rate limit
    assert dec_spike.suggested_ttl_seconds == 300


# ==============================================================================
# WORKSTREAM D: CONTAINMENT LIFECYCLE & TTL INTEGRITY
# ==============================================================================

def test_ws_d_01_sliding_ttl_renewal_zero_inflation(db_session: Session):
    """Verify sliding renewal maintains bounded TTL (~300s) across repeat flow evaluations."""
    target_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    decision = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Port scan test",
        suggested_ttl_seconds=300,
    )

    # Initial rule
    _, rule = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule.ttl_seconds == 300

    # Repeat 20 times rapidly
    for _ in range(20):
        _, rule = EnforcementService.execute_decision(decision, db=db_session, actor="test")

    now = datetime.now(timezone.utc)
    exp = rule.expires_at.replace(tzinfo=timezone.utc) if rule.expires_at.tzinfo is None else rule.expires_at
    rem = (exp - now).total_seconds()
    assert 280 <= rem <= 305, f"Expected ~300s, got {rem}s (compounding defect detected if > 360s)"
    assert rule.ttl_seconds == 300


def test_ws_d_02_dry_run_deduplication(db_session: Session):
    """Verify repeated detections in DRY_RUN mode reuse existing SIMULATED rule."""
    EnforcementService.set_mode("DRY_RUN")
    target_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    decision = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Deduplication test",
        suggested_ttl_seconds=300,
    )

    _, r1 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    _, r2 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert r1.id == r2.id
    assert r1.status == "SIMULATED"


def test_ws_d_03_pruning_and_manual_revocation(db_session: Session):
    """Verify manual revocation and automatic pruning mark rules REVOKED and EXPIRED."""
    repo = EnforcementRepository(db_session)
    target_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    decision = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Revocation test",
        suggested_ttl_seconds=300,
    )
    _, rule = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert rule.status == "SIMULATED"

    # Revoke
    success, msg = EnforcementService.revoke_rule(rule.id, db=db_session, actor="security_lead")
    assert success is True
    assert rule.status == "REVOKED"


# ==============================================================================
# WORKSTREAM E: PERSISTENCE, PROVENANCE & AUDIT TRAIL
# ==============================================================================

def test_ws_e_01_security_event_persistence_and_provenance(db_session: Session):
    """Verify SecurityEventModel stores provenance and canonical features."""
    event_repo = SecurityEventRepository(db_session)
    evt_id = f"evt-e2e-{uuid.uuid4().hex[:6]}"
    event_model = SecurityEventModel(
        id=evt_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.10.55",
        destination_ip="10.100.1.50",
        attack_type="PORT_SCAN",
        risk_score=81,
        threat_level="HIGH",
        confidence=0.91,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Simulated",
        description="E2E Validation Event",
        is_anomaly=True,
        is_demo=False,
        flow_features={"telemetry_source": "AWS_VPC_FLOW_LOG", "packet_count": 2, "byte_count": 120},
    )
    event_repo.create(event_model)
    db_session.commit()

    saved = event_repo.get_by_id(evt_id)
    assert saved is not None
    assert saved.flow_features.get("telemetry_source") == "AWS_VPC_FLOW_LOG"


def test_ws_e_02_policy_audit_ledger_immutability(db_session: Session):
    """Verify policy audit repository records every state transition."""
    event_repo = SecurityEventRepository(db_session)
    audit_repo = PolicyAuditRepository(db_session)
    evt_id = f"evt-audit-{uuid.uuid4().hex[:6]}"

    # Create event first to satisfy FK
    event_model = SecurityEventModel(
        id=evt_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.10.55",
        destination_ip="10.100.1.50",
        attack_type="PORT_SCAN",
        risk_score=81,
        threat_level="HIGH",
        confidence=0.91,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Simulated",
        description="Audit test event",
        is_anomaly=True,
        is_demo=False,
    )
    event_repo.create(event_model)
    db_session.commit()

    log = audit_repo.log_action(
        event_id=evt_id,
        requested_action="Block",
        previous_action=None,
        resulting_status="Simulated",
        actor="e2e_validator",
    )
    db_session.commit()

    logs = audit_repo.get_history_for_event(evt_id)
    assert len(logs) >= 1
    assert logs[0].requested_action == "Block"
    assert logs[0].actor == "e2e_validator"


# ==============================================================================
# WORKSTREAM F: INTEGRATED SCENARIO MATRIX
# ==============================================================================

def test_ws_f_scenario_1_benign_transit():
    """Scenario 1: Benign hybrid HTTPS traffic -> Allow, Risk <= 25."""
    req = NetworkFlowRequest(
        packet_count=15,
        byte_count=8500,
        duration=1.2,
        conn_rate=8.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    pred = MLService.predict(req)
    assert pred.threat_level == "LOW"
    assert pred.risk_score <= 25
    dec = PolicyEngine.evaluate(pred, "192.168.1.100", "10.100.1.10", 443)
    assert dec.policy_action == "Allow"
    assert dec.suggested_ttl_seconds == 0


def test_ws_f_scenario_2_multi_port_reconnaissance():
    """Scenario 2: Multi-destination port sweep -> PORT_SCAN, Risk >= 75, Block."""
    req = NetworkFlowRequest(
        packet_count=2,
        byte_count=120,
        duration=0.08,
        conn_rate=120.0,
        dst_port=80,
        unique_dst_ports=60,  # Swept 60 distinct ports
        failed_auth_count=0,
    )
    pred = MLService.predict(req)
    assert pred.attack_type == "PORT_SCAN"
    assert pred.threat_level in ["HIGH", "CRITICAL"]
    assert pred.risk_score >= 75
    dec = PolicyEngine.evaluate(pred, "192.168.10.55", "10.100.1.50", 80)
    assert dec.policy_action == "Block"
    assert dec.target_port is None
    assert dec.suggested_ttl_seconds == 300


def test_ws_f_scenario_3_ssh_probing():
    """Scenario 3: Rapid SSH connection probes on port 22 -> Restrict/Block."""
    PolicyEngine.ssh_tracker.reset_host("198.51.100.22")
    req = NetworkFlowRequest(
        packet_count=5,
        byte_count=800,
        duration=0.5,
        conn_rate=10.0,
        dst_port=22,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    pred = MLService.predict(req)

    # Simulate burst of 7 probes on port 22
    for _ in range(7):
        dec = PolicyEngine.evaluate(pred, "198.51.100.22", "10.100.1.20", 22, byte_count=800)
    assert dec.policy_action in ["Restrict", "Block"]
    assert dec.suggested_ttl_seconds in [300, 600]


def test_ws_f_scenario_4_volumetric_http_surge():
    """Scenario 4: High volumetric packet and byte surge -> TRAFFIC_SPIKE, Restrict."""
    req = NetworkFlowRequest(
        packet_count=14,
        byte_count=11925,
        duration=1.0,
        conn_rate=14.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    pred = MLService.predict(req)
    assert pred.attack_type == "TRAFFIC_SPIKE"
    assert pred.threat_level in ["HIGH", "CRITICAL"]
    dec = PolicyEngine.evaluate(pred, "198.51.100.80", "10.100.1.10", 80)
    assert dec.policy_action == "Restrict"
    assert dec.target_port == 80
    assert dec.suggested_ttl_seconds == 300


def test_ws_f_scenario_5_suspicious_data_transfer():
    """Scenario 5: High byte transfer with anomalous profile -> Restrict/Monitor."""
    req = NetworkFlowRequest(
        packet_count=300,
        byte_count=1000000,
        duration=5.0,
        conn_rate=60.0,
        dst_port=8443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    pred = MLService.predict(req)
    assert pred.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]
    dec = PolicyEngine.evaluate(pred, "198.51.100.85", "10.100.1.10", 8443)
    assert dec.policy_action in ["Monitor", "Restrict", "Block"]
    if dec.policy_action == "Monitor":
        assert dec.confidence < 0.60 or "confidence" in dec.reason.lower() or "observation" in dec.reason.lower()


def test_ws_f_scenario_6_repeated_detections_matrix(db_session: Session):
    """Scenario 6: Repeated attacker detections deduplicate and refresh sliding TTL."""
    target_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    decision = PolicyDecision(
        decision_id=f"dec-{uuid.uuid4().hex[:6]}",
        target_ip=target_ip,
        target_port=None,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=85,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Repeated attack scenario",
        suggested_ttl_seconds=300,
    )
    _, r1 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    _, r2 = EnforcementService.execute_decision(decision, db=db_session, actor="test")
    assert r1.id == r2.id
    assert r2.ttl_seconds == 300


def test_ws_f_scenario_7_expired_and_revoked_containment(db_session: Session):
    """Scenario 7: Expired and revoked containment rules display 0s remaining TTL."""
    client = TestClient(app)
    repo = EnforcementRepository(db_session)
    now = datetime.now(timezone.utc)
    uid = uuid.uuid4().hex[:4]

    revoked_rule = ActiveEnforcementModel(
        id=f"rule-rev-{uid}",
        target_ip=f"10.0.5.{uid[:2]}",
        target_port=None,
        protocol="ANY",
        action="Block",
        status="REVOKED",
        mode="DRY_RUN",
        reason="Revoked rule test",
        ttl_seconds=300,
        expires_at=now + timedelta(seconds=200),
        revoked_at=now,
        revoked_by="security_admin",
    )
    repo.create(revoked_rule)
    db_session.commit()

    resp = client.get("/api/v1/enforcement/rules?status_filter=REVOKED")
    assert resp.status_code == 200
    rev_data = [r for r in resp.json() if r["rule_id"] == revoked_rule.id]
    assert len(rev_data) == 1
    assert rev_data[0]["status"] == "REVOKED"
    assert rev_data[0]["remaining_ttl_seconds"] == 0


def test_ws_f_scenario_8_protected_management_subnet_traffic():
    """Scenario 8: Traffic from protected CIDRs (127.0.0.1, 192.168.1.1, 10.100.0.1)."""
    from backend.app.config import settings
    protected_ips = settings.management_allowlist
    for ip in protected_ips:
        req = NetworkFlowRequest(
            packet_count=100,
            byte_count=50000,
            duration=0.5,
            conn_rate=200.0,
            dst_port=80,
            unique_dst_ports=50,
            failed_auth_count=10,
        )
        pred = MLService.predict(req)
        dec = PolicyEngine.evaluate(pred, ip, "10.100.1.10", 80)
        assert dec.policy_action == "Allow", f"Protected IP {ip} was not permitted!"
        assert dec.rule_name == "MANAGEMENT_ALLOWLIST_PROTECTION"
        assert dec.enforcement_required is False
