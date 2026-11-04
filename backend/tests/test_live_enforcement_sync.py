"""
Regression Tests for Hybrid-Cloud Router Reference Counting & Gateway Enforcement Deduplication
===============================================================================================
Covers:
  1. Router-side shared-rule reference counting, TTL expiry, idempotent ADD/REMOVE,
     independent source IP containment, port-scoped Restrict, and refusal of expired rules.
  2. Gateway-side host-wide Block normalization (target_port=None), multi-port scan deduplication,
     port-specific Restrict retention, Allow/Monitor non-blocking, expired DB pruning,
     startup reconciliation, and LAB_ENFORCEMENT_ENABLED gating.
"""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import settings
from backend.app.db.base import Base
from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.models.policy_audit_log import PolicyAuditLogModel
from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.schemas.policy import PolicyDecision
from backend.app.schemas.predict import PredictionResponse
from backend.app.services.enforcement.sandbox_adapter import SandboxAdapter
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.policy_engine import PolicyEngine


def _load_router_agent_module():
    router_agent_path = (
        Path(__file__).resolve().parent.parent.parent
        / "deployment"
        / "hybrid-lab"
        / "router"
        / "router_agent.py"
    )
    spec = importlib.util.spec_from_file_location("lab_router_agent", router_agent_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeIptablesChain:
    """In-memory simulation of the HYBRID_LAB_CONTAINMENT iptables chain."""

    def __init__(self) -> None:
        self.rules: List[Tuple[str, ...]] = []
        self.calls: List[List[str]] = []

    def run(self, cmd: List[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        if len(cmd) >= 3 and cmd[0] == "iptables":
            op = cmd[1]
            if op == "-C" and cmd[2] == "HYBRID_LAB_CONTAINMENT":
                spec = tuple(cmd[3:])
                rc = 0 if spec in self.rules else 1
                return subprocess.CompletedProcess(cmd, rc, "", "")
            if op == "-I" and cmd[2] == "HYBRID_LAB_CONTAINMENT":
                spec = tuple(cmd[4:])
                self.rules.insert(0, spec)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if op == "-D" and cmd[2] == "HYBRID_LAB_CONTAINMENT":
                spec = tuple(cmd[3:])
                if spec in self.rules:
                    self.rules.remove(spec)
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                return subprocess.CompletedProcess(cmd, 1, "", "Bad rule")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def router_env(monkeypatch):
    mod = _load_router_agent_module()
    mod._active_rules.clear()
    fake_chain = FakeIptablesChain()
    monkeypatch.setattr(mod.subprocess, "run", fake_chain.run)
    return mod, fake_chain


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


# ==============================================================================
# 1. ROUTER-SIDE REFERENCE COUNTING & LIFECYCLE TESTS
# ==============================================================================


def test_router_shared_block_reference_counting_and_expiry(router_env):
    """
    - Two Block rule IDs for the same source produce one effective DROP rule.
    - Expiring the first rule leaves the DROP rule installed.
    - Expiring the final rule removes the DROP rule.
    """
    mod, chain = router_env

    res1 = mod.apply_or_remove_firewall_rule(
        {
            "operation": "ADD",
            "rule_id": "rule-short",
            "target_ip": "10.10.10.50",
            "action": "Block",
            "target_port": None,
            "ttl_seconds": 10,
        }
    )
    res2 = mod.apply_or_remove_firewall_rule(
        {
            "operation": "ADD",
            "rule_id": "rule-long",
            "target_ip": "10.10.10.50",
            "action": "Block",
            "target_port": None,
            "ttl_seconds": 300,
        }
    )

    assert res1["success"] is True
    assert res2["success"] is True
    assert len(mod._active_rules) == 2
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Simulate expiry of rule-short only
    mod._active_rules["rule-short"]["expires_epoch"] = 1.0
    expired = mod._reap_expired_rules()
    assert expired == ["rule-short"]
    assert "rule-short" not in mod._active_rules
    assert "rule-long" in mod._active_rules
    # DROP rule MUST remain installed because rule-long is still active
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Simulate expiry of the final rule (rule-long)
    mod._active_rules["rule-long"]["expires_epoch"] = 1.0
    expired_final = mod._reap_expired_rules()
    assert expired_final == ["rule-long"]
    assert len(mod._active_rules) == 0
    assert chain.rules == []


def test_router_remove_duplicate_preserves_other_active_rule(router_env):
    """
    - Removing one duplicate rule ID does not remove another active rule's protection.
    - Duplicate ADD and REMOVE are idempotent.
    """
    mod, chain = router_env

    # Duplicate ADD with same rule_id is idempotent
    mod.apply_or_remove_firewall_rule(
        {"operation": "ADD", "rule_id": "rule-a", "target_ip": "10.10.10.50", "action": "Block", "ttl_seconds": 120}
    )
    mod.apply_or_remove_firewall_rule(
        {"operation": "ADD", "rule_id": "rule-a", "target_ip": "10.10.10.50", "action": "Block", "ttl_seconds": 120}
    )
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Second distinct rule_id for same source
    mod.apply_or_remove_firewall_rule(
        {"operation": "ADD", "rule_id": "rule-b", "target_ip": "10.10.10.50", "action": "Block", "ttl_seconds": 120}
    )
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Remove rule-a: rule-b is still active, so DROP rule stays
    rem1 = mod.apply_or_remove_firewall_rule(
        {"operation": "REMOVE", "rule_id": "rule-a", "target_ip": "10.10.10.50", "action": "Block"}
    )
    assert rem1["success"] is True
    assert rem1["still_referenced"] is True
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Duplicate REMOVE of rule-a is safe and still preserves rule-b
    rem_dup = mod.apply_or_remove_firewall_rule(
        {"operation": "REMOVE", "rule_id": "rule-a", "target_ip": "10.10.10.50", "action": "Block"}
    )
    assert rem_dup["success"] is True
    assert rem_dup["still_referenced"] is True
    assert chain.rules == [("-s", "10.10.10.50", "-j", "DROP")]

    # Removing final rule-b removes the DROP rule
    rem2 = mod.apply_or_remove_firewall_rule(
        {"operation": "REMOVE", "rule_id": "rule-b", "target_ip": "10.10.10.50", "action": "Block"}
    )
    assert rem2["success"] is True
    assert rem2["still_referenced"] is False
    assert chain.rules == []


def test_router_independent_sources_and_port_scoped_restrict(router_env):
    """
    - Different source IPs are independently contained.
    - Restrict on one port does not block other ports or remove a Block rule.
    - Expired rules (ttl_seconds <= 0) are refused.
    """
    mod, chain = router_env

    # Contain 10.10.10.30 (Block) and 10.10.10.50 (Restrict on port 8080)
    mod.apply_or_remove_firewall_rule(
        {"operation": "ADD", "rule_id": "r-30", "target_ip": "10.10.10.30", "action": "Block", "ttl_seconds": 120}
    )
    mod.apply_or_remove_firewall_rule(
        {
            "operation": "ADD",
            "rule_id": "r-50-8080",
            "target_ip": "10.10.10.50",
            "action": "Restrict",
            "target_port": 8080,
            "ttl_seconds": 120,
        }
    )

    assert ("-s", "10.10.10.30", "-j", "DROP") in chain.rules
    assert ("-s", "10.10.10.50", "-p", "tcp", "--dport", "8080", "-j", "DROP") in chain.rules
    assert ("-s", "10.10.10.50", "-j", "DROP") not in chain.rules

    # Removing 10.10.10.30 leaves 10.10.10.50:8080 intact
    mod.apply_or_remove_firewall_rule(
        {"operation": "REMOVE", "rule_id": "r-30", "target_ip": "10.10.10.30", "action": "Block"}
    )
    assert chain.rules == [("-s", "10.10.10.50", "-p", "tcp", "--dport", "8080", "-j", "DROP")]

    # Expired rule (ttl_seconds <= 0) is refused on ADD
    expired_add = mod.apply_or_remove_firewall_rule(
        {"operation": "ADD", "rule_id": "r-exp", "target_ip": "10.10.10.30", "action": "Block", "ttl_seconds": 0}
    )
    assert expired_add["success"] is False
    assert "r-exp" not in mod._active_rules


# ==============================================================================
# 2. GATEWAY-SIDE DEDUPLICATION, RECONCILIATION & ROUTER SYNC TESTS
# ==============================================================================


def test_gateway_port_scan_block_has_none_port_and_deduplicates(db_session: Session, monkeypatch):
    """
    - PORT_SCAN Block decisions have target_port=None.
    - Repeated detections for the same source across different ports do not create duplicate Block records.
    - Restrict decisions retain their destination port.
    - Monitor and Allow do not create blocking rules.
    """
    monkeypatch.setattr(settings, "lab_enforcement_enabled", False)
    EnforcementService.set_mode("SANDBOX")

    scan_pred = PredictionResponse(
        risk_score=95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        confidence=0.96,
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.96, "BENIGN": 0.04},
        top_contributing_features=[],
    )

    test_ip = f"10.10.10.{uuid.uuid4().int % 100 + 100}"
    rule_ids = set()
    for port in (22, 80, 443, 8080):
        dec = PolicyEngine.evaluate(
            prediction=scan_pred,
            source_ip=test_ip,
            destination_ip="10.20.10.40",
            dst_port=port,
        )
        assert dec.policy_action == "Block"
        assert dec.target_port is None, "Block decision must be host-wide (target_port=None)"
        res, rule_model = EnforcementService.execute_decision(dec, db_session)
        assert rule_model is not None
        assert rule_model.target_port is None
        rule_ids.add(rule_model.id)

    db_session.commit()
    assert len(rule_ids) == 1, "Multi-port scan from same source must deduplicate into one host-wide Block rule"

    # Verify Restrict retains its destination port
    spike_pred = PredictionResponse(
        risk_score=82,
        threat_level="HIGH",
        attack_type="TRAFFIC_SPIKE",
        confidence=0.88,
        action_recommendation="Restrict",
        is_anomaly=True,
        class_probabilities={"TRAFFIC_SPIKE": 0.88, "BENIGN": 0.12},
        top_contributing_features=[],
    )
    restrict_ip = f"10.10.10.{uuid.uuid4().int % 50 + 51}"
    r_dec = PolicyEngine.evaluate(
        prediction=spike_pred,
        source_ip=restrict_ip,
        destination_ip="10.20.10.40",
        dst_port=8080,
    )
    assert r_dec.policy_action == "Restrict"
    assert r_dec.target_port == 8080
    _, r_model = EnforcementService.execute_decision(r_dec, db_session)
    assert r_model is not None
    assert r_model.target_port == 8080

    # Verify Monitor and Allow do not create blocking rules
    low_conf_pred = PredictionResponse(
        risk_score=72,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        confidence=0.45,
        action_recommendation="Monitor",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.45, "BENIGN": 0.55},
        top_contributing_features=[],
    )
    mon_dec = PolicyEngine.evaluate(
        prediction=low_conf_pred,
        source_ip="10.10.10.199",
        destination_ip="10.20.10.40",
        dst_port=8080,
    )
    assert mon_dec.policy_action == "Monitor"
    assert mon_dec.enforcement_required is False
    mon_res, mon_model = EnforcementService.execute_decision(mon_dec, db_session)
    assert mon_model is None
    assert mon_res.rule_id == "no-rule"

    # Cleanup test rows
    for rid in list(rule_ids) + [r_model.id]:
        EnforcementService.revoke_rule(rid, db_session, actor="test_cleanup")
        row = db_session.get(ActiveEnforcementModel, rid)
        if row:
            db_session.delete(row)
    db_session.commit()


def test_gateway_reconciliation_and_enforcement_flag_gating(db_session: Session, monkeypatch):
    """
    - Expired DB rules are marked EXPIRED and not reconciled.
    - Active rules are reconciled and synced to router when LAB_ENFORCEMENT_ENABLED=true.
    - When LAB_ENFORCEMENT_ENABLED=false, no router HTTP calls occur.
    """
    now = datetime.now(timezone.utc)
    exp_id = f"rule-test-exp-{uuid.uuid4().hex[:6]}"
    act_id = f"rule-test-act-{uuid.uuid4().hex[:6]}"

    expired_row = ActiveEnforcementModel(
        id=exp_id,
        event_id=None,
        target_ip="10.10.10.181",
        target_port=22,
        protocol="TCP",
        action="Block",
        status="ACTIVE",
        mode="SANDBOX",
        reason="Expired test rule",
        ttl_seconds=60,
        expires_at=now - timedelta(seconds=30),
    )
    active_row = ActiveEnforcementModel(
        id=act_id,
        event_id=None,
        target_ip="10.10.10.182",
        target_port=443,
        protocol="TCP",
        action="Block",
        status="ACTIVE",
        mode="SANDBOX",
        reason="Active test rule",
        ttl_seconds=300,
        expires_at=now + timedelta(seconds=300),
    )
    db_session.add_all([expired_row, active_row])
    db_session.commit()

    router_calls: List[Dict[str, Any]] = []

    def fake_urlopen(req, timeout=1.5):
        body = json.loads(req.data.decode("utf-8")) if getattr(req, "data", None) else {}
        router_calls.append(body)
        resp = MagicMock()
        resp.status = 200
        resp.__enter__.return_value = resp
        resp.read.return_value = b'{"success": true}'
        return resp

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    try:
        # 1. With enforcement disabled: no router calls should occur
        monkeypatch.setattr(settings, "lab_enforcement_enabled", False)
        EnforcementService.reconcile_from_db(db_session)
        db_session.commit()

        db_session.refresh(expired_row)
        db_session.refresh(active_row)
        assert expired_row.status == "EXPIRED", "Expired DB rule must be marked EXPIRED during reconciliation"
        assert active_row.status == "ACTIVE"
        assert active_row.target_port is None, "Reconciled Block rule must normalize target_port to None"
        assert len(router_calls) == 0, "No router sync calls may occur when LAB_ENFORCEMENT_ENABLED=false"

        # 2. With enforcement enabled: active rule must synchronize to lab-router, expired rule must not
        monkeypatch.setattr(settings, "lab_enforcement_enabled", True)
        EnforcementService.reconcile_from_db(db_session)
        db_session.commit()

        synced_ids = [c["rule_id"] for c in router_calls]
        assert act_id in synced_ids
        assert exp_id not in synced_ids
    finally:
        for row_id in (exp_id, act_id):
            row = db_session.get(ActiveEnforcementModel, row_id)
            if row:
                db_session.delete(row)
        db_session.commit()
