"""
Enforcement Adapter & Service Test Suite
========================================
Tests Dry-Run, Sandbox mode, RESTRICT vs BLOCK distinctions, TTL expirations,
deduplication, and manual rollback.
"""

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.schemas.policy import PolicyDecision
from backend.app.services.enforcement.dry_run_adapter import DryRunAdapter
from backend.app.services.enforcement.sandbox_adapter import SandboxAdapter
from backend.app.services.enforcement_service import EnforcementService


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def sample_block_decision():
    return PolicyDecision(
        decision_id="dec-test-01",
        target_ip="198.51.100.55",
        target_port=8080,
        policy_action="Block",
        enforcement_required=True,
        confidence=0.95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=95,
        rule_name="RECON_PORT_SCAN_QUARANTINE",
        reason="Port scan reconnaissance detected.",
        suggested_ttl_seconds=300,
    )


@pytest.fixture
def sample_restrict_decision():
    return PolicyDecision(
        decision_id="dec-test-02",
        target_ip="203.0.113.88",
        target_port=22,
        policy_action="Restrict",
        enforcement_required=True,
        confidence=0.92,
        threat_level="MEDIUM",
        attack_type="BRUTE_FORCE",
        risk_score=65,
        rule_name="GRADUATED_SERVICE_RESTRICTION",
        reason="Targeted SSH brute-force attempt.",
        suggested_ttl_seconds=180,
    )


def test_dry_run_adapter_simulation(sample_block_decision):
    """Verify DryRunAdapter calculates outcomes without modifying environment."""
    adapter = DryRunAdapter()
    res = adapter.enforce(sample_block_decision, "rule-dry-01")

    assert res.success is True
    assert res.status == "SIMULATED"
    assert res.mode == "DRY_RUN"
    assert "Simulated" in res.message
    assert len(adapter.list_active_rules()) == 0


def test_sandbox_adapter_block_quarantine(sample_block_decision):
    """Verify SandboxAdapter BLOCK action drops all traffic from target IP across any port."""
    sandbox = SandboxAdapter()
    res = sandbox.enforce(sample_block_decision, "rule-sbx-01")

    assert res.success is True
    assert res.status == "ACTIVE"
    assert res.mode == "SANDBOX"

    # Test that traffic from 198.51.100.55 is dropped on ANY port
    allowed_8080, reason_8080 = sandbox.is_traffic_allowed("198.51.100.55", dst_port=8080)
    assert allowed_8080 is False
    assert "QUARANTINE" in reason_8080.upper()

    allowed_443, reason_443 = sandbox.is_traffic_allowed("198.51.100.55", dst_port=443)
    assert allowed_443 is False
    assert "QUARANTINE" in reason_443.upper()

    # Unrelated IP should pass normally
    allowed_other, _ = sandbox.is_traffic_allowed("192.168.1.50", dst_port=443)
    assert allowed_other is True


def test_sandbox_adapter_restrict_port_specific(sample_restrict_decision):
    """
    Verify SandboxAdapter RESTRICT drops traffic ONLY to the targeted port
    while allowing other legitimate ports through.
    """
    sandbox = SandboxAdapter()
    res = sandbox.enforce(sample_restrict_decision, "rule-sbx-02")

    assert res.success is True

    # Port 22 (SSH) should be restricted/dropped
    allowed_22, reason_22 = sandbox.is_traffic_allowed("203.0.113.88", dst_port=22)
    assert allowed_22 is False
    assert "RESTRICTED" in reason_22.upper()

    # Port 443 (HTTPS) from the same IP should be ALLOWED
    allowed_443, reason_443 = sandbox.is_traffic_allowed("203.0.113.88", dst_port=443)
    assert allowed_443 is True
    assert "ALLOW" in reason_443.upper()


def test_sandbox_rule_expiration():
    """Verify that expired sandbox rules are pruned and traffic is allowed again."""
    sandbox = SandboxAdapter()
    now = datetime.now(timezone.utc)
    expired_decision = PolicyDecision(
        decision_id="dec-expired",
        target_ip="198.51.100.99",
        target_port=80,
        policy_action="Block",
        enforcement_required=True,
        confidence=1.0,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        risk_score=90,
        rule_name="TEST_EXPIRED",
        reason="Test expired rule",
        suggested_ttl_seconds=-10,  # Expired in past
    )
    sandbox.enforce(expired_decision, "rule-exp-01")

    # Prune should remove expired rule
    pruned = sandbox.prune_expired()
    assert "rule-exp-01" in pruned

    # Traffic from 198.51.100.99 should now be allowed
    allowed, _ = sandbox.is_traffic_allowed("198.51.100.99", dst_port=80)
    assert allowed is True


def test_enforcement_service_deduplication(db_session: Session, sample_block_decision):
    """Verify that repeated decisions for the same target extend TTL rather than duplicate."""
    EnforcementService.set_mode("SANDBOX")

    res1, rule1 = EnforcementService.execute_decision(sample_block_decision, db_session)
    db_session.commit()
    assert rule1 is not None
    original_rule_id = rule1.id
    original_ttl = rule1.ttl_seconds

    # Second decision arrives for same target IP
    res2, rule2 = EnforcementService.execute_decision(sample_block_decision, db_session)
    db_session.commit()
    assert rule2 is not None
    assert rule2.id == original_rule_id, "Should reuse existing rule ID"
    assert rule2.ttl_seconds > original_ttl, "Should extend TTL"


def test_manual_rule_revocation(db_session: Session, sample_block_decision):
    """Verify manual revocation removes containment and logs audit record."""
    EnforcementService.set_mode("SANDBOX")
    res, rule = EnforcementService.execute_decision(sample_block_decision, db_session)
    db_session.commit()
    assert rule is not None

    success, msg = EnforcementService.revoke_rule(rule.id, db_session, actor="sec_analyst")
    db_session.commit()
    assert success is True

    # Rule in DB should be REVOKED
    repo = EnforcementRepository(db_session)
    updated_rule = repo.get_by_id(rule.id)
    assert updated_rule.status == "REVOKED"
    assert updated_rule.revoked_by == "sec_analyst"


def test_restart_reconciliation(db_session: Session, sample_restrict_decision):
    """Verify startup reconciliation restores active rules from PostgreSQL into sandbox."""
    EnforcementService.set_mode("SANDBOX")
    res, rule = EnforcementService.execute_decision(sample_restrict_decision, db_session)
    db_session.commit()

    reconciled_count = EnforcementService.reconcile_from_db(db_session)
    assert reconciled_count >= 1
