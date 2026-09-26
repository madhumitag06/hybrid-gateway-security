"""
Database & Repository Integration Tests
=======================================
Directly tests SQLAlchemy ORM models, constraints, and repository data-access methods.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy.exc import IntegrityError
from backend.app.db.session import SessionLocal, init_db
from backend.app.models.policy_audit_log import PolicyAuditLogModel
from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.repositories.security_event_repo import SecurityEventRepository


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Ensure database schema is initialized for testing."""
    init_db()


@pytest.fixture
def db_session():
    """Yield a database session and roll back changes after each test."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_create_and_retrieve_security_event(db_session):
    repo = SecurityEventRepository(db_session)

    test_event_id = "test-evt-001"
    # Clean up if exists
    repo.delete_by_id(test_event_id)

    event = SecurityEventModel(
        id=test_event_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.99",
        destination_ip="10.100.2.50",
        attack_type="PORT_SCAN",
        risk_score=95,
        threat_level="HIGH",
        confidence=0.98,
        action_recommendation="Block",
        current_policy_action="Block",
        status="Applied",
        description="Test port scan event",
        is_anomaly=True,
        is_demo=False,
        flow_features={"packet_count": 5, "conn_rate": 150.0},
        class_probabilities={"PORT_SCAN": 0.98, "BENIGN": 0.02},
        top_contributing_features=[{"feature": "conn_rate", "deviation_z_score": 10.5}],
    )

    created = repo.create(event)
    assert created.id == test_event_id

    fetched = repo.get_by_id(test_event_id)
    assert fetched is not None
    assert fetched.source_ip == "192.168.1.99"
    assert fetched.risk_score == 95
    assert fetched.is_anomaly is True

    # Clean up
    repo.delete_by_id(test_event_id)


def test_policy_audit_logging(db_session):
    event_repo = SecurityEventRepository(db_session)
    audit_repo = PolicyAuditRepository(db_session)

    test_event_id = "test-evt-audit"
    event_repo.delete_by_id(test_event_id)

    event = SecurityEventModel(
        id=test_event_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.5",
        destination_ip="10.100.1.1",
        attack_type="BRUTE_FORCE",
        risk_score=85,
        threat_level="HIGH",
        confidence=0.92,
        action_recommendation="Restrict",
        current_policy_action="Monitor",
        status="Monitoring",
        description="SSH login failures",
        is_anomaly=True,
        flow_features={},
        class_probabilities={},
        top_contributing_features=[],
    )
    event_repo.create(event)

    # Add audit log
    audit_repo.log_action(
        event_id=test_event_id,
        requested_action="Block",
        previous_action="Monitor",
        resulting_status="Applied",
        actor="analyst_krishna",
    )

    history = audit_repo.get_history_for_event(test_event_id)
    assert len(history) >= 1
    assert history[0].requested_action == "Block"
    assert history[0].previous_action == "Monitor"
    assert history[0].actor == "analyst_krishna"

    # Clean up
    event_repo.delete_by_id(test_event_id)


def test_filtering_and_pagination(db_session):
    repo = SecurityEventRepository(db_session)

    # Insert 3 temporary test events
    ids = ["filter-evt-1", "filter-evt-2", "filter-evt-3"]
    for i, e_id in enumerate(ids):
        repo.delete_by_id(e_id)
        ev = SecurityEventModel(
            id=e_id,
            timestamp=datetime.now(timezone.utc),
            source_ip=f"192.168.10.{i+1}",
            destination_ip="10.100.0.1",
            attack_type="PORT_SCAN" if i == 0 else "BENIGN",
            risk_score=80 if i == 0 else 10,
            threat_level="HIGH" if i == 0 else "LOW",
            confidence=0.95,
            action_recommendation="Block" if i == 0 else "Allow",
            current_policy_action="Block" if i == 0 else "Allow",
            status="Applied" if i == 0 else "Allowed",
            description=f"Filter test event {i}",
            is_anomaly=(i == 0),
            flow_features={},
            class_probabilities={},
            top_contributing_features=[],
        )
        repo.create(ev)

    # Filter by threat_level = HIGH
    high_events, count = repo.list_events(threat_level="HIGH")
    assert any(e.id == "filter-evt-1" for e in high_events)

    # Filter by min_risk = 70
    risky_events, count = repo.list_events(min_risk=70)
    assert any(e.id == "filter-evt-1" for e in risky_events)

    # Clean up
    for e_id in ids:
        repo.delete_by_id(e_id)
