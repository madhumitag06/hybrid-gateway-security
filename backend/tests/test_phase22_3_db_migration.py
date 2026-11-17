"""
Phase 22.3 SEC-08 Database Migration Safety & Alembic Ownership Test Suite:
Isolated Lifecycle Scenarios on Disposable SQLite Fixtures.
"""

import os
import tempfile
import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic import command

from backend.app.db.session import (
    HEAD_ALEMBIC_REVISION,
    get_alembic_config,
    get_current_alembic_version,
    verify_production_schema,
    apply_migrations_to_head,
    init_db,
)


@pytest.fixture
def disposable_db():
    """Provides a fresh, isolated temporary SQLite database path."""
    temp_dir = tempfile.mkdtemp(prefix="hgs_test_migration_")
    db_path = os.path.join(temp_dir, "migration_fixture.db")
    db_url = f"sqlite:///{db_path}"
    engine = sa.create_engine(db_url)
    try:
        yield db_url, engine
    finally:
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass
        if os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass


def test_scenario_1_clean_database_upgrade(disposable_db):
    """
    Scenario 1: Empty database upgraded through Alembic migrations to HEAD.
    Verifies all expected tables, version state, and authoritative migration ownership.
    """
    db_url, engine = disposable_db

    # 1. Start with clean database
    inspector_before = sa.inspect(engine)
    assert inspector_before.get_table_names() == []

    # 2. Run Alembic upgrade head
    apply_migrations_to_head(db_url=db_url)

    # 3. Verify Alembic version recorded
    ver = get_current_alembic_version(engine)
    assert ver == HEAD_ALEMBIC_REVISION

    # 4. Verify all expected tables exist
    inspector_after = sa.inspect(engine)
    tables = set(inspector_after.get_table_names())
    expected_tables = {
        "alembic_version",
        "_alembic_004_created_tables",
        "_alembic_005_created_tables",
        "users",
        "refresh_tokens",
        "security_events",
        "active_enforcements",
        "policy_audit_logs",
        "shadow_predictions",
        "pcap_ingestions",
        "cloud_accounts",
        "cloud_resources",
        "cloud_telemetry_checkpoints",
        "cloud_telemetry_ingestions",
        "cloud_credential_vault",
        "adaptive_flow_feedbacks",
        "adaptive_training_runs",
    }
    assert expected_tables.issubset(tables)

    # 5. Verify production schema verification passes
    is_valid, msg = verify_production_schema(engine)
    assert is_valid is True
    assert HEAD_ALEMBIC_REVISION in msg


def test_scenario_2_existing_migrated_database_restart(disposable_db):
    """
    Scenario 2: Existing migrated database with populated records.
    Verifies that application startup verification leaves all records intact
    and causes zero schema drift.
    """
    db_url, engine = disposable_db

    # 1. Apply migrations to head
    apply_migrations_to_head(db_url=db_url)

    # 2. Insert representative records into users and security_events
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO users (id, email, password_hash, full_name, role, is_active, is_verified, auth_provider, created_at, updated_at) "
            "VALUES ('test-user-1', 'persisted@gateway.local', '$2b$12$fakehash', 'Persisted User', 'ANALYST', 1, 1, 'LOCAL', '2026-11-16 00:00:00', '2026-11-16 00:00:00')"
        ))
        conn.execute(sa.text(
            "INSERT INTO security_events (id, timestamp, source_ip, destination_ip, attack_type, risk_score, threat_level, confidence, action_recommendation, current_policy_action, status, description, is_anomaly, is_demo, flow_features, class_probabilities, top_contributing_features, created_at, updated_at) "
            "VALUES ('event-1', '2026-11-16 00:00:00', '192.168.1.55', '10.0.0.1', 'BENIGN', 10, 'LOW', 0.95, 'Allow', 'Allow', 'PROCESSED', 'Normal flow', 0, 0, '{}', '{}', '{}', '2026-11-16 00:00:00', '2026-11-16 00:00:00')"
        ))

    # 3. Run production verification
    is_valid, msg = verify_production_schema(engine)
    assert is_valid is True

    # 4. Verify records are intact
    with engine.connect() as conn:
        user_count = conn.execute(sa.text("SELECT COUNT(*) FROM users")).scalar()
        event_count = conn.execute(sa.text("SELECT COUNT(*) FROM security_events")).scalar()
        assert user_count == 1
        assert event_count == 1

        # Check version remains at HEAD
        ver = conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == HEAD_ALEMBIC_REVISION


def test_scenario_3_unmigrated_database_fails_closed_in_production(disposable_db, monkeypatch):
    """
    Scenario 3: Unmigrated database in production environment must fail closed.
    verify_production_schema must return False and init_db must raise RuntimeError.
    """
    db_url, engine = disposable_db
    monkeypatch.setattr("backend.app.config.settings.app_env", "production")

    # 1. Empty DB - missing alembic_version table
    is_valid, msg = verify_production_schema(engine)
    assert is_valid is False
    assert "alembic_version table missing" in msg

    # 2. init_db() in production must raise RuntimeError
    monkeypatch.setattr("backend.app.db.session.engine", engine)
    with pytest.raises(RuntimeError) as exc_info:
        init_db()
    assert "alembic_version table missing" in str(exc_info.value)


def test_scenario_4_downgrade_preserves_unowned_tables(disposable_db):
    """
    Scenario 4: Independent-process migration ownership safety.
    Verifies that downgrade only removes tables tracked by _alembic_004_created_tables,
    preserving earlier revision tables (users, security_events, active_enforcements).
    """
    db_url, engine = disposable_db

    # 1. Upgrade to head
    cfg = get_alembic_config(db_url=db_url)
    command.upgrade(cfg, "head")

    inspector_head = sa.inspect(engine)
    tables_at_head = set(inspector_head.get_table_names())
    assert "policy_audit_logs" in tables_at_head
    assert "users" in tables_at_head
    assert "cloud_credential_vault" in tables_at_head

    # 2. Downgrade to 003_auth_users
    command.downgrade(cfg, "003_auth_users")

    # 3. Verify revision is at 003_auth_users
    ver = get_current_alembic_version(engine)
    assert ver == "003_auth_users"

    # 4. Tables created by 004 were dropped, but 003 and earlier tables remain
    inspector_downgraded = sa.inspect(engine)
    tables_after = set(inspector_downgraded.get_table_names())
    assert "users" in tables_after
    assert "refresh_tokens" in tables_after
    assert "security_events" in tables_after
    assert "active_enforcements" in tables_after
    # shadow_predictions was created by 004 and should be dropped
    assert "shadow_predictions" not in tables_after
    assert "cloud_accounts" not in tables_after
    assert "_alembic_004_created_tables" not in tables_after


def test_scenario_5_schema_drift_and_incomplete_schema_detected(disposable_db):
    """
    Scenario 5: Schema drift and missing critical tables are caught fail-closed.
    """
    db_url, engine = disposable_db

    # 1. Create alembic_version table with an outdated revision
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES ('002_active_enforcements')"))

    is_valid, msg = verify_production_schema(engine)
    assert is_valid is False
    assert "Schema drift detected" in msg

    # 2. Version is set to HEAD but critical tables are missing
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE alembic_version SET version_num = '005_cloud_credentials'"))

    is_valid, msg = verify_production_schema(engine)
    assert is_valid is False
    assert "Production schema inconsistency" in msg
    assert "users" in msg
