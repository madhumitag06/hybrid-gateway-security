"""
Unit & Integration tests for Cloud Registry & Inventory Persistence.
"""

from datetime import datetime, timezone
import pytest
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema
from backend.app.cloud.schemas.cloud_resource import CloudResourceSchema
from backend.app.cloud.services.cloud_registry import CloudRegistry
from backend.app.db.session import SessionLocal, init_db
from backend.app.models.cloud_account import CloudAccountModel, CloudResourceModel


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_cloud_account_upsert_and_retrieval(db_session):
    test_id = "test-aws-reg-01"

    # Clean up if existed
    existing = db_session.query(CloudAccountModel).filter(CloudAccountModel.account_id == test_id).first()
    if existing:
        db_session.delete(existing)
        db_session.commit()

    cfg = CloudAccountConfigSchema(
        account_id=test_id,
        provider="AWS",
        display_name="Test AWS Registry Account",
        region="us-east-1",
        role_arn="arn:aws:iam::123456789012:role/SecRole",
        enabled=True,
        enforcement_enabled=False,
    )

    saved = CloudRegistry.upsert_account(
        db=db_session,
        config=cfg,
        status="CONFIGURED",
        latency_ms=2.5,
    )

    assert saved.account_id == test_id
    assert saved.provider == "AWS"
    assert saved.status == "CONFIGURED"
    assert saved.display_name == "Test AWS Registry Account"
    assert saved.metadata_json.get("role_arn") == "arn:aws:iam::123456789012:role/SecRole"

    # Verify secret redaction: access keys/passwords must NOT be present
    assert "aws_secret_access_key" not in saved.metadata_json
    assert "password" not in saved.metadata_json

    # Retrieve
    retrieved = CloudRegistry.get_account(db_session, test_id)
    assert retrieved is not None
    assert retrieved.display_name == "Test AWS Registry Account"

    # Update status
    updated = CloudRegistry.update_account_status(
        db_session,
        account_id=test_id,
        status="CONNECTED",
        latency_ms=1.8,
    )
    assert updated is not None
    assert updated.status == "CONNECTED"
    assert updated.metadata_json.get("latency_ms") == 1.8


def test_cloud_resource_sync_and_inventory_summary(db_session):
    account_id = "test-gcp-reg-01"
    now = datetime.now(timezone.utc)

    # Clean previous resources and account if exist
    existing_acc = db_session.query(CloudAccountModel).filter(CloudAccountModel.id == account_id).first()
    if existing_acc:
        db_session.delete(existing_acc)
        db_session.commit()

    cfg = CloudAccountConfigSchema(
        account_id=account_id,
        provider="GCP",
        display_name="Test GCP Account",
        region="us-central1",
    )
    CloudRegistry.upsert_account(db_session, cfg, status="CONNECTED")

    sample_resources = [
        CloudResourceSchema(
            resource_id="vpc-test-gcp",
            account_id=account_id,
            provider="GCP",
            resource_type="VPC",
            name="test-vpc",
            cidr_block="10.40.0.0/16",
            region="global",
            created_at=now,
        ),
        CloudResourceSchema(
            resource_id="subnet-test-gcp",
            account_id=account_id,
            provider="GCP",
            resource_type="SUBNET",
            name="test-subnet",
            cidr_block="10.40.10.0/24",
            region="us-central1",
            vpc_id="vpc-test-gcp",
            created_at=now,
        ),
        CloudResourceSchema(
            resource_id="fw-test-gcp",
            account_id=account_id,
            provider="GCP",
            resource_type="FIREWALL_POLICY",
            name="test-fw-allow",
            region="global",
            created_at=now,
        ),
    ]

    synced = CloudRegistry.sync_resources(db_session, account_id, sample_resources)
    assert synced == 3

    # Query resources
    res_list = CloudRegistry.list_resources(db_session, provider="GCP", account_id=account_id)
    assert len(res_list) == 3

    # Inventory summary
    summary = CloudRegistry.get_inventory_summary(db_session)
    assert summary.total_vpcs >= 1
    assert summary.total_subnets >= 1
    assert summary.total_security_groups >= 1
    assert "GCP" in summary.by_provider
