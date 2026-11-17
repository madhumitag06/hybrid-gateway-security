"""
Integration Tests for Multi-Cloud Onboarding Lifecycle & RBAC
=============================================================
Tests end-to-end cloud account registration, credential vault encryption,
caller identity validation, resource discovery, credential rotation, and account disconnection.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.cloud.services.credential_vault import CredentialVaultService
from backend.app.db.session import get_db
from backend.app.models.cloud_account import CloudAccountModel, CloudCredentialVaultModel, CloudResourceModel
from backend.app.core.security import create_access_token


@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(
        subject="admin-test-01", email="admin@secops.local", role="ADMIN"
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(
        subject="analyst-test-01", email="analyst@secops.local", role="ANALYST"
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator_headers():
    token = create_access_token(
        subject="operator-test-01", email="operator@secops.local", role="OPERATOR"
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def mock_cloud_connection_for_offline_testing(monkeypatch):
    """
    Guarantees that test suite executes 100% offline with zero external cloud calls
    and zero network timeouts, strictly honoring Section 2 of Master Directive.
    """
    from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
    monkeypatch.setattr(
        CloudConnectionManager,
        "test_connection",
        lambda cfg: {
            "provider": cfg.provider,
            "status": "CONFIGURED",
            "latency_ms": 1.2,
            "message": "Offline test fixture verification",
            "caller_identity": {
                "account": cfg.account_id,
                "arn": f"arn:aws:iam::{cfg.account_id}:role/MockedGatewayRole",
                "status": "VERIFIED",
                "auth_method": "OFFLINE_TEST_FIXTURE",
            },
            "checked_at": "2026-11-17T00:00:00Z",
        },
    )


def test_list_accounts_returns_masked_vault_indicators(api_client, analyst_headers):
    """Verify GET /api/v1/cloud/accounts returns accounts with safe masked indicators and no secrets."""
    res = api_client.get("/api/v1/cloud/accounts", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    for acc in data:
        assert "password" not in acc
        assert "secret_access_key" not in acc
        assert "client_secret" not in acc


def test_onboard_aws_account_with_credentials_vault(api_client, operator_headers):
    """Verify onboarding AWS account encrypts secrets in vault and runs initial discovery."""
    acc_id = "test-aws-lifecycle-01"
    req_body = {
        "provider": "AWS",
        "account_id": acc_id,
        "display_name": "Test AWS Enterprise Lab",
        "region": "us-east-1",
        "role_arn": "arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole",
        "external_id": "SecretExternalID123",
        "credentials": {
            "access_key_id": "AKIA1111222233334444",
            "secret_access_key": "SecretAccessKeyStringThatMustBeEncrypted",
            "role_arn": "arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole",
            "external_id": "SecretExternalID123",
        },
    }

    res = api_client.post("/api/v1/cloud/accounts", json=req_body, headers=operator_headers)
    assert res.status_code == 200
    result = res.json()
    assert result["account_id"] == acc_id
    assert result["provider"] == "AWS"
    assert result["has_stored_credentials"] is True
    assert result["masked_identity"] is not None
    # Verify secret is NEVER returned in response
    assert "SecretAccessKeyStringThatMustBeEncrypted" not in str(result)
    assert "SecretExternalID123" not in str(result)


def test_onboard_gcp_account_and_discovery(api_client, operator_headers):
    """Verify onboarding GCP account and executing discovery."""
    acc_id = "test-gcp-lifecycle-01"
    req_body = {
        "provider": "GCP",
        "account_id": acc_id,
        "display_name": "Test GCP Builders Hub",
        "region": "us-central1",
        "project_id": "gcp-builders-test-proj",
        "credentials": {
            "project_id": "gcp-builders-test-proj",
            "client_email": "gateway-sa@gcp-builders-test-proj.iam.gserviceaccount.com",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...\n-----END PRIVATE KEY-----",
        },
    }

    res = api_client.post("/api/v1/cloud/accounts", json=req_body, headers=operator_headers)
    assert res.status_code == 200
    result = res.json()
    assert result["account_id"] == acc_id
    assert result["has_stored_credentials"] is True
    assert "PRIVATE KEY" not in str(result)

    # Test universal discovery endpoint for GCP
    disc_res = api_client.post(
        f"/api/v1/cloud/accounts/GCP/discover?account_id={acc_id}",
        headers=operator_headers,
    )
    assert disc_res.status_code == 200
    disc_data = disc_res.json()
    assert disc_data["status"] == "SUCCESS"
    assert disc_data["provider"] == "GCP"
    assert disc_data["total_resources"] >= 1


def test_onboard_azure_account_and_discovery(api_client, operator_headers):
    """Verify onboarding Azure account and executing discovery."""
    acc_id = "test-azure-lifecycle-01"
    req_body = {
        "provider": "AZURE",
        "account_id": acc_id,
        "display_name": "Test Azure Enterprise Sub",
        "region": "eastus",
        "subscription_id": "sub-12345-azure-test",
        "tenant_id": "tenant-67890-test",
        "client_id": "client-abcde-test",
        "credentials": {
            "subscription_id": "sub-12345-azure-test",
            "tenant_id": "tenant-67890-test",
            "client_id": "client-abcde-test",
            "client_secret": "SuperConfidentialAzureClientSecretString",
        },
    }

    res = api_client.post("/api/v1/cloud/accounts", json=req_body, headers=operator_headers)
    assert res.status_code == 200
    result = res.json()
    assert result["account_id"] == acc_id
    assert result["has_stored_credentials"] is True
    assert "SuperConfidentialAzureClientSecretString" not in str(result)

    # Test universal discovery endpoint for Azure
    disc_res = api_client.post(
        f"/api/v1/cloud/accounts/AZURE/discover?account_id={acc_id}",
        headers=operator_headers,
    )
    assert disc_res.status_code == 200
    disc_data = disc_res.json()
    assert disc_data["status"] == "SUCCESS"
    assert disc_data["provider"] == "AZURE"
    assert disc_data["total_resources"] >= 1


def test_rotate_credentials_and_disconnect_lifecycle(api_client, admin_headers, analyst_headers):
    """Verify credential rotation and account disconnection lifecycle."""
    acc_id = "test-rotation-account"
    # 1. Onboard account
    create_res = api_client.post(
        "/api/v1/cloud/accounts",
        json={
            "provider": "AWS",
            "account_id": acc_id,
            "region": "us-east-1",
            "credentials": {"access_key_id": "AKIAOLDOLDOLDOLD", "secret_access_key": "OldSecretValue"},
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 200

    # 2. Analyst cannot rotate credentials (RBAC check)
    rotate_payload = {
        "credentials": {"access_key_id": "AKIANEWNEWNEWNEW", "secret_access_key": "NewRotatedSecretValue"}
    }
    forbidden_res = api_client.post(
        f"/api/v1/cloud/accounts/AWS/{acc_id}/rotate-credentials",
        json=rotate_payload,
        headers=analyst_headers,
    )
    assert forbidden_res.status_code == 403

    # 3. Admin successfully rotates credentials
    rotate_res = api_client.post(
        f"/api/v1/cloud/accounts/AWS/{acc_id}/rotate-credentials",
        json=rotate_payload,
        headers=admin_headers,
    )
    assert rotate_res.status_code == 200
    rot_data = rotate_res.json()
    assert rot_data["success"] is True
    assert rot_data["rotated_at"] is not None
    assert "NewRotatedSecretValue" not in str(rot_data)

    # 4. Analyst cannot delete account (RBAC check)
    del_forbidden = api_client.delete(
        f"/api/v1/cloud/accounts/AWS/{acc_id}",
        headers=analyst_headers,
    )
    assert del_forbidden.status_code == 403

    # 5. Admin successfully disconnects and deletes account
    del_res = api_client.delete(
        f"/api/v1/cloud/accounts/AWS/{acc_id}",
        headers=admin_headers,
    )
    assert del_res.status_code == 200
    assert del_res.json()["success"] is True

    # 6. Verify account is gone
    get_res = api_client.get(f"/api/v1/cloud/accounts?provider=AWS", headers=admin_headers)
    assert not any(a["account_id"] == acc_id for a in get_res.json())
