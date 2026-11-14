"""
Unit tests for Cloud Provider Abstraction Interfaces and Connection Manager.
"""

import pytest
from backend.app.cloud.interfaces.provider import BaseCloudProviderAdapter
from backend.app.cloud.interfaces.telemetry import BaseTelemetryProvider
from backend.app.cloud.interfaces.enforcement import BaseCloudEnforcementProvider
from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema


def test_cloud_connection_manager_factory():
    """Verify factory instantiates adapters for all supported providers."""
    providers = ["AWS", "GCP", "AZURE", "DOCKER_LAB"]
    for prov in providers:
        cfg = CloudAccountConfigSchema(
            account_id=f"test-{prov.lower()}-01",
            provider=prov,
            account_name=f"Test {prov} Account",
            region="us-east-1" if prov == "AWS" else ("us-central1" if prov == "GCP" else "eastus"),
            enabled=True,
        )
        adapter = CloudConnectionManager.create_adapter(cfg)
        assert isinstance(adapter, BaseCloudProviderAdapter)
        assert adapter.provider == prov
        assert adapter.account_id == f"test-{prov.lower()}-01"

        # Verify child provider getters
        assert isinstance(adapter.get_identity_provider(), BaseCloudIdentityProvider)
        assert isinstance(adapter.get_telemetry_provider(), BaseTelemetryProvider)
        assert isinstance(adapter.get_enforcement_provider(), BaseCloudEnforcementProvider)


def test_invalid_provider_raises_error():
    """Verify requesting an unsupported provider raises ValueError."""
    cfg = CloudAccountConfigSchema(
        account_id="invalid-01",
        provider="AWS",  # Pydantic schema only allows valid literals, so override inside factory check
        account_name="Invalid Provider",
    )
    cfg.provider = "UNKNOWN_CLOUD"  # type: ignore
    with pytest.raises(ValueError, match="Unsupported cloud provider"):
        CloudConnectionManager.create_adapter(cfg)


def test_capabilities_contract():
    """Verify provider capability reporting contract."""
    for prov in ["AWS", "GCP", "AZURE", "DOCKER_LAB"]:
        cfg = CloudAccountConfigSchema(
            account_id=f"test-{prov.lower()}-cap",
            provider=prov,
            account_name=f"Cap Test {prov}",
            region="global",
            enabled=True,
            enforcement_enabled=True,
        )
        adapter = CloudConnectionManager.create_adapter(cfg)
        caps = adapter.get_capabilities()
        assert caps.read_inventory is True
        assert caps.read_flow_logs is True
        assert caps.supports_flow_logs_v2 is True

