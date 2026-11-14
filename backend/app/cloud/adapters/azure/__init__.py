"""
Azure Cloud Adapter Package.
"""

from backend.app.cloud.adapters.azure.adapter import AzureCloudAdapter
from backend.app.cloud.adapters.azure.enforcement import AzureEnforcementProvider
from backend.app.cloud.adapters.azure.identity import AzureIdentityProvider
from backend.app.cloud.adapters.azure.telemetry import AzureTelemetryProvider

__all__ = [
    "AzureCloudAdapter",
    "AzureIdentityProvider",
    "AzureTelemetryProvider",
    "AzureEnforcementProvider",
]

