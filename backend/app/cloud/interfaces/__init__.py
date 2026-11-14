"""
Cloud Provider Abstraction - Interfaces Package.
"""

try:
    from backend.app.cloud.interfaces.enforcement import BaseCloudEnforcementProvider
    from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
    from backend.app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from backend.app.cloud.interfaces.telemetry import BaseTelemetryProvider
except ImportError:
    from app.cloud.interfaces.enforcement import BaseCloudEnforcementProvider
    from app.cloud.interfaces.identity import BaseCloudIdentityProvider
    from app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from app.cloud.interfaces.telemetry import BaseTelemetryProvider

__all__ = [
    "BaseCloudProviderAdapter",
    "BaseTelemetryProvider",
    "BaseCloudEnforcementProvider",
    "BaseCloudIdentityProvider",
]
