"""
GCP Identity & Workload Identity Federation Provider
Handles Google Cloud / Google Builders Hub project identity, service account metadata,
and Workload Identity Federation OIDC token exchange without storing static keys.
"""

from typing import Any, Dict, Optional, Tuple
import logging

try:
    from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
except ImportError:
    from app.cloud.interfaces.identity import BaseCloudIdentityProvider

logger = logging.getLogger(__name__)


class GcpIdentityProvider(BaseCloudIdentityProvider):
    """GCP Service Account and Workload Identity Federation provider."""

    def __init__(
        self,
        project_id: str = "gcp-builders-hub-prod",
        service_account_email: Optional[str] = None,
        workload_identity_pool: Optional[str] = None,
        workload_identity_provider: Optional[str] = None,
        region: str = "us-central1",
    ):
        super().__init__(provider_name="GCP", account_id=project_id)
        self.project_id = project_id
        self.service_account_email = service_account_email or f"gateway-sa@{project_id}.iam.gserviceaccount.com"
        self.workload_identity_pool = workload_identity_pool
        self.workload_identity_provider = workload_identity_provider
        self.region = region

    def validate_credentials(self) -> Tuple[bool, str]:
        """Validate GCP configuration parameters."""
        if not self.project_id:
            return False, "Missing GCP project_id"
        return True, "GCP identity configuration syntactically valid"

    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Verify caller identity via Google Cloud metadata or STS token if google-auth available,
        otherwise return configured non-secret service account identity.
        """
        try:
            import google.auth
            credentials, project = google.auth.default()
            return {
                "project_id": project or self.project_id,
                "service_account": getattr(credentials, "service_account_email", self.service_account_email),
                "status": "VERIFIED",
                "auth_method": "APPLICATION_DEFAULT_CREDENTIALS",
            }
        except Exception as e:
            logger.debug("Google auth default omitted or unconfigured: %s", e)
            return {
                "project_id": self.project_id,
                "service_account": self.service_account_email,
                "workload_identity_pool": self.workload_identity_pool or "github-actions-pool",
                "status": "CONFIGURED_STANDBY",
                "auth_method": "WORKLOAD_IDENTITY_FEDERATION",
                "note": "Configured for Google Builders Hub / GitHub Actions OIDC federation",
            }

    def get_federation_metadata(self) -> Dict[str, Any]:
        """Return GCP Workload Identity Federation parameters."""
        pool = self.workload_identity_pool or "projects/123456789012/locations/global/workloadIdentityPools/github-pool"
        provider = self.workload_identity_provider or f"{pool}/providers/github-provider"
        return {
            "audience": f"//iam.googleapis.com/{provider}",
            "service_account": self.service_account_email,
            "workload_identity_provider": provider,
            "project_id": self.project_id,
        }

