"""
AWS Identity & Access Provider
Handles AWS STS caller identity, role assumption, and OIDC federation metadata.
"""

from typing import Any, Dict, Optional, Tuple
import logging

try:
    from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
except ImportError:
    from app.cloud.interfaces.identity import BaseCloudIdentityProvider

logger = logging.getLogger(__name__)


class AwsIdentityProvider(BaseCloudIdentityProvider):
    """AWS STS and IAM identity provider implementation."""

    def __init__(
        self,
        account_id: str = "aws-production-01",
        role_arn: Optional[str] = None,
        region: str = "us-east-1",
        oidc_role_arn: Optional[str] = None,
        oidc_token_path: Optional[str] = None,
    ):
        super().__init__(provider_name="AWS", account_id=account_id)
        self.role_arn = role_arn
        self.region = region
        self.oidc_role_arn = oidc_role_arn
        self.oidc_token_path = oidc_token_path

    def validate_credentials(self) -> Tuple[bool, str]:
        """Validate AWS IAM / OIDC configuration."""
        if not self.account_id:
            return False, "Missing AWS account_id"
        if not self.region:
            return False, "Missing AWS region"
        return True, "AWS identity configuration syntactically valid"

    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Verify caller identity via STS GetCallerIdentity if boto3 and credentials exist,
        otherwise return configured non-secret IAM identity descriptor.
        """
        try:
            import boto3
            # Check if AWS credentials or IAM role exists
            sts = boto3.client("sts", region_name=self.region)
            identity = sts.get_caller_identity()
            return {
                "account": identity.get("Account", self.account_id),
                "arn": identity.get("Arn", self.role_arn or f"arn:aws:iam::{self.account_id}:root"),
                "user_id": identity.get("UserId", f"AROA{self.account_id[:12].upper()}"),
                "status": "VERIFIED",
                "auth_method": "STS_ASSUME_ROLE" if self.role_arn else "IAM_USER",
            }
        except Exception as e:
            logger.debug("boto3 sts call omitted or unconfigured: %s", e)
            # Safe non-secret return for simulated/configured mode
            return {
                "account": self.account_id,
                "arn": self.role_arn or f"arn:aws:iam::{self.account_id}:role/SecurityGatewayRole",
                "user_id": f"AROA{self.account_id[:12].upper()}" if len(self.account_id) >= 12 else "AROA000000000000",
                "status": "CONFIGURED_STANDBY",
                "auth_method": "OIDC_WEB_IDENTITY" if self.oidc_role_arn else "ASSUME_ROLE",
                "note": "Credentials verified syntactically or in simulated standby mode",
            }

    def get_federation_metadata(self) -> Dict[str, Any]:
        """Return GitHub Actions OIDC federation metadata."""
        return {
            "oidc_provider": "token.actions.githubusercontent.com",
            "audience": "sts.amazonaws.com",
            "role_arn": self.oidc_role_arn or self.role_arn,
            "session_name": "AntigravitySecurityGatewaySession",
            "region": self.region,
        }

