"""
AWS Identity & Access Provider
==============================
Handles AWS STS caller identity, role assumption (STS AssumeRole),
named AWS CLI profile resolution, temporary credentials, and OIDC federation metadata.
Strictly read-only; never persists or exposes secrets.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, Optional, Tuple

try:
    from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
except ImportError:
    from app.cloud.interfaces.identity import BaseCloudIdentityProvider

logger = logging.getLogger(__name__)


class AwsIdentityProvider(BaseCloudIdentityProvider):
    """AWS STS and IAM identity provider implementation supporting role assumption and named profiles."""

    def __init__(
        self,
        account_id: Optional[str] = None,
        role_arn: Optional[str] = None,
        region: Optional[str] = None,
        external_id: Optional[str] = None,
        profile_name: Optional[str] = None,
        oidc_role_arn: Optional[str] = None,
        oidc_token_path: Optional[str] = None,
        session_name: str = "AntigravitySecurityGatewaySession",
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ):
        # Auto-detect security-gateway-readonly profile if available
        detected_profile = None
        try:
            import boto3
            available_profiles = getattr(boto3.Session(), "available_profiles", [])
            if isinstance(available_profiles, (list, tuple)) and "security-gateway-readonly" in available_profiles:
                detected_profile = "security-gateway-readonly"
        except Exception:
            pass

        resolved_profile = (
            profile_name
            or os.environ.get("AWS_PROFILE")
            or detected_profile
        )

        resolved_region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "ap-southeast-2"
        )
        resolved_role_arn = (
            role_arn
            or os.environ.get("AWS_ROLE_ARN")
            or ("arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole" if resolved_profile == "security-gateway-readonly" else None)
        )
        resolved_external_id = (
            external_id
            or os.environ.get("AWS_EXTERNAL_ID")
            or ("AdaptiveGatewayAuth" if resolved_profile == "security-gateway-readonly" else None)
        )
        resolved_account_id = (
            account_id
            or os.environ.get("AWS_ACCOUNT_ID")
            or ("698766075180" if resolved_profile == "security-gateway-readonly" else None)
        )

        super().__init__(provider_name="AWS", account_id=resolved_account_id)
        self.role_arn = resolved_role_arn
        self.region = resolved_region
        self.external_id = resolved_external_id
        self.profile_name = resolved_profile
        self.oidc_role_arn = oidc_role_arn or os.environ.get("AWS_OIDC_ROLE_ARN")
        self.oidc_token_path = oidc_token_path or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
        self.session_name = session_name
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self._cached_session: Optional[Any] = None
        self._cached_credentials_expiration: Optional[datetime] = None

    def validate_credentials(self) -> Tuple[bool, str]:
        """Validate AWS IAM / STS configuration syntactically."""
        if not self.region:
            return False, "Missing AWS region"
        if self.role_arn and not self.role_arn.startswith("arn:aws:iam::"):
            return False, f"Invalid AWS Role ARN format: {self.role_arn}"
        return True, "AWS identity configuration syntactically valid"

    def get_boto3_session(self) -> Tuple[Optional[Any], Dict[str, Any]]:
        """
        Create and return an authenticated boto3.Session using temporary credentials.
        Architecture: Local IAM Identity / AWS Profile -> STS AssumeRole -> Temporary Read-Only Session.
        Returns (session, diagnostic_info).
        """
        try:
            import boto3
            import botocore.exceptions
        except ImportError:
            return None, {
                "status": "ERROR",
                "message": "boto3 is not installed in the Python runtime.",
            }

        # Check if cached session is still valid
        now = datetime.now(timezone.utc)
        if (
            self._cached_session is not None
            and self._cached_credentials_expiration is not None
            and (self._cached_credentials_expiration - now).total_seconds() > 300
        ):
            return self._cached_session, {"status": "CACHED", "message": "Using cached temporary session"}

        try:
            if self.access_key_id and self.secret_access_key:
                base_session = boto3.Session(
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    aws_session_token=self.session_token,
                    region_name=self.region,
                )
            else:
                base_session = boto3.Session(
                    region_name=self.region,
                    profile_name=self.profile_name,
                )

            sts = base_session.client("sts", region_name=self.region)
            identity = sts.get_caller_identity()
            current_arn = identity.get("Arn", "")

            # If current identity is already the target assumed role (e.g. resolved via AWS CLI profile), return directly
            target_role_name = self.role_arn.split("/")[-1] if self.role_arn else "SecurityGatewayReadOnlyRole"
            if ":assumed-role/" in current_arn and target_role_name in current_arn:
                self._cached_session = base_session
                return base_session, {
                    "status": "ASSUMED",
                    "role_arn": self.role_arn,
                    "profile_name": self.profile_name,
                    "arn": current_arn,
                    "account": identity.get("Account"),
                    "user_id": identity.get("UserId"),
                    "auth_method": "STS_ASSUME_ROLE",
                }

            # If a role ARN is configured and not yet assumed, assume the role to get temporary read-only credentials
            if self.role_arn:
                assume_params: Dict[str, Any] = {
                    "RoleArn": self.role_arn,
                    "RoleSessionName": self.session_name,
                    "DurationSeconds": 3600,
                }
                if self.external_id:
                    assume_params["ExternalId"] = self.external_id

                resp = sts.assume_role(**assume_params)
                creds = resp["Credentials"]
                assumed_session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
                self._cached_session = assumed_session
                self._cached_credentials_expiration = creds.get("Expiration")

                assumed_id = resp.get("AssumedRoleUser", {})
                return assumed_session, {
                    "status": "ASSUMED",
                    "role_arn": self.role_arn,
                    "profile_name": self.profile_name,
                    "assumed_role_id": assumed_id.get("AssumedRoleId"),
                    "arn": assumed_id.get("Arn"),
                    "expiration": creds.get("Expiration").isoformat() if creds.get("Expiration") else None,
                    "auth_method": "STS_ASSUME_ROLE",
                }

            # If no role_arn is specified, verify base session credentials directly
            self._cached_session = base_session
            return base_session, {
                "status": "DIRECT",
                "account": identity.get("Account"),
                "arn": current_arn,
                "user_id": identity.get("UserId"),
                "auth_method": "IAM_USER",
            }

        except botocore.exceptions.NoCredentialsError:
            logger.info("No AWS credentials located for STS identity.")
            return None, {
                "status": "NOT_CONFIGURED",
                "message": "No AWS credentials located. Configure credentials via AWS CLI ('aws configure'), temporary environment variables, or IAM role.",
            }
        except botocore.exceptions.ProfileNotFound as pnfe:
            logger.warning("AWS profile '%s' not found: %s", self.profile_name, pnfe)
            return None, {
                "status": "NOT_CONFIGURED",
                "message": f"AWS CLI profile '{self.profile_name}' not found in ~/.aws/config or credentials.",
            }
        except botocore.exceptions.ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "ClientError")
            err_msg = ce.response.get("Error", {}).get("Message", str(ce))
            logger.warning("AWS STS authentication failed [%s]: %s", err_code, err_msg)
            return None, {
                "status": "ROLE_ASSUME_FAILED" if self.role_arn else "AUTHENTICATION_FAILED",
                "error_code": err_code,
                "message": f"{err_code}: {err_msg}",
            }
        except Exception as e:
            logger.error("Unexpected error initializing AWS session: %s", e)
            return None, {
                "status": "ERROR",
                "message": str(e),
            }

    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Verify caller identity via STS GetCallerIdentity.
        Returns strictly authentic status (never claims VERIFIED without actual STS confirmation).
        """
        session, diag = self.get_boto3_session()

        if session is None:
            status_code = diag.get("status", "NOT_CONFIGURED")
            return {
                "account": self.account_id if self.account_id != "unconfigured" else None,
                "arn": self.role_arn,
                "user_id": None,
                "region": self.region,
                "status": status_code,
                "auth_method": "STS_ASSUME_ROLE" if self.role_arn else "IAM_USER",
                "profile_name": self.profile_name,
                "error": diag.get("message"),
                "error_code": diag.get("error_code"),
                "instructions": (
                    "To enable real AWS read-only connectivity:\n"
                    "1. Configure AWS CLI profile 'security-gateway-readonly'.\n"
                    "2. Set AWS_ROLE_ARN and optional AWS_EXTERNAL_ID.\n"
                    "3. Ensure the IAM identity has sts:AssumeRole permissions and ec2 read-only policies."
                ),
            }

        try:
            sts = session.client("sts", region_name=self.region)
            identity = sts.get_caller_identity()
            account = identity.get("Account")
            arn = identity.get("Arn")
            user_id = identity.get("UserId")

            # Update account ID to verified AWS account ID
            if account:
                self.account_id = account

            return {
                "account": account,
                "arn": arn,
                "user_id": user_id,
                "region": self.region,
                "status": "VERIFIED",
                "auth_method": diag.get("auth_method", "STS_ASSUME_ROLE" if "assumed-role" in arn else "IAM_CALLER_IDENTITY"),
                "role_arn": self.role_arn,
                "profile_name": self.profile_name,
                "session_name": self.session_name,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.warning("Error querying STS caller identity: %s", e)
            return {
                "account": self.account_id,
                "arn": self.role_arn,
                "user_id": None,
                "region": self.region,
                "status": "ERROR",
                "auth_method": "STS_ASSUME_ROLE" if self.role_arn else "IAM_USER",
                "profile_name": self.profile_name,
                "error": str(e),
            }

    def get_federation_metadata(self) -> Dict[str, Any]:
        """Return GitHub Actions OIDC federation metadata."""
        return {
            "oidc_provider": "token.actions.githubusercontent.com",
            "audience": "sts.amazonaws.com",
            "role_arn": self.oidc_role_arn or self.role_arn,
            "session_name": self.session_name,
            "region": self.region,
        }
