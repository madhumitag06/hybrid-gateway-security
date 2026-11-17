"""
Cloud Credential Vault Service
===============================
Provides authenticated, envelope-encrypted secret management for multi-cloud integrations.
All sensitive credentials (AWS Access Keys, Secret Keys, GCP Service Account keys,
Azure Client Secrets, and tokens) are encrypted at rest using AES-256-GCM.
Plaintext secrets are NEVER written to logs, database columns, or API responses.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import secrets
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Key derivation constants
KEY_VERSION_CURRENT = "v1"
SALT_CONSTANT = b"AdaptiveGatewayCloudSecretSalt2026"


def _derive_encryption_key() -> bytes:
    """
    Derives a 256-bit (32-byte) key for AESGCM encryption.
    Reads CLOUD_CREDENTIAL_ENCRYPTION_KEY environment variable.
    If unset in local/dev environment, derives a deterministic machine/app key
    to avoid operational crashes, while emitting a warning.
    """
    raw_key = os.environ.get("CLOUD_CREDENTIAL_ENCRYPTION_KEY")
    if raw_key and len(raw_key.strip()) >= 32:
        return hashlib.sha256(raw_key.strip().encode("utf-8")).digest()

    fallback_seed = (
        os.environ.get("JWT_SECRET_KEY")
        or os.environ.get("SECRET_KEY")
        or "adaptive-gateway-fallback-credential-encryption-seed-2026"
    )
    if os.environ.get("ENVIRONMENT", "development").lower() == "production":
        logger.warning(
            "CLOUD_CREDENTIAL_ENCRYPTION_KEY is not configured in production. "
            "Falling back to derived environment key."
        )
    return hashlib.pbkdf2_hmac("sha256", fallback_seed.encode("utf-8"), SALT_CONSTANT, iterations=100_000)


class CredentialVaultService:
    """
    Cryptographic vault managing AES-256-GCM encryption, decryption,
    masking, and database lifecycle for cloud provider credentials.
    """

    @classmethod
    def encrypt_credentials(cls, payload: Dict[str, Any]) -> str:
        """
        Serializes payload dictionary to JSON and encrypts using AES-256-GCM with a 96-bit random nonce.
        Returns serialized format: 'enc:v1:<base64-nonce>:<base64-ciphertext-tag>'
        """
        if not payload:
            raise ValueError("Credential payload cannot be empty")

        key = _derive_encryption_key()
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
        json_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, json_bytes, None)

        b64_nonce = base64.b64encode(nonce).decode("ascii")
        b64_ct = base64.b64encode(ciphertext).decode("ascii")
        return f"enc:{KEY_VERSION_CURRENT}:{b64_nonce}:{b64_ct}"

    @classmethod
    def decrypt_credentials(cls, encrypted_blob: str) -> Dict[str, Any]:
        """
        Parses and decrypts an AES-256-GCM encrypted blob.
        Returns the original decrypted dictionary.
        """
        if not encrypted_blob or not encrypted_blob.startswith("enc:"):
            raise ValueError("Invalid encrypted credential blob format")

        parts = encrypted_blob.split(":")
        if len(parts) != 4:
            raise ValueError("Malformed encrypted blob token")

        _, version, b64_nonce, b64_ct = parts
        if version != KEY_VERSION_CURRENT:
            raise ValueError(f"Unsupported credential vault key version: '{version}'")

        nonce = base64.b64decode(b64_nonce.encode("ascii"))
        ciphertext = base64.b64decode(b64_ct.encode("ascii"))

        key = _derive_encryption_key()
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_bytes.decode("utf-8"))

    @classmethod
    def mask_credentials(cls, provider: str, creds: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produces a non-sensitive, masked representation of credentials suitable for UI display.
        Never reveals secret keys, passwords, or private key material.
        """
        masked: Dict[str, Any] = {}
        prov = provider.upper()

        for k, v in creds.items():
            val = str(v)
            k_lower = k.lower()

            if "access_key_id" in k_lower or k_lower == "key_id":
                if len(val) >= 8:
                    masked[k] = f"{val[:4]}{'•' * 8}{val[-4:]}"
                else:
                    masked[k] = "••••••••"
            elif any(s in k_lower for s in ["secret", "password", "token", "private_key", "credential"]):
                masked[k] = "••••••••••••••••"
            elif "role_arn" in k_lower:
                masked[k] = val  # Role ARNs are identifiers, not secrets
            elif "external_id" in k_lower:
                masked[k] = f"{val[:2]}••••{val[-2:]}" if len(val) >= 4 else "••••"
            elif "tenant_id" in k_lower or "subscription_id" in k_lower or "project_id" in k_lower:
                masked[k] = val  # Cloud account/tenant IDs
            elif "client_id" in k_lower:
                masked[k] = f"{val[:4]}...{val[-4:]}" if len(val) >= 8 else "••••••••"
            else:
                masked[k] = "••••••••"

        return masked

    @classmethod
    def derive_masked_identity(cls, provider: str, auth_method: str, creds: Dict[str, Any]) -> str:
        """
        Constructs a human-readable summary of the authenticated identity (e.g., 'AKIA••••••••••••1A2B' or Role ARN).
        """
        prov = provider.upper()
        if prov == "AWS":
            if "role_arn" in creds:
                role = str(creds["role_arn"])
                return role.split("/")[-1] if "/" in role else role
            if "access_key_id" in creds:
                ak = str(creds["access_key_id"])
                return f"{ak[:4]}{'•' * 8}{ak[-4:]}" if len(ak) >= 8 else "AWS-Keys"
            return "AWS-IAM-Role"

        if prov == "GCP":
            if "client_email" in creds:
                return str(creds["client_email"])
            if "workload_identity_provider" in creds:
                return "Workload-Identity-Federation"
            return "GCP-Service-Account"

        if prov == "AZURE":
            if "client_id" in creds:
                cid = str(creds["client_id"])
                return f"AppId: {cid[:4]}...{cid[-4:]}" if len(cid) >= 8 else "Azure-Service-Principal"
            return "Azure-Entra-ID"

        return f"{prov}-{auth_method}"

    # Database integration methods
    @classmethod
    def store_credentials(
        cls,
        db: Session,
        account_id: str,
        provider: str,
        auth_method: str,
        credentials: Dict[str, Any],
        masked_identity: Optional[str] = None,
    ) -> Any:
        """
        Encrypts and stores cloud credentials in the database vault.
        """
        try:
            from backend.app.models.cloud_account import CloudCredentialVaultModel
        except ImportError:
            from app.models.cloud_account import CloudCredentialVaultModel

        now = datetime.now(timezone.utc)
        encrypted_blob = cls.encrypt_credentials(credentials)
        mask_id = masked_identity or cls.derive_masked_identity(provider, auth_method, credentials)

        vault_entry = (
            db.query(CloudCredentialVaultModel)
            .filter(CloudCredentialVaultModel.account_id == account_id)
            .first()
        )

        if vault_entry is None:
            vault_entry = CloudCredentialVaultModel(
                account_id=account_id,
                provider=provider.upper(),
                auth_method=auth_method,
                encrypted_blob=encrypted_blob,
                key_version=KEY_VERSION_CURRENT,
                masked_identity=mask_id,
                created_at=now,
                updated_at=now,
            )
            db.add(vault_entry)
        else:
            vault_entry.provider = provider.upper()
            vault_entry.auth_method = auth_method
            vault_entry.encrypted_blob = encrypted_blob
            vault_entry.key_version = KEY_VERSION_CURRENT
            vault_entry.masked_identity = mask_id
            vault_entry.updated_at = now

        db.commit()
        db.refresh(vault_entry)
        return vault_entry

    @classmethod
    def get_credentials(cls, db: Session, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves and decrypts credentials for an account from the vault.
        Returns None if no credentials exist.
        """
        try:
            from backend.app.models.cloud_account import CloudCredentialVaultModel
        except ImportError:
            from app.models.cloud_account import CloudCredentialVaultModel

        entry = (
            db.query(CloudCredentialVaultModel)
            .filter(CloudCredentialVaultModel.account_id == account_id)
            .first()
        )
        if not entry:
            return None

        return cls.decrypt_credentials(entry.encrypted_blob)

    @classmethod
    def rotate_credentials(
        cls,
        db: Session,
        account_id: str,
        new_credentials: Dict[str, Any],
        new_auth_method: Optional[str] = None,
    ) -> Any:
        """
        Rotates existing credentials with a new encrypted blob and updates rotation audit timestamp.
        """
        try:
            from backend.app.models.cloud_account import CloudCredentialVaultModel
        except ImportError:
            from app.models.cloud_account import CloudCredentialVaultModel

        entry = (
            db.query(CloudCredentialVaultModel)
            .filter(CloudCredentialVaultModel.account_id == account_id)
            .first()
        )
        if not entry:
            raise ValueError(f"No credential vault entry found for account '{account_id}'")

        now = datetime.now(timezone.utc)
        auth_method = new_auth_method or entry.auth_method
        entry.encrypted_blob = cls.encrypt_credentials(new_credentials)
        entry.auth_method = auth_method
        entry.masked_identity = cls.derive_masked_identity(entry.provider, auth_method, new_credentials)
        entry.rotated_at = now
        entry.updated_at = now

        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def delete_credentials(cls, db: Session, account_id: str) -> bool:
        """
        Safely purges encrypted credentials for an account from the vault.
        """
        try:
            from backend.app.models.cloud_account import CloudCredentialVaultModel
        except ImportError:
            from app.models.cloud_account import CloudCredentialVaultModel

        entry = (
            db.query(CloudCredentialVaultModel)
            .filter(CloudCredentialVaultModel.account_id == account_id)
            .first()
        )
        if not entry:
            return False

        db.delete(entry)
        db.commit()
        return True

    @classmethod
    def get_vault_info(cls, db: Session, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns safe non-secret metadata about an account's vault entry.
        """
        try:
            from backend.app.models.cloud_account import CloudCredentialVaultModel
        except ImportError:
            from app.models.cloud_account import CloudCredentialVaultModel

        entry = (
            db.query(CloudCredentialVaultModel)
            .filter(CloudCredentialVaultModel.account_id == account_id)
            .first()
        )
        if not entry:
            return None

        return {
            "has_credentials": True,
            "auth_method": entry.auth_method,
            "masked_identity": entry.masked_identity,
            "key_version": entry.key_version,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
            "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
            "rotated_at": entry.rotated_at.isoformat() if entry.rotated_at else None,
        }
