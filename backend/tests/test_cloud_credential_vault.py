"""
Unit and Integration Tests for Cloud Credential Vault Service
============================================================
Validates AES-256-GCM envelope encryption, authentication tags, nonces,
secret masking, database lifecycle (store/retrieve/rotate/delete), and cascade isolation.
"""

import os
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from backend.app.cloud.services.credential_vault import (
    CredentialVaultService,
    _derive_encryption_key,
)
from backend.app.db.base import Base
from backend.app.models.cloud_account import (
    CloudAccountModel,
    CloudCredentialVaultModel,
)


@pytest.fixture
def sqlite_vault_session():
    """Provides an isolated in-memory SQLite session with CloudAccount & Vault tables created."""
    engine = sa.create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create dummy account for foreign key relation
    acc = CloudAccountModel(
        id="acc-test-aws-01",
        account_id="acc-test-aws-01",
        provider="AWS",
        display_name="Test AWS Account",
        region="us-east-1",
        status="CONFIGURED",
        enabled=True,
        capabilities={},
        metadata_json={},
    )
    session.add(acc)
    session.commit()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_encryption_key_derivation():
    """Verify deterministic 256-bit key derivation."""
    key = _derive_encryption_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_aes_gcm_encrypt_decrypt_roundtrip():
    """Verify AES-256-GCM encryption and successful decryption of payload."""
    payload = {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-west-2",
    }
    encrypted = CredentialVaultService.encrypt_credentials(payload)
    assert encrypted.startswith("enc:v1:")
    assert "AKIAIOSFODNN7EXAMPLE" not in encrypted
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in encrypted

    decrypted = CredentialVaultService.decrypt_credentials(encrypted)
    assert decrypted == payload


def test_encryption_generates_unique_nonces():
    """Verify two encryptions of identical payload yield different ciphertexts due to fresh 96-bit nonces."""
    payload = {"secret": "SuperSecret123!"}
    enc1 = CredentialVaultService.encrypt_credentials(payload)
    enc2 = CredentialVaultService.encrypt_credentials(payload)
    assert enc1 != enc2


def test_tampered_ciphertext_fails_auth():
    """Verify AES-GCM authentication tag verification rejects tampered ciphertext."""
    payload = {"secret": "CriticalSecretToken"}
    encrypted = CredentialVaultService.encrypt_credentials(payload)
    parts = encrypted.split(":")
    # Alter the last byte of ciphertext
    ct_b64 = parts[3]
    tampered_ct_b64 = ct_b64[:-2] + ("AA" if ct_b64[-2:] != "AA" else "BB")
    tampered_blob = f"{parts[0]}:{parts[1]}:{parts[2]}:{tampered_ct_b64}"

    with pytest.raises(Exception):
        CredentialVaultService.decrypt_credentials(tampered_blob)


def test_credential_masking():
    """Verify sensitive fields are safely masked for UI display."""
    aws_creds = {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "role_arn": "arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole",
        "external_id": "MySuperSecretExternalID",
    }
    masked = CredentialVaultService.mask_credentials("AWS", aws_creds)
    assert masked["access_key_id"].startswith("AKIA")
    assert masked["access_key_id"].endswith("MPLE")
    assert "•" in masked["access_key_id"]
    assert masked["secret_access_key"] == "••••••••••••••••"
    assert masked["role_arn"] == "arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole"
    assert "••••" in masked["external_id"]
    assert "MySuperSecretExternalID" not in masked["external_id"]


def test_store_and_retrieve_in_vault(sqlite_vault_session):
    """Verify storing encrypted credentials into database vault and reading back."""
    db = sqlite_vault_session
    account_id = "acc-test-aws-01"
    creds = {
        "role_arn": "arn:aws:iam::698766075180:role/ReadOnly",
        "external_id": "ExtAuth99",
    }
    entry = CredentialVaultService.store_credentials(
        db=db,
        account_id=account_id,
        provider="AWS",
        auth_method="STS_ASSUME_ROLE",
        credentials=creds,
    )
    assert entry.account_id == account_id
    assert entry.encrypted_blob.startswith("enc:v1:")

    retrieved = CredentialVaultService.get_credentials(db, account_id)
    assert retrieved == creds

    info = CredentialVaultService.get_vault_info(db, account_id)
    assert info is not None
    assert info["has_credentials"] is True
    assert info["auth_method"] == "STS_ASSUME_ROLE"


def test_rotate_credentials_in_vault(sqlite_vault_session):
    """Verify rotating credentials updates the encrypted blob and sets rotation timestamp."""
    db = sqlite_vault_session
    account_id = "acc-test-aws-01"
    initial_creds = {"access_key_id": "AKIA111111111111", "secret": "old-secret"}
    CredentialVaultService.store_credentials(
        db=db,
        account_id=account_id,
        provider="AWS",
        auth_method="ACCESS_KEYS",
        credentials=initial_creds,
    )

    new_creds = {"access_key_id": "AKIA222222222222", "secret": "new-rotated-secret"}
    updated_entry = CredentialVaultService.rotate_credentials(db, account_id, new_creds)

    assert updated_entry.rotated_at is not None
    retrieved = CredentialVaultService.get_credentials(db, account_id)
    assert retrieved == new_creds


def test_delete_credentials_from_vault(sqlite_vault_session):
    """Verify deleting credentials removes them cleanly."""
    db = sqlite_vault_session
    account_id = "acc-test-aws-01"
    CredentialVaultService.store_credentials(
        db=db,
        account_id=account_id,
        provider="AWS",
        auth_method="ACCESS_KEYS",
        credentials={"secret": "abc"},
    )
    assert CredentialVaultService.get_credentials(db, account_id) is not None

    deleted = CredentialVaultService.delete_credentials(db, account_id)
    assert deleted is True
    assert CredentialVaultService.get_credentials(db, account_id) is None
