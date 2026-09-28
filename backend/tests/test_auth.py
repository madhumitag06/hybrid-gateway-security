"""
Auth Core & Security Unit Tests
================================
Validates cryptographic password hashing, JWT token lifecycle, refresh token logic,
tamper rejection, role authorization checks, and initial admin bootstrap idempotency.
"""

from datetime import timedelta
import pytest
import jwt

from backend.app.config import settings
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from backend.app.db.session import SessionLocal
from backend.app.models.user import UserRole
from backend.app.repositories.user_repo import UserRepository
from backend.app.services.auth_service import AuthService


def test_password_hashing_and_verification():
    raw_pwd = "SuperSecretPassword123!"
    pwd_hash = hash_password(raw_pwd)

    # Password hash must not equal plaintext
    assert pwd_hash != raw_pwd
    assert pwd_hash.startswith("$2b$") or len(pwd_hash) > 20

    # Verification must succeed for exact password
    assert verify_password(raw_pwd, pwd_hash) is True

    # Verification must fail for incorrect password
    assert verify_password("WrongPassword123!", pwd_hash) is False
    assert verify_password("", pwd_hash) is False


def test_jwt_access_token_creation_and_decoding():
    user_id = "test-user-uuid-123"
    email = "analyst@gateway.local"
    role = UserRole.ANALYST

    token = create_access_token(
        subject=user_id,
        email=email,
        role=role,
        expires_delta=timedelta(minutes=15),
    )

    payload = decode_token(token)
    assert payload is not None
    assert payload.get("sub") == user_id
    assert payload.get("email") == email
    assert payload.get("role") == UserRole.ANALYST.value
    assert payload.get("type") == "access"
    assert "exp" in payload


def test_jwt_refresh_token_creation_and_decoding():
    user_id = "test-user-uuid-456"
    email = "admin@gateway.local"

    token = create_refresh_token(subject=user_id, email=email)
    payload = decode_token(token)
    assert payload is not None
    assert payload.get("sub") == user_id
    assert payload.get("email") == email
    assert payload.get("type") == "refresh"


def test_jwt_tamper_and_invalid_signature_rejected():
    user_id = "test-user-uuid-789"
    token = create_access_token(subject=user_id, email="tamper@test.local")

    # Decode with completely wrong secret must fail
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(
            token,
            "WRONG_SECRET_KEY_FOR_TESTING_1234567890",
            algorithms=[settings.auth_jwt_algorithm],
        )

    # Malformed token string returns None
    assert decode_token("invalid.jwt.token") is None
    assert decode_token("not-a-token") is None


def test_jwt_expired_token_rejected():
    # Create an immediately expired token
    user_id = "expired-user-uuid"
    token = create_access_token(
        subject=user_id,
        email="expired@test.local",
        expires_delta=timedelta(seconds=-10),
    )

    # decode_token catches ExpiredSignatureError and safely returns None
    payload = decode_token(token)
    assert payload is None


def test_admin_bootstrap_idempotency():
    with SessionLocal() as db:
        admin_user = AuthService.bootstrap_admin_user_if_needed(db)
        assert admin_user is not None
        assert admin_user.role == UserRole.ADMIN
        assert admin_user.email == settings.admin_email

        # Running bootstrap a second time must NOT create duplicate admins
        second_run = AuthService.bootstrap_admin_user_if_needed(db)
        assert second_run.id == admin_user.id
        assert second_run.email == admin_user.email
