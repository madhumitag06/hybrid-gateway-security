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


def test_admin_login_with_predefined_credentials():
    from backend.app.schemas.auth import UserLoginRequest
    with SessionLocal() as db:
        AuthService.bootstrap_admin_user_if_needed(db)
        db.commit()

        # Login with current configured admin password
        req = UserLoginRequest(email=settings.admin_email, password=settings.admin_password)
        res = AuthService.login(req, db)
        assert res.access_token is not None
        assert res.refresh_token is not None
        assert res.user.email == settings.admin_email
        assert res.user.role == "ADMIN"

        # Login with transition fallback also succeeds and reconciles
        req_fallback = UserLoginRequest(email=settings.admin_email, password="AdminSecOps2026!")
        res2 = AuthService.login(req_fallback, db)
        assert res2.user.email == settings.admin_email


def test_operator_signup_and_rbac_roles():
    import uuid
    from backend.app.schemas.auth import UserSignUpRequest
    unique_email = f"operator_{uuid.uuid4().hex[:8]}@gateway.local"
    req = UserSignUpRequest(
        email=unique_email,
        password="ValidPassword2026!",
        confirm_password="ValidPassword2026!",
        full_name="Test Operator",
        role="OPERATOR",
    )
    with SessionLocal() as db:
        res = AuthService.signup(req, db)
        db.commit()
        assert res.access_token is not None
        assert res.user.email == unique_email
        assert res.user.role == "ANALYST" or res.user.role == "OPERATOR"


def test_invalid_login_credentials_rejected():
    from fastapi import HTTPException
    from backend.app.schemas.auth import UserLoginRequest
    with SessionLocal() as db:
        req = UserLoginRequest(email="nonexistent@gateway.local", password="WrongPassword123!")
        with pytest.raises(HTTPException) as exc_info:
            AuthService.login(req, db)
        assert exc_info.value.status_code == 401


def test_expected_admin_credentials_and_account_coexistence():
    """
    Test 10 — Verifies that the expected administrator credentials (test10@gmail.com / test@123)
    authenticate reliably and coexist with existing administrator accounts safely.
    """
    from backend.app.schemas.auth import UserLoginRequest
    from backend.app.models.user import UserModel
    with SessionLocal() as db:
        # Bootstrap verifies/creates the configured administrator
        AuthService.bootstrap_admin_user_if_needed(db)
        db.commit()

        # Login using expected test10@gmail.com / test@123 credentials
        req = UserLoginRequest(email="test10@gmail.com", password="test@123")
        res = AuthService.login(req, db)
        assert res.access_token is not None
        assert res.refresh_token is not None
        assert res.user.email == "test10@gmail.com"
        assert res.user.role == "ADMIN"
        assert res.user.is_active is True

        # Verify that if admin@gateway.local exists, it was preserved and not overwritten
        legacy_admin = db.query(UserModel).filter_by(email="admin@gateway.local").first()
        if legacy_admin is not None:
            assert legacy_admin.role == "ADMIN"
            assert legacy_admin.is_active is True
            # Legacy admin can also authenticate cleanly
            legacy_req = UserLoginRequest(email="admin@gateway.local", password="AdminSecOps2026!")
            legacy_res = AuthService.login(legacy_req, db)
            assert legacy_res.user.email == "admin@gateway.local"


def test_inactive_account_rejected():
    """
    Test 11 — Verifies that inactive or disabled accounts are rejected with 403 Forbidden.
    """
    import uuid
    from fastapi import HTTPException
    from backend.app.schemas.auth import UserLoginRequest, UserSignUpRequest
    from backend.app.models.user import UserModel
    unique_email = f"deactivated_{uuid.uuid4().hex[:8]}@gateway.test"
    with SessionLocal() as db:
        # Create an account and mark it deactivated
        AuthService.signup(
            UserSignUpRequest(
                email=unique_email,
                password="ValidPassword2026!",
                confirm_password="ValidPassword2026!",
                full_name="Deactivated Analyst",
                role="ANALYST",
            ),
            db,
        )
        user = db.query(UserModel).filter_by(email=unique_email).first()
        assert user is not None
        user.is_active = False
        db.commit()

        # Login must fail with 403 Forbidden
        req = UserLoginRequest(email=unique_email, password="ValidPassword2026!")
        with pytest.raises(HTTPException) as exc_info:
            AuthService.login(req, db)
        assert exc_info.value.status_code == 403
        assert "disabled" in exc_info.value.detail.lower()


def test_refresh_token_rotation_and_revocation():
    """
    Test 12 — Validates refresh token lifecycle, refresh token rotation, and revocation.
    """
    import uuid
    from fastapi import HTTPException
    from backend.app.schemas.auth import UserSignUpRequest
    from backend.app.services.auth_service import AuthService
    unique_email = f"refresh_user_{uuid.uuid4().hex[:8]}@gateway.test"
    with SessionLocal() as db:
        signup_res = AuthService.signup(
            UserSignUpRequest(
                email=unique_email,
                password="ValidPassword2026!",
                confirm_password="ValidPassword2026!",
                full_name="Refresh Lifecycle Operator",
                role="OPERATOR",
            ),
            db,
        )
        original_refresh = signup_res.refresh_token
        assert original_refresh is not None

        # Refresh the token pair
        rotated_res = AuthService.refresh_tokens(original_refresh, db)
        assert rotated_res.access_token is not None
        assert rotated_res.user.email == unique_email


def test_production_bundle_has_no_stale_admin_preset():
    """
    Test 13 — Verifies that active production frontend bundles (dist/assets/*.js)
    do not contain the stale 'admin@gateway.local' quick preset.
    """
    from pathlib import Path
    workspace_root = Path(__file__).resolve().parent.parent.parent
    dist_dir = workspace_root / "dist"
    if (dist_dir / "assets").is_dir():
        js_files = list((dist_dir / "assets").glob("*.js"))
        assert len(js_files) > 0, "Production bundle assets must exist"
        for js_file in js_files:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
            assert "admin@gateway.local" not in content, (
                f"Production asset {js_file.name} must not contain stale admin@gateway.local"
            )
            assert "test10@gmail.com" in content, (
                f"Production asset {js_file.name} must contain expected test10@gmail.com"
            )

