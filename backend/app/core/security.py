"""
Security and Cryptography Utilities
===================================
Provides modern password hashing with bcrypt, JWT token creation, expiration,
and cryptographic validation.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
import bcrypt
import jwt

import uuid

from backend.app.config import settings


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with a random salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_access_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
    email: Optional[str] = None,
    role: Optional[Union[str, Any]] = None,
    **extra_claims: Any,
) -> str:
    """Create a signed short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.auth_access_token_expire_minutes)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
        "iss": "hybrid-gateway-security",
    }
    if email is not None:
        payload["email"] = email
    if role is not None:
        payload["role"] = role.value if hasattr(role, "value") else str(role)
    if claims:
        payload.update(claims)
    if extra_claims:
        payload.update(extra_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.auth_jwt_secret,
        algorithm=settings.auth_jwt_algorithm,
    )
    return encoded_jwt


def create_refresh_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
    email: Optional[str] = None,
    **extra_claims: Any,
) -> str:
    """Create a signed long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.auth_refresh_token_expire_days)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "refresh",
        "iss": "hybrid-gateway-security",
    }
    if email is not None:
        payload["email"] = email
    if claims:
        payload.update(claims)
    if extra_claims:
        payload.update(extra_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.auth_jwt_secret,
        algorithm=settings.auth_jwt_algorithm,
    )
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a signed JWT token.
    Returns decoded dictionary or None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.auth_jwt_secret,
            algorithms=[settings.auth_jwt_algorithm],
            issuer="hybrid-gateway-security",
            options={"verify_exp": True, "verify_iss": True},
        )
        return payload
    except jwt.PyJWTError:
        return None
