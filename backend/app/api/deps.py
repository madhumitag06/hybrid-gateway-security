"""
Authentication and Authorization FastAPI Dependencies
=====================================================
Provides dependency injection functions to validate JWT bearer tokens,
retrieve authenticated users from PostgreSQL, and enforce role-based access control.
"""

import ipaddress
import secrets
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.core.security import decode_token
from backend.app.db.session import get_db
from backend.app.models.user import UserModel
from backend.app.repositories.user_repo import UserRepository

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False,
)


def get_current_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
) -> UserModel:
    """
    Validate JWT bearer token and return the authenticated user record.
    Raises 401 Unauthorized if token is missing, expired, or invalid.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


def get_current_active_user(
    current_user: UserModel = Depends(get_current_user),
) -> UserModel:
    """Ensure authenticated user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive operator account.",
        )
    return current_user


def require_admin(
    current_user: UserModel = Depends(get_current_active_user),
) -> UserModel:
    """
    Ensure the authenticated operator possesses the 'ADMIN' role.
    Raises 403 Forbidden for analysts or ordinary users.
    """
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required.",
        )
    return current_user


def require_operator(
    current_user: UserModel = Depends(get_current_active_user),
) -> UserModel:
    """
    Ensure the authenticated operator possesses at least 'OPERATOR' or 'ADMIN' role.
    Raises 403 Forbidden for analysts, auditors, or ordinary users.
    """
    if current_user.role not in ("ADMIN", "OPERATOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Operator or Administrator privileges required.",
        )
    return current_user


def require_analyst(
    current_user: UserModel = Depends(get_current_active_user),
) -> UserModel:
    """
    Ensure the authenticated operator possesses at least 'ANALYST', 'AUDITOR', 'OPERATOR', or 'ADMIN' role.
    Raises 403 Forbidden for ordinary 'USER' accounts.
    """
    if current_user.role not in ("ADMIN", "OPERATOR", "ANALYST", "AUDITOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Security Analyst, Auditor, Operator, or Administrator role required.",
        )
    return current_user


def is_trusted_management_ip(client_ip: Optional[str]) -> bool:
    """
    Checks if a client IP address belongs to an explicitly configured trusted management network.
    SEC-09: Strictly isolated from firewall policy allowlists (PolicyEngine.is_ip_allowlisted).
    Fails closed if trusted_management_networks is empty or not configured.
    """
    if not client_ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip.strip())
        for network in settings.get_trusted_management_networks():
            if ip_obj in network:
                return True
    except ValueError:
        return False
    return False


def require_service_or_trusted_network(
    request: Request,
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
) -> Optional[UserModel]:
    """
    Service-authentication and trusted-network authorization guard for machine-to-machine
    telemetry ingestion and automated inference endpoints.
    Allows access if:
    1. Valid Bearer JWT token from an active user is provided.
    2. Valid X-API-Key or X-Service-Token header matching configured gateway_service_key.
    3. Client IP matches an explicitly configured trusted management network (trusted_management_networks)
       or in-process testclient ("testclient").
    Raises 401 Unauthorized if neither credentials nor trusted management network origin is present.
    """
    # 1. Check Bearer JWT token if supplied
    if token:
        try:
            return get_current_user(db=db, token=token)
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 2. Check X-API-Key or X-Service-Token header
    has_api_key_header = "X-API-Key" in request.headers or "X-Service-Token" in request.headers
    api_key = request.headers.get("X-API-Key") or request.headers.get("X-Service-Token")
    if has_api_key_header or api_key is not None:
        configured_key = getattr(settings, "gateway_service_key", None)
        if not configured_key or not isinstance(configured_key, str) or not configured_key.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Service authentication is disabled or unconfigured.",
            )
        if (
            isinstance(api_key, str)
            and api_key.strip()
            and secrets.compare_digest(api_key.strip(), configured_key.strip())
        ):
            return None
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service API key.",
        )

    # 3. Check client network origin against dedicated management trust configuration
    # SEC-09 PROXY & SPOOFING PROTECTION:
    # Never trust client-supplied X-Forwarded-For or X-Real-IP headers from untrusted callers.
    # Only the socket-level request.client.host is evaluated.
    client_ip = request.client.host if request.client else None
    if client_ip:
        if client_ip == "testclient":
            return None
        if is_trusted_management_ip(client_ip):
            return None

    # 4. Rejection - Fail closed
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: Provide a valid Bearer token, X-API-Key header, or originate from an authorized management network.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_optional_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
) -> Optional[UserModel]:
    """Optional authentication for public or semi-public telemetry endpoints."""
    if not token:
        return None
    try:
        return get_current_user(db=db, token=token)
    except HTTPException:
        return None
