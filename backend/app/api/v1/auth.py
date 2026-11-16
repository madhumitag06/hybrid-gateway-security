"""
Authentication and User Management REST API Endpoints
=====================================================
Exposes routes for local user registration, login, JWT token rotation,
profile inspection, password management, Google OAuth 2.0, and administrator user listing.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_active_user, require_admin
from backend.app.config import settings
from backend.app.core.rate_limit import RateLimiter
from backend.app.db.session import get_db
from backend.app.models.user import UserModel
from backend.app.repositories.user_repo import UserRepository
from backend.app.schemas.auth import (
    AdminUserCreateRequest,
    AdminUserListResponse,
    GoogleOAuthInitResponse,
    GoogleTokenExchangeRequest,
    PasswordChangeRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserResponse,
    UserSignUpRequest,
)
from backend.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Sets the refresh token as a secure HttpOnly cookie (SEC-13)."""
    response.set_cookie(
        key="hgs_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        path="/api",
        max_age=settings.auth_refresh_token_expire_days * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Clears the HttpOnly refresh token cookie on logout (SEC-13)."""
    response.delete_cookie(key="hgs_refresh_token", path="/api")
    response.delete_cookie(key="hgs_refresh_token", path="/api/v1/auth")


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RateLimiter(max_requests=5, window_seconds=60, scope="auth_signup"))],
    summary="Register a new operator account",
)
def signup(
    req: UserSignUpRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Create a new local operator user and issue an authenticated JWT token pair."""
    token_resp = AuthService.signup(req, db)
    _set_refresh_cookie(response, token_resp.refresh_token)
    return token_resp


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(RateLimiter(max_requests=10, window_seconds=60, scope="auth_login"))],
    summary="Authenticate operator credentials",
)
def login(
    req: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Verify email and password, returning access and refresh JWT tokens."""
    token_resp = AuthService.login(req, db)
    _set_refresh_cookie(response, token_resp.refresh_token)
    return token_resp


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using a valid refresh token",
)
def refresh_token(
    request: Request,
    response: Response,
    req: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db),
):
    """Rotate and issue a new JWT access/refresh token pair."""
    token_str = (req.refresh_token if req and req.refresh_token else None) or request.cookies.get("hgs_refresh_token")
    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token required in request body or HttpOnly cookie.",
        )
    token_resp = AuthService.refresh_tokens(token_str, db)
    _set_refresh_cookie(response, token_resp.refresh_token)
    return token_resp


@router.post(
    "/logout",
    summary="Revoke active refresh token",
)
def logout(
    request: Request,
    response: Response,
    req: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db),
):
    """Revoke refresh token and invalidate server session."""
    token_str = (req.refresh_token if req and req.refresh_token else None) or request.cookies.get("hgs_refresh_token")
    AuthService.logout(token_str, db)
    _clear_refresh_cookie(response)
    return {"message": "Successfully logged out.", "status": "LOGGED_OUT"}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated operator profile",
)
def get_me(current_user: UserModel = Depends(get_current_active_user)):
    """Return the profile and role details of the currently authenticated operator."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/password/change",
    summary="Change operator password",
)
def change_password(
    req: PasswordChangeRequest,
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update operator password and revoke all existing sessions."""
    AuthService.change_password(current_user.id, req, db)
    return {"message": "Password updated successfully. Please sign in with your new password."}


@router.get(
    "/google/login",
    response_model=GoogleOAuthInitResponse,
    summary="Initiate Google OAuth 2.0 / OpenID Connect authorization",
)
def google_oauth_init():
    """Returns Google authorization URL and state token if Google OAuth is configured."""
    return AuthService.init_google_oauth()


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Google OAuth 2.0 authorization code callback",
)
def google_oauth_callback(
    response: Response,
    code: str = Query(..., description="Authorization code from Google"),
    state: Optional[str] = Query(None, description="OAuth state parameter"),
    db: Session = Depends(get_db),
):
    """Exchange authorization code for verified Google identity and issue application JWT session."""
    token_resp = AuthService.handle_google_oauth_callback(code, state, db)
    _set_refresh_cookie(response, token_resp.refresh_token)
    return token_resp


@router.post(
    "/google/token",
    response_model=TokenResponse,
    summary="Direct Google ID token verification",
)
def google_token_exchange(
    req: GoogleTokenExchangeRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Verify client-side Google credential ID token and authenticate or link user account."""
    if req.id_token:
        token_resp = AuthService.handle_google_id_token(req.id_token, db)
    elif req.code:
        token_resp = AuthService.handle_google_oauth_callback(req.code, req.state, db)
    else:
        raise HTTPException(status_code=400, detail="Missing Google ID token or code.")
    _set_refresh_cookie(response, token_resp.refresh_token)
    return token_resp


@router.get(
    "/admin/users",
    response_model=AdminUserListResponse,
    summary="List all registered operator accounts (Admin only)",
)
def list_admin_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserModel = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin-only endpoint returning all registered operators and their active roles."""
    user_repo = UserRepository(db)
    users, total = user_repo.list_all(skip=skip, limit=limit)
    return AdminUserListResponse(
        total_users=total,
        users=[UserResponse.model_validate(u) for u in users],
    )


@router.post(
    "/admin/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision user account with specified role (Admin only)",
)
def create_admin_user(
    req: AdminUserCreateRequest,
    current_user: UserModel = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin-only endpoint for provisioning operators and assigning elevated roles."""
    return AuthService.admin_provision_user(req, db)
