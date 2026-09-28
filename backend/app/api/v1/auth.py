"""
Authentication and User Management REST API Endpoints
=====================================================
Exposes routes for local user registration, login, JWT token rotation,
profile inspection, password management, Google OAuth 2.0, and administrator user listing.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_active_user, require_admin
from backend.app.db.session import get_db
from backend.app.models.user import UserModel
from backend.app.repositories.user_repo import UserRepository
from backend.app.schemas.auth import (
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


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new operator account",
)
def signup(req: UserSignUpRequest, db: Session = Depends(get_db)):
    """Create a new local operator user and issue an authenticated JWT token pair."""
    return AuthService.signup(req, db)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate operator credentials",
)
def login(req: UserLoginRequest, db: Session = Depends(get_db)):
    """Verify email and password, returning access and refresh JWT tokens."""
    return AuthService.login(req, db)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using a valid refresh token",
)
def refresh_token(req: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Rotate and issue a new JWT access/refresh token pair."""
    return AuthService.refresh_tokens(req.refresh_token, db)


@router.post(
    "/logout",
    summary="Revoke active refresh token",
)
def logout(
    req: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db),
):
    """Revoke refresh token and invalidate server session."""
    token_str = req.refresh_token if req else None
    AuthService.logout(token_str, db)
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
    code: str = Query(..., description="Authorization code from Google"),
    state: Optional[str] = Query(None, description="OAuth state parameter"),
    db: Session = Depends(get_db),
):
    """Exchange authorization code for verified Google identity and issue application JWT session."""
    return AuthService.handle_google_oauth_callback(code, state, db)


@router.post(
    "/google/token",
    response_model=TokenResponse,
    summary="Direct Google ID token verification",
)
def google_token_exchange(
    req: GoogleTokenExchangeRequest,
    db: Session = Depends(get_db),
):
    """Verify client-side Google credential ID token and authenticate or link user account."""
    if req.id_token:
        return AuthService.handle_google_id_token(req.id_token, db)
    elif req.code:
        return AuthService.handle_google_oauth_callback(req.code, req.state, db)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Missing Google ID token or code.")


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
