"""
Authentication & User Account Pydantic Schemas
==============================================
Defines request and response schemas for user registration, authentication,
JWT token pairs, profile inspection, password change, and Google OAuth flow.
"""

from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator

UserRole = Literal["ADMIN", "ANALYST", "USER"]
AuthProvider = Literal["LOCAL", "GOOGLE"]


class UserSignUpRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of operator")
    email: str = Field(..., min_length=3, max_length=255, description="Unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Plaintext password (min 8 chars)")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")
    role: Optional[UserRole] = "ANALYST"

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if "@" not in clean or len(clean.split("@")) != 2 or not clean.split("@")[0] or not clean.split("@")[1]:
            raise ValueError("Invalid email format")
        return clean

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if info.data and "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class UserLoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, description="Registered email address")
    password: str = Field(..., min_length=1, description="Account password")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if "@" not in clean or len(clean.split("@")) != 2 or not clean.split("@")[0] or not clean.split("@")[1]:
            raise ValueError("Invalid email format")
        return clean


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    auth_provider: AuthProvider
    is_active: bool
    is_verified: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Signed refresh token string")


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Existing password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password (min 8 chars)")
    confirm_new_password: str = Field(..., min_length=8, max_length=128, description="Confirmation of new password")

    @field_validator("confirm_new_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("New passwords do not match")
        return v


class GoogleOAuthInitResponse(BaseModel):
    enabled: bool
    client_id_configured: bool = False
    auth_url: Optional[str] = None
    authorization_url: Optional[str] = None
    state: Optional[str] = None
    message: Optional[str] = None


class GoogleTokenExchangeRequest(BaseModel):
    id_token: Optional[str] = None
    code: Optional[str] = None
    state: Optional[str] = None


class AdminUserListResponse(BaseModel):
    total_users: int
    users: List[UserResponse]
