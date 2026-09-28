"""
User and Refresh Token Repository Layer
=======================================
Database query and persistence methods for operator accounts and refresh tokens.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.app.models.user import RefreshTokenModel, UserModel


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, user_id: str) -> Optional[UserModel]:
        return self.db.get(UserModel, user_id)

    def get_by_email(self, email: str) -> Optional[UserModel]:
        normalized = email.strip().lower()
        stmt = select(UserModel).where(UserModel.email == normalized)
        return self.db.scalars(stmt).first()

    def get_by_google_id(self, google_id: str) -> Optional[UserModel]:
        stmt = select(UserModel).where(UserModel.google_subject_id == google_id)
        return self.db.scalars(stmt).first()

    def create(self, user: UserModel) -> UserModel:
        self.db.add(user)
        self.db.flush()
        return user

    def update(self, user: UserModel) -> UserModel:
        user.updated_at = datetime.now(timezone.utc)
        self.db.flush()
        return user

    def list_all(self, skip: int = 0, limit: int = 50) -> Tuple[List[UserModel], int]:
        total = self.db.scalar(select(func.count(UserModel.id))) or 0
        stmt = (
            select(UserModel)
            .order_by(desc(UserModel.created_at))
            .offset(skip)
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all()), total

    def count(self) -> int:
        return self.db.scalar(select(func.count(UserModel.id))) or 0


class RefreshTokenRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, token_model: RefreshTokenModel) -> RefreshTokenModel:
        self.db.add(token_model)
        self.db.flush()
        return token_model

    def get_valid(self, token_str: str) -> Optional[RefreshTokenModel]:
        now = datetime.now(timezone.utc)
        stmt = (
            select(RefreshTokenModel)
            .where(
                RefreshTokenModel.token == token_str,
                RefreshTokenModel.is_revoked.is_(False),
                RefreshTokenModel.expires_at > now,
            )
        )
        return self.db.scalars(stmt).first()

    def revoke(self, token_str: str) -> bool:
        stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == token_str)
        token_obj = self.db.scalars(stmt).first()
        if token_obj:
            token_obj.is_revoked = True
            self.db.flush()
            return True
        return False

    def revoke_all_for_user(self, user_id: str) -> int:
        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.user_id == user_id,
            RefreshTokenModel.is_revoked.is_(False),
        )
        tokens = list(self.db.scalars(stmt).all())
        for t in tokens:
            t.is_revoked = True
        self.db.flush()
        return len(tokens)
