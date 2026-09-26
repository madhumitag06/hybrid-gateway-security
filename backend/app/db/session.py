"""
Database Session and Engine Management
======================================
Provides thread-safe SQLAlchemy engine, connection pooling, session factory,
and FastAPI dependency injection generator.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.app.config import settings
from backend.app.db.base import Base

# Determine engine parameters based on database dialect
is_sqlite = settings.database_url.startswith("sqlite")

engine_kwargs = {
    "echo": settings.db_echo,
}

if not is_sqlite:
    engine_kwargs.update({
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_pre_ping": True,
    })
else:
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding an isolated database session per request.
    Automatically commits on success or rolls back on exception.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """
    Safely ensure all declarative tables exist in the database.
    """
    import backend.app.models  # noqa: F401 - ensure models are imported
    Base.metadata.create_all(bind=engine)
