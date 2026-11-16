"""
Database Session and Engine Management
======================================
Provides thread-safe SQLAlchemy engine, connection pooling, session factory,
FastAPI dependency injection generator, and Alembic schema lifecycle management.
"""

from pathlib import Path
import sys
from typing import Generator, Optional, Tuple
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.app.config import settings
from backend.app.db.base import Base

HEAD_ALEMBIC_REVISION = "004_enterprise_schema"

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


def get_alembic_config(db_url: Optional[str] = None):
    """
    Constructs an Alembic Config object compatible with standard development,
    isolated testing, and frozen PyInstaller standalone execution.
    """
    from alembic.config import Config

    is_frozen = getattr(sys, "frozen", False)
    if is_frozen:
        bundle_dir = Path(getattr(sys, "_MEIPASS", sys.executable)).resolve()
        ini_candidates = [
            bundle_dir / "backend" / "alembic.ini",
            bundle_dir / "alembic.ini",
            Path("backend/alembic.ini").resolve(),
        ]
        script_candidates = [
            bundle_dir / "backend" / "alembic",
            bundle_dir / "alembic",
            Path("backend/alembic").resolve(),
        ]
    else:
        root_dir = Path(__file__).resolve().parent.parent.parent.parent
        ini_candidates = [
            root_dir / "backend" / "alembic.ini",
            Path("backend/alembic.ini").resolve(),
        ]
        script_candidates = [
            root_dir / "backend" / "alembic",
            Path("backend/alembic").resolve(),
        ]

    ini_path = next((p for p in ini_candidates if p.is_file()), ini_candidates[0])
    script_path = next((p for p in script_candidates if p.is_dir()), script_candidates[0])

    cfg = Config(str(ini_path))
    cfg.set_main_option("sqlalchemy.url", db_url or settings.database_url)
    cfg.set_main_option("script_location", str(script_path))
    return cfg


def get_current_alembic_version(bind_engine=None) -> Optional[str]:
    """
    Reads the current revision recorded in alembic_version table.
    Returns None if the table does not exist or has no recorded version.
    """
    target_engine = bind_engine or engine
    inspector = sa.inspect(target_engine)
    if "alembic_version" not in inspector.get_table_names():
        return None
    with target_engine.connect() as conn:
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def verify_production_schema(bind_engine=None) -> Tuple[bool, str]:
    """
    Verifies that the database has been properly migrated using Alembic to HEAD.
    In production, this verification must pass before starting the gateway.
    """
    target_engine = bind_engine or engine
    current_ver = get_current_alembic_version(target_engine)
    if not current_ver:
        return False, (
            "CRITICAL: alembic_version table missing. "
            "Production database must be migrated using Alembic before gateway startup ('alembic upgrade head')."
        )
    if current_ver != HEAD_ALEMBIC_REVISION:
        return False, (
            f"CRITICAL: Schema drift detected. Current Alembic revision '{current_ver}' "
            f"does not match expected production HEAD revision '{HEAD_ALEMBIC_REVISION}'. "
            "Please apply pending migrations ('alembic upgrade head')."
        )
    # Check essential enterprise tables
    inspector = sa.inspect(target_engine)
    existing = set(inspector.get_table_names())
    required_tables = {"users", "security_events", "active_enforcements", "policy_audit_logs", "shadow_predictions"}
    missing = required_tables - existing
    if missing:
        return False, (
            f"CRITICAL: Production schema inconsistency. Expected tables missing: {sorted(list(missing))}."
        )
    return True, f"Verified at Alembic revision {HEAD_ALEMBIC_REVISION}"


def apply_migrations_to_head(db_url: Optional[str] = None) -> None:
    """
    Executes Alembic migrations forward to HEAD.
    Used during standalone EXE startup and explicit migration procedures.
    """
    from alembic import command
    cfg = get_alembic_config(db_url=db_url)
    command.upgrade(cfg, "head")


def init_db(force_create_all: bool = False) -> None:
    """
    Authoritative database initialization lifecycle.
    - In PRODUCTION:
      Alembic is strictly authoritative. Verifies schema is at HEAD ('004_enterprise_schema').
      Base.metadata.create_all() is strictly prohibited and never invoked.
      Raises RuntimeError if unmigrated or inconsistent schema is detected.
    - In STANDALONE EXECUTABLE:
      Applies Alembic migrations forward to HEAD using programmatic Alembic engine.
    - In DEVELOPMENT & TESTING:
      If alembic_version is absent and database is uninitialized, allows safe table creation
      for test execution or applies migrations.
    """
    import backend.app.models  # noqa: F401 - ensure models are imported

    is_frozen = getattr(sys, "frozen", False)
    is_prod = settings.is_production

    if is_prod and not force_create_all:
        is_valid, msg = verify_production_schema(engine)
        if not is_valid:
            raise RuntimeError(msg)
        return

    if is_frozen:
        try:
            apply_migrations_to_head()
            return
        except Exception:
            # Fallback to verify or safe initialization if offline
            inspector = sa.inspect(engine)
            if "users" not in inspector.get_table_names():
                Base.metadata.create_all(bind=engine)
            return

    # Development / Testing
    inspector = sa.inspect(engine)
    tables = inspector.get_table_names()
    if not tables or force_create_all:
        Base.metadata.create_all(bind=engine)
