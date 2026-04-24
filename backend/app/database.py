"""
Database connection and session management.
"""
import logging
from pathlib import Path
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, Session
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load .env from backend folder (ensures OAuth credentials are found)
_backend_dir = Path(__file__).resolve().parent.parent
load_dotenv(_backend_dir / ".env.example", override=False)  # Template/fallback values
load_dotenv(_backend_dir / ".env", override=True)           # Real local secrets/config
load_dotenv(override=True)  # Also try cwd and allow explicit env overrides

# Database URL from environment
# Use DATABASE_URL for selecting backend DB (SQLite or PostgreSQL).
# For production/deployment, set DATABASE_URL to PostgreSQL.
def _normalize_database_url(raw: str | None) -> str:
    """Strip accidental quotes/whitespace/newlines from ECS/console paste mistakes."""
    if raw is None:
        return "sqlite:///./email_abuse.db"
    s = raw.strip().strip('"').strip("'").replace("\n", "").replace("\r", "")
    return s if s else "sqlite:///./email_abuse.db"


def _coerce_database_url(raw: str | None) -> str:
    """
    Normalize + validate SQLAlchemy URL. If invalid (common ECS paste mistakes),
    fall back to SQLite so the API can still boot; log loudly so it can be fixed.
    """
    url = _normalize_database_url(raw)
    # Prefer explicit psycopg2 driver for Postgres (matches requirements.txt).
    if url.startswith("postgresql://") and "+psycopg" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    if url.startswith("sqlite"):
        return url
    try:
        make_url(url)
        return url
    except Exception as e:
        logger.error(
            "Invalid DATABASE_URL (SQLAlchemy cannot parse it). Using SQLite fallback. "
            "Fix: paste Neon URL as one line with no quotes; if UI breaks on '&', "
            "store URL in Secrets Manager or use ?sslmode=require only. Error: %s",
            e,
        )
        return "sqlite:///./email_abuse.db"


DATABASE_URL = _coerce_database_url(os.getenv("DATABASE_URL"))

# Create engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode and optimize SQLite for better concurrent performance."""
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
        cursor.close()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def ensure_multi_tenant_columns() -> None:
    """Add tenant columns for existing databases if they are missing."""
    try:
        inspector = inspect(engine)
        user_cols = {col["name"] for col in inspector.get_columns("users")} if "users" in inspector.get_table_names() else set()
        reg_cols = {col["name"] for col in inspector.get_columns("registrations")} if "registrations" in inspector.get_table_names() else set()
        with engine.begin() as conn:
            if "organization_id" not in user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN organization_id VARCHAR(100)"))
            if "owner_user_id" not in reg_cols:
                conn.execute(text("ALTER TABLE registrations ADD COLUMN owner_user_id INTEGER"))
            if "organization_id" not in reg_cols:
                conn.execute(text("ALTER TABLE registrations ADD COLUMN organization_id VARCHAR(100)"))
    except Exception as e:
        logger.warning("Tenant schema auto-migration skipped: %s", e)


def get_db() -> Session:
    """
    Dependency for getting database session.
    
    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
