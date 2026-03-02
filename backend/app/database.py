"""
Database connection and session management.
"""
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
import os
from dotenv import load_dotenv

# Load .env from backend folder (ensures OAuth credentials are found)
_backend_dir = Path(__file__).resolve().parent.parent
load_dotenv(_backend_dir / ".env.example")  # Load first (template/fallback)
load_dotenv(_backend_dir / ".env")          # Then .env overrides (user secrets)
load_dotenv()  # Also try cwd for flexibility

# Database URL from environment
# Use SQLite for easier local setup without PostgreSQL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./email_abuse.db"  # Changed to SQLite for easier setup
)

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
