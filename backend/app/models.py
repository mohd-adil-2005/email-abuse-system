"""
SQLAlchemy models for the Email Abuse Detection System.
"""
from datetime import datetime
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, DateTime, Index, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Registration(Base):
    """Registration model tracking email registrations with abuse detection."""
    __tablename__ = "registrations"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone_hash = Column(String(64), nullable=False, index=True)  # SHA256 hash
    phone_normalized = Column(String(20), nullable=False)  # E.164 format
    status = Column(String(20), nullable=False, default="pending", index=True)  # approved/pending/blocked
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_temporary = Column(Boolean, default=False, nullable=False)
    spam_score = Column(Integer, default=0, nullable=False)  # 0-100
    is_flagged = Column(Boolean, default=False, nullable=False, index=True)
    detection_notes = Column(Text, nullable=True)

    # Indexes for performance
    __table_args__ = (
        Index('idx_phone_hash', 'phone_hash'),
        Index('idx_status', 'status'),
        Index('idx_flagged', 'is_flagged'),
    )


class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth-only users
    api_key = Column(String(255), nullable=True, unique=True, index=True)  # API key for programmatic access
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # OAuth2 / OIDC
    oauth_provider = Column(String(20), nullable=True, index=True)  # 'google' | 'github'
    oauth_id = Column(String(100), nullable=True, index=True)  # Provider's user ID

    # Relationship to audit logs
    audit_logs = relationship("AuditLog", back_populates="user")


class AuditLog(Base):
    """Audit log model for tracking user actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(100), nullable=False)  # e.g., "override_status", "bulk_block"
    details = Column(JSON, nullable=True)  # Flexible JSON for action details (JSONB for PostgreSQL, JSON for SQLite)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationship to user
    user = relationship("User", back_populates="audit_logs")

