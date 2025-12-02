"""
Pydantic schemas for request/response validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, field_validator


# Registration Schemas
class RegistrationCheckRequest(BaseModel):
    """Request schema for checking a registration."""
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=20)

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        """Normalize phone number (remove non-digits, ensure starts with +)."""
        digits = ''.join(filter(str.isdigit, v))
        if not digits:
            raise ValueError("Phone must contain digits")
        if not v.startswith('+'):
            digits = '+' + digits
        return digits


class RegistrationCheckResponse(BaseModel):
    """Response schema for registration check."""
    allowed: bool
    email: str
    phone_hash: str
    status: str
    is_temporary: bool
    spam_score: int
    is_flagged: bool
    detection_notes: Optional[str] = None
    message: str
    registration_id: Optional[int] = None  # Added for easy lookup


class RegistrationResponse(BaseModel):
    """Response schema for registration details."""
    id: int
    email: str
    phone_hash: str
    phone_normalized: str
    status: str
    created_at: datetime
    updated_at: datetime
    is_temporary: bool
    spam_score: int
    is_flagged: bool
    detection_notes: Optional[str] = None

    class Config:
        from_attributes = True


class RegistrationListResponse(BaseModel):
    """Paginated list of registrations."""
    items: List[RegistrationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Authentication Schemas
class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """User response schema."""
    id: int
    username: str
    is_admin: bool
    has_api_key: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyResponse(BaseModel):
    """API key response schema."""
    api_key: str
    message: str


# Override Schemas
class OverrideRequest(BaseModel):
    """Request to override registration status."""
    registration_id: int
    status: str = Field(..., pattern="^(approved|pending|blocked)$")
    reason: str = Field(..., min_length=5, max_length=500)


class OverrideResponse(BaseModel):
    """Response for override action."""
    success: bool
    registration: RegistrationResponse
    message: str


class ManualUpdateRequest(BaseModel):
    """Request to manually update registration flags."""
    registration_id: int
    is_temporary: Optional[bool] = None
    is_flagged: Optional[bool] = None
    spam_score: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[str] = Field(None, pattern="^(approved|pending|blocked)$")
    detection_notes: Optional[str] = Field(None, max_length=1000)
    reason: str = Field(..., min_length=5, max_length=500)


class ManualUpdateResponse(BaseModel):
    """Response for manual update."""
    success: bool
    registration: RegistrationResponse
    message: str


# Stats Schemas
class StatsResponse(BaseModel):
    """Statistics response."""
    total_registrations: int
    blocked_registrations: int
    unique_phones: int
    temporary_blocked: int
    flagged_registrations: int
    avg_spam_score: float


# Flagged Registrations
class FlaggedListResponse(BaseModel):
    """Paginated list of flagged registrations."""
    items: List[RegistrationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Bulk Operations
class BulkBlockRequest(BaseModel):
    """Request to bulk block registrations."""
    registration_ids: List[int] = Field(..., min_items=1)
    reason: str = Field(..., min_length=5, max_length=500)


class BulkBlockResponse(BaseModel):
    """Response for bulk block action."""
    success: bool
    blocked_count: int
    message: str


class BulkRegistrationRequest(BaseModel):
    """Request to bulk import registrations."""
    registrations: List[RegistrationCheckRequest] = Field(..., min_items=1, max_items=1000)
    skip_rate_limit: bool = False  # Admin only


class BulkRegistrationResult(BaseModel):
    """Result for a single registration in bulk import."""
    email: str
    phone: str
    success: bool
    allowed: bool
    status: str
    message: str
    registration_id: Optional[int] = None
    error: Optional[str] = None


class BulkRegistrationResponse(BaseModel):
    """Response for bulk registration import."""
    success: bool
    total: int
    successful: int
    failed: int
    results: List[BulkRegistrationResult]
    processing_time_seconds: float


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    """Audit log response schema."""
    id: int
    user_id: int
    username: str
    action: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    """Paginated list of audit logs."""
    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

