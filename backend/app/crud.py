"""
CRUD operations for database models.
"""
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from typing import Optional, List, Tuple
from datetime import datetime

from .models import Registration, User, AuditLog
from .utils import is_temporary_email, calculate_spam_score, is_flagged_spam, hash_phone, normalize_phone


# Registration CRUD
def get_registration_by_email(db: Session, email: str) -> Optional[Registration]:
    """Get registration by email."""
    return db.query(Registration).filter(Registration.email == email).first()


def get_registration_by_id(db: Session, registration_id: int) -> Optional[Registration]:
    """Get registration by ID."""
    return db.query(Registration).filter(Registration.id == registration_id).first()


def count_registrations_by_phone(db: Session, phone_hash: str) -> int:
    """Count registrations for a phone number."""
    return db.query(Registration).filter(Registration.phone_hash == phone_hash).count()


def create_registration(
    db: Session,
    email: str,
    phone: str,
    status: str = "pending",
    detection_notes: Optional[str] = None
) -> Registration:
    """
    Create a new registration with abuse detection.
    
    Returns:
        Created registration object
    """
    phone_normalized = normalize_phone(phone)
    phone_hash_value = hash_phone(phone_normalized)
    
    # Check if temporary email
    is_temp = is_temporary_email(email)
    
    # Calculate spam score
    spam_score, calculated_notes = calculate_spam_score(email)
    is_flagged_value = is_flagged_spam(spam_score)
    
    # Combine notes if both provided
    final_notes = []
    if is_temp:
        final_notes.append("Temporary email detected")
    if calculated_notes and calculated_notes != "No issues detected":
        final_notes.append(calculated_notes)
    if detection_notes:
        final_notes.append(detection_notes)
        
    merged_notes = "; ".join(final_notes) if final_notes else "No issues detected"
    
    # Determine status
    if is_temp or status == "blocked":
        final_status = "blocked"
    elif is_flagged_value:
        final_status = status if status != "pending" else "pending"
    else:
        final_status = status
    
    registration = Registration(
        email=email,
        phone_hash=phone_hash_value,
        phone_normalized=phone_normalized,
        status=final_status,
        is_temporary=is_temp,
        spam_score=spam_score,
        is_flagged=is_flagged_value,
        detection_notes=merged_notes
    )
    
    db.add(registration)
    db.commit()
    db.refresh(registration)
    return registration


def get_registrations(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    phone_hash: Optional[str] = None,
    status: Optional[str] = None
) -> Tuple[List[Registration], int]:
    """Get paginated registrations with optional filters."""
    query = db.query(Registration)
    
    if phone_hash:
        query = query.filter(Registration.phone_hash == phone_hash)
    if status:
        query = query.filter(Registration.status == status)
    
    total = query.count()
    items = query.order_by(Registration.created_at.desc()).offset(skip).limit(limit).all()
    
    return items, total


def get_flagged_registrations(
    db: Session,
    skip: int = 0,
    limit: int = 100
) -> Tuple[List[Registration], int]:
    """Get paginated flagged registrations."""
    query = db.query(Registration).filter(Registration.is_flagged == True)
    total = query.count()
    items = query.order_by(Registration.created_at.desc()).offset(skip).limit(limit).all()
    return items, total


def update_registration_status(
    db: Session,
    registration_id: int,
    status: str,
    detection_notes: Optional[str] = None
) -> Optional[Registration]:
    """Update registration status."""
    registration = get_registration_by_id(db, registration_id)
    if not registration:
        return None
    
    registration.status = status
    if detection_notes:
        registration.detection_notes = detection_notes
    registration.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(registration)
    return registration


def update_registration_flags(
    db: Session,
    registration_id: int,
    is_temporary: Optional[bool] = None,
    is_flagged: Optional[bool] = None,
    spam_score: Optional[int] = None,
    detection_notes: Optional[str] = None,
    status: Optional[str] = None
) -> Optional[Registration]:
    """Update registration flags (spam, temporary, etc.)."""
    registration = get_registration_by_id(db, registration_id)
    if not registration:
        return None
    
    if is_temporary is not None:
        registration.is_temporary = is_temporary
        if is_temporary and status is None:
            registration.status = "blocked"
    
    if is_flagged is not None:
        registration.is_flagged = is_flagged
        if is_flagged and status is None and registration.status == "approved":
            registration.status = "pending"
    
    if spam_score is not None:
        registration.spam_score = max(0, min(100, spam_score))
        # Auto-update flagged status based on spam score
        if spam_score > 70:
            registration.is_flagged = True
        elif spam_score <= 70 and is_flagged is None:
            registration.is_flagged = False
    
    if detection_notes is not None:
        registration.detection_notes = detection_notes
    
    if status is not None:
        registration.status = status
    
    registration.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(registration)
    return registration


def bulk_update_registration_status(
    db: Session,
    registration_ids: List[int],
    status: str,
    detection_notes: Optional[str] = None
) -> int:
    """Bulk update registration statuses."""
    count = db.query(Registration).filter(
        Registration.id.in_(registration_ids)
    ).update({
        "status": status,
        "detection_notes": detection_notes,
        "updated_at": datetime.utcnow()
    }, synchronize_session=False)
    
    db.commit()
    return count


# User CRUD
def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username."""
    return db.query(User).filter(User.username == username).first()


def create_user(
    db: Session,
    username: str,
    hashed_password: str,
    is_admin: bool = False,
    api_key: Optional[str] = None
) -> User:
    """Create a new user."""
    user = User(
        username=username,
        hashed_password=hashed_password,
        is_admin=is_admin,
        api_key=api_key
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_api_key(db: Session, api_key: str) -> Optional[User]:
    """Get user by API key."""
    return db.query(User).filter(User.api_key == api_key).first()


def generate_api_key(db: Session, user_id: int) -> Optional[str]:
    """Generate and assign API key to user."""
    import secrets
    api_key = f"sk_{secrets.token_urlsafe(32)}"
    
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.api_key = api_key
        db.commit()
        db.refresh(user)
        return api_key
    return None


# Phone Number Grouping
def get_phone_registrations(
    db: Session,
    skip: int = 0,
    limit: int = 100
) -> Tuple[List[dict], int]:
    """
    Get phone numbers grouped with their associated emails.
    
    Returns:
        List of dicts with phone_hash, phone_normalized, email_count, and emails
    """
    from sqlalchemy import func
    
    # Group by phone_hash and get counts
    phone_groups = db.query(
        Registration.phone_hash,
        Registration.phone_normalized,
        func.count(Registration.id).label('email_count')
    ).group_by(
        Registration.phone_hash,
        Registration.phone_normalized
    ).order_by(func.count(Registration.id).desc()).offset(skip).limit(limit).all()
    
    total = db.query(func.count(func.distinct(Registration.phone_hash))).scalar()
    
    # Get emails for each phone
    result = []
    for phone_hash, phone_normalized, email_count in phone_groups:
        emails = db.query(Registration).filter(
            Registration.phone_hash == phone_hash
        ).order_by(Registration.created_at.desc()).all()
        
        result.append({
            "phone_hash": phone_hash,
            "phone_normalized": phone_normalized,
            "email_count": email_count,
            "emails": [
                {
                    "id": reg.id,
                    "email": reg.email,
                    "status": reg.status,
                    "is_temporary": reg.is_temporary,
                    "is_flagged": reg.is_flagged,
                    "spam_score": reg.spam_score,
                    "created_at": reg.created_at
                }
                for reg in emails
            ]
        })
    
    return result, total


def get_blocked_registrations(
    db: Session,
    skip: int = 0,
    limit: int = 100
) -> Tuple[List[dict], int]:
    """
    Get blocked phone numbers and their blocked emails.
    
    Returns:
        List of dicts with phone info and blocked emails
    """
    from sqlalchemy import func
    
    # Get blocked registrations
    blocked = db.query(Registration).filter(
        Registration.status == "blocked"
    ).order_by(Registration.created_at.desc()).offset(skip).limit(limit).all()
    
    total = db.query(Registration).filter(
        Registration.status == "blocked"
    ).count()
    
    # Group by phone_hash
    phone_dict = {}
    for reg in blocked:
        phone_hash = reg.phone_hash
        if phone_hash not in phone_dict:
            phone_dict[phone_hash] = {
                "phone_hash": phone_hash,
                "phone_normalized": reg.phone_normalized,
                "blocked_count": 0,
                "blocked_emails": []
            }
        
        phone_dict[phone_hash]["blocked_count"] += 1
        phone_dict[phone_hash]["blocked_emails"].append({
            "id": reg.id,
            "email": reg.email,
            "is_temporary": reg.is_temporary,
            "is_flagged": reg.is_flagged,
            "spam_score": reg.spam_score,
            "detection_notes": reg.detection_notes,
            "created_at": reg.created_at,
            "updated_at": reg.updated_at
        })
    
    result = list(phone_dict.values())
    return result, total


# Stats
def get_stats(db: Session) -> dict:
    """Get statistics about registrations."""
    total = db.query(Registration).count()
    blocked = db.query(Registration).filter(Registration.status == "blocked").count()
    unique_phones = db.query(func.count(func.distinct(Registration.phone_hash))).scalar()
    temporary_blocked = db.query(Registration).filter(Registration.is_temporary == True).count()
    flagged = db.query(Registration).filter(Registration.is_flagged == True).count()
    
    avg_score_result = db.query(func.avg(Registration.spam_score)).scalar()
    avg_score = float(avg_score_result) if avg_score_result else 0.0
    
    return {
        "total_registrations": total,
        "blocked_registrations": blocked,
        "unique_phones": unique_phones,
        "temporary_blocked": temporary_blocked,
        "flagged_registrations": flagged,
        "avg_spam_score": round(avg_score, 2)
    }


# Audit Log CRUD
def create_audit_log(
    db: Session,
    user_id: int,
    action: str,
    details: Optional[dict] = None
) -> AuditLog:
    """Create an audit log entry."""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        details=details
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log


def get_audit_logs(
    db: Session,
    skip: int = 0,
    limit: int = 100
) -> Tuple[List[AuditLog], int]:
    """Get paginated audit logs."""
    query = db.query(AuditLog)
    total = query.count()
    items = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return items, total

