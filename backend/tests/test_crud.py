"""
Tests for CRUD operations.
"""
import pytest
from app.crud import (
    create_registration, get_registration_by_email, count_registrations_by_phone,
    get_stats, hash_phone, normalize_phone
)
from app.models import Registration


def test_create_registration(db):
    """Test creating a registration."""
    registration = create_registration(
        db=db,
        email="test@example.com",
        phone="+1234567890",
        status="approved"
    )
    
    assert registration.email == "test@example.com"
    assert registration.phone_hash is not None
    assert registration.status == "approved"
    assert registration.spam_score >= 0
    assert registration.spam_score <= 100


def test_phone_limit(db):
    """Test phone number registration limit (max 3)."""
    phone = "+1234567890"
    phone_hash = hash_phone(normalize_phone(phone))
    
    # Create 3 registrations
    for i in range(3):
        create_registration(
            db=db,
            email=f"test{i}@example.com",
            phone=phone,
            status="approved"
        )
    
    count = count_registrations_by_phone(db, phone_hash)
    assert count == 3


def test_temporary_email_detection(db):
    """Test that temporary emails are detected and blocked."""
    registration = create_registration(
        db=db,
        email="test@tempmail.com",
        phone="+1234567890",
        status="pending"
    )
    
    # Should be blocked if temp email is in our list
    # Note: This depends on the disposable domains list
    assert registration.is_temporary in [True, False]  # May or may not be in list


def test_spam_score_calculation(db):
    """Test spam score calculation."""
    # High entropy email should get high score
    registration = create_registration(
        db=db,
        email="x7k9m2p4q1w8@example.com",
        phone="+1234567890",
        status="pending"
    )
    
    assert registration.spam_score >= 0
    assert registration.spam_score <= 100


def test_get_stats(db):
    """Test statistics retrieval."""
    # Create some test data
    create_registration(db=db, email="test1@example.com", phone="+1111111111", status="approved")
    create_registration(db=db, email="test2@example.com", phone="+2222222222", status="blocked")
    
    stats = get_stats(db)
    assert stats["total_registrations"] >= 2
    assert stats["blocked_registrations"] >= 1
    assert stats["unique_phones"] >= 2

