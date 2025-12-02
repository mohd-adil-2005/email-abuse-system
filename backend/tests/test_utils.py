"""
Tests for utility functions.
"""
import pytest
from app.utils import (
    hash_phone, normalize_phone, is_temporary_email,
    calculate_spam_score, is_flagged_spam, calculate_entropy
)


def test_hash_phone():
    """Test phone hashing."""
    phone = "+1234567890"
    hash1 = hash_phone(phone)
    hash2 = hash_phone(phone)
    
    # Same input should produce same hash
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 produces 64 char hex


def test_normalize_phone():
    """Test phone normalization."""
    assert normalize_phone("1234567890") == "+1234567890"
    assert normalize_phone("+1234567890") == "+1234567890"
    assert normalize_phone("(123) 456-7890") == "+1234567890"


def test_calculate_entropy():
    """Test entropy calculation."""
    # Random string should have high entropy
    random_str = "x7k9m2p4q1w8"
    entropy_random = calculate_entropy(random_str)
    
    # Repetitive string should have low entropy
    repetitive_str = "aaaaaa"
    entropy_repetitive = calculate_entropy(repetitive_str)
    
    assert entropy_random > entropy_repetitive


def test_calculate_spam_score():
    """Test spam score calculation."""
    # High entropy email
    score1, notes1 = calculate_spam_score("x7k9m2p4q1w8@example.com")
    assert score1 >= 0
    assert score1 <= 100
    
    # Email with keyword
    score2, notes2 = calculate_spam_score("spamtest@example.com")
    assert score2 >= 0
    assert score2 <= 100
    
    # Normal email
    score3, notes3 = calculate_spam_score("john.doe@example.com")
    assert score3 >= 0
    assert score3 <= 100


def test_is_flagged_spam():
    """Test spam flagging logic."""
    assert is_flagged_spam(71) == True
    assert is_flagged_spam(70) == False
    assert is_flagged_spam(50) == False

