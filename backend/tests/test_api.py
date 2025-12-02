"""
Tests for API endpoints.
"""
import pytest
from app.crud import create_user
from app.auth import get_password_hash


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_check_registration(client):
    """Test registration check endpoint."""
    response = client.post(
        "/check_registration",
        json={"email": "test@example.com", "phone": "+1234567890"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "allowed" in data
    assert "email" in data
    assert "spam_score" in data


def test_login(client, test_user):
    """Test login endpoint."""
    response = client.post(
        "/login",
        data={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_protected_endpoint(client, test_user):
    """Test that protected endpoints require authentication."""
    response = client.get("/stats")
    assert response.status_code == 401  # Unauthorized


def test_stats_with_auth(client, test_user):
    """Test stats endpoint with authentication."""
    # Login
    login_response = client.post(
        "/login",
        data={"username": "testuser", "password": "testpass"}
    )
    token = login_response.json()["access_token"]
    
    # Get stats
    response = client.get(
        "/stats",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_registrations" in data
    assert "blocked_registrations" in data

