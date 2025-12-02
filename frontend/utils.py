"""
API helper functions for Streamlit dashboard.
"""
import requests
import os
from typing import Optional, Dict, Any
import streamlit as st

# Backend API URL
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


def get_auth_headers() -> Dict[str, str]:
    """
    Get authorization headers from session state.
    
    Returns:
        Headers dict with Bearer token if available
    """
    if "access_token" in st.session_state:
        return {"Authorization": f"Bearer {st.session_state.access_token}"}
    return {}


def login(username: str, password: str) -> Optional[str]:
    """
    Login and store token in session state.
    
    Args:
        username: Username
        password: Password
        
    Returns:
        Error message if login fails, None if successful
    """
    try:
        response = requests.post(
            f"{API_BASE_URL}/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            st.session_state.access_token = data["access_token"]
            st.session_state.username = username
            return None
        else:
            return response.json().get("detail", "Login failed")
    except Exception as e:
        return f"Connection error: {str(e)}"


def logout():
    """Clear session state."""
    if "access_token" in st.session_state:
        del st.session_state.access_token
    if "username" in st.session_state:
        del st.session_state.username


def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return "access_token" in st.session_state


def api_get(endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
    """
    Make authenticated GET request to API.
    
    Args:
        endpoint: API endpoint (without base URL)
        params: Query parameters
        
    Returns:
        JSON response or None if error
    """
    try:
        headers = get_auth_headers()
        response = requests.get(
            f"{API_BASE_URL}{endpoint}",
            headers=headers,
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            # Authentication error - clear session
            if "access_token" in st.session_state:
                del st.session_state.access_token
            if "username" in st.session_state:
                del st.session_state.username
            st.error("Session expired. Please login again.")
            st.rerun()
            return None
        else:
            # Try to get error details from response
            try:
                error_detail = response.json().get("detail", response.text)
            except:
                error_detail = response.text
            st.error(f"API Error: {response.status_code} - {error_detail}")
            return None
    except requests.exceptions.ConnectionError:
        st.error(f"❌ Cannot connect to backend API at {API_BASE_URL}. Make sure the backend server is running.")
        return None
    except requests.exceptions.Timeout:
        st.error("⏱️ Request timed out. The backend server may be slow or unavailable.")
        return None
    except Exception as e:
        st.error(f"Connection error: {str(e)}")
        return None


def api_post(endpoint: str, json_data: Dict[str, Any]) -> Optional[Dict]:
    """
    Make authenticated POST request to API.
    
    Args:
        endpoint: API endpoint (without base URL)
        json_data: JSON payload
        
    Returns:
        JSON response or None if error
    """
    try:
        response = requests.post(
            f"{API_BASE_URL}{endpoint}",
            headers={**get_auth_headers(), "Content-Type": "application/json"},
            json=json_data,
            timeout=10
        )
        if response.status_code in [200, 201]:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        st.error(f"Connection error: {str(e)}")
        return None


def get_stats() -> Optional[Dict]:
    """Get statistics."""
    try:
        result = api_get("/stats")
        # Return default stats if None to prevent errors
        if result is None:
            return {
                "total_registrations": 0,
                "blocked_registrations": 0,
                "unique_phones": 0,
                "temporary_blocked": 0,
                "flagged_registrations": 0,
                "avg_spam_score": 0.0
            }
        return result
    except Exception as e:
        st.error(f"Error fetching statistics: {str(e)}")
        return {
            "total_registrations": 0,
            "blocked_registrations": 0,
            "unique_phones": 0,
            "temporary_blocked": 0,
            "flagged_registrations": 0,
            "avg_spam_score": 0.0
        }


def get_registrations(page: int = 1, page_size: int = 50, phone_hash: str = None, status: str = None) -> Optional[Dict]:
    """Get paginated registrations."""
    params = {"page": page, "page_size": page_size}
    if phone_hash:
        params["phone_hash"] = phone_hash
    if status:
        params["status"] = status
    return api_get("/registrations", params=params)


def get_flagged_registrations(page: int = 1, page_size: int = 50) -> Optional[Dict]:
    """Get paginated flagged registrations."""
    try:
        params = {"page": page, "page_size": page_size}
        result = api_get("/flagged", params=params)
        # Return empty result if None to prevent errors
        if result is None:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}
        return result
    except Exception as e:
        st.error(f"Error fetching flagged registrations: {str(e)}")
        return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}


def override_registration(registration_id: int, status: str, reason: str) -> Optional[Dict]:
    """Override registration status."""
    return api_post("/override", {
        "registration_id": registration_id,
        "status": status,
        "reason": reason
    })


def bulk_block_registrations(registration_ids: list, reason: str) -> Optional[Dict]:
    """Bulk block registrations."""
    return api_post("/bulk_block", {
        "registration_ids": registration_ids,
        "reason": reason
    })


def get_audit_logs(page: int = 1, page_size: int = 50) -> Optional[Dict]:
    """Get paginated audit logs."""
    params = {"page": page, "page_size": page_size}
    return api_get("/audit_logs", params=params)


def get_phone_registrations(page: int = 1, page_size: int = 50) -> Optional[Dict]:
    """Get phone numbers with their associated emails."""
    try:
        params = {"page": page, "page_size": page_size}
        result = api_get("/phone-registrations", params=params)
        if result is None:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}
        return result
    except Exception as e:
        st.error(f"Error fetching phone registrations: {str(e)}")
        return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}


def get_blocked_registrations_list(page: int = 1, page_size: int = 50) -> Optional[Dict]:
    """Get blocked phone numbers and their blocked emails."""
    try:
        params = {"page": page, "page_size": page_size}
        result = api_get("/blocked-registrations", params=params)
        if result is None:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}
        return result
    except Exception as e:
        st.error(f"Error fetching blocked registrations: {str(e)}")
        return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}


def generate_api_key() -> Optional[Dict]:
    """Generate API key for current user."""
    try:
        result = api_post("/generate-api-key", {})
        return result
    except Exception as e:
        st.error(f"Error generating API key: {str(e)}")
        return None


def manual_update_registration(
    registration_id: int,
    is_temporary: Optional[bool] = None,
    is_flagged: Optional[bool] = None,
    spam_score: Optional[int] = None,
    status: Optional[str] = None,
    detection_notes: Optional[str] = None,
    reason: str = ""
) -> Optional[Dict]:
    """Manually update registration flags."""
    try:
        data = {
            "registration_id": registration_id,
            "reason": reason
        }
        if is_temporary is not None:
            data["is_temporary"] = is_temporary
        if is_flagged is not None:
            data["is_flagged"] = is_flagged
        if spam_score is not None:
            data["spam_score"] = spam_score
        if status is not None:
            data["status"] = status
        if detection_notes is not None:
            data["detection_notes"] = detection_notes
        
        result = api_post("/manual-update", data)
        return result
    except Exception as e:
        st.error(f"Error updating registration: {str(e)}")
        return None


def check_registration(email: str, phone: str) -> Optional[Dict]:
    """Check/add a new registration."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/check_registration",
            json={"email": email, "phone": phone},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            try:
                error_detail = response.json().get("detail", response.text)
            except:
                error_detail = response.text
            st.error(f"Registration check failed: {error_detail}")
            return None
    except requests.exceptions.ConnectionError:
        st.error(f"Cannot connect to backend API at {API_BASE_URL}. Make sure the backend server is running.")
        return None
    except Exception as e:
        st.error(f"Error checking registration: {str(e)}")
        return None

