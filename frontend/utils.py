"""
API helper functions for Streamlit dashboard.
"""
import requests
import os
from typing import Optional, Dict, Any
import streamlit as st

# Backend API URL
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# Cookie keys for persisting login across browser refresh (logout after 1 day via token expiry)
AUTH_COOKIE_NAME = "auth_token"
USERNAME_COOKIE_NAME = "auth_username"


def get_auth_headers() -> Dict[str, str]:
    """
    Get authorization headers from session state.
    
    Returns:
        Headers dict with Bearer token if available
    """
    if "access_token" in st.session_state:
        return {"Authorization": f"Bearer {st.session_state.access_token}"}
    return {}


def login(username: str, password: str, cookie_manager: Any = None) -> Optional[str]:
    """
    Login and store token in session state (and optionally in cookie for persistence across refresh).
    
    Args:
        username: Username
        password: Password
        cookie_manager: Optional cookie manager to persist token so admin is not logged out on refresh
        
    Returns:
        Error message if login fails, None if successful
    """
    try:
        response = requests.post(
            f"{API_BASE_URL}/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        try:
            data = response.json() if response.text else {}
        except (ValueError, requests.exceptions.JSONDecodeError):
            if response.status_code != 200:
                return f"Server error ({response.status_code}). Is the backend running at {API_BASE_URL}?"
            return "Invalid response from server."
        if response.status_code == 200 and data.get("access_token"):
            st.session_state.access_token = data["access_token"]
            st.session_state.username = username
            save_auth_cookie(cookie_manager, data["access_token"], username)
            return None
        return data.get("detail", "Login failed")
    except requests.exceptions.ConnectionError:
        return "Cannot connect to backend. Make sure it is running at {}.".format(API_BASE_URL)
    except Exception as e:
        return f"Connection error: {str(e)}"


def signup(username: str, password: str, is_admin: bool = False, cookie_manager: Any = None) -> Optional[str]:
    """
    Sign up a new user and store token in session state (and optionally in cookie).
    
    Returns:
        Error message if signup fails, None if successful
    """
    try:
        response = requests.post(
            f"{API_BASE_URL}/signup",
            json={"username": username, "password": password, "is_admin": is_admin},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        try:
            data = response.json() if response.text else {}
        except (ValueError, requests.exceptions.JSONDecodeError):
            if response.status_code == 200:
                return "Invalid response from server. Is the backend running at {}?".format(API_BASE_URL)
            return f"Server error ({response.status_code}). Check backend at {API_BASE_URL}."
        if response.status_code == 200:
            if data.get("access_token"):
                st.session_state.access_token = data["access_token"]
                st.session_state.username = username
                save_auth_cookie(cookie_manager, data["access_token"], username)
                return None
            return "Invalid response from server."
        return data.get("detail", f"Signup failed (status {response.status_code})")
    except requests.exceptions.ConnectionError:
        return "Cannot connect to backend. Make sure it is running at {}.".format(API_BASE_URL)
    except requests.exceptions.Timeout:
        return "Request timed out. Is the backend running?"
    except Exception as e:
        return f"Connection error: {str(e)}"


def logout(cookie_manager: Any = None):
    """Clear session state and auth cookies so refresh does not restore session."""
    if "access_token" in st.session_state:
        del st.session_state.access_token
    if "username" in st.session_state:
        del st.session_state.username
    if cookie_manager is not None:
        try:
            cookie_manager.delete(AUTH_COOKIE_NAME)
            cookie_manager.delete(USERNAME_COOKIE_NAME)
        except Exception:
            pass


def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return "access_token" in st.session_state


def login_with_token(token: str, cookie_manager: Any = None) -> bool:
    """
    Login using a JWT token (e.g. from OAuth callback or persisted cookie).
    Verifies token by fetching /me. Optionally persists to cookie.
    """
    try:
        response = requests.get(
            f"{API_BASE_URL}/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            st.session_state.access_token = token
            st.session_state.username = data.get("username", "user")
            if cookie_manager is not None:
                try:
                    cookie_manager.set(AUTH_COOKIE_NAME, token)
                    cookie_manager.set(USERNAME_COOKIE_NAME, st.session_state.username)
                except Exception:
                    pass
            return True
    except Exception:
        pass
    return False


def save_auth_cookie(cookie_manager: Any, token: str, username: str) -> None:
    """Persist token and username in cookies so login survives browser refresh."""
    if cookie_manager is None:
        return
    try:
        cookie_manager.set(AUTH_COOKIE_NAME, token)
        cookie_manager.set(USERNAME_COOKIE_NAME, username)
    except Exception:
        pass


def clear_auth_cookie(cookie_manager: Any) -> None:
    """Remove auth cookies (e.g. on logout)."""
    if cookie_manager is None:
        return
    try:
        cookie_manager.delete(AUTH_COOKIE_NAME)
        cookie_manager.delete(USERNAME_COOKIE_NAME)
    except Exception:
        pass


def restore_session_from_cookie(cookie_manager: Any) -> bool:
    """
    If not authenticated but auth token exists in cookie, verify with backend and restore session.
    Returns True if session was restored.
    """
    if cookie_manager is None or is_authenticated():
        return False
    try:
        token = cookie_manager.get(cookie=AUTH_COOKIE_NAME)
        if not token:
            return False
        if login_with_token(token, cookie_manager=None):
            return True
        clear_auth_cookie(cookie_manager)
    except Exception:
        pass
    return False


def get_oauth_providers() -> Dict[str, bool]:
    """Get which OAuth providers are available from backend."""
    try:
        response = requests.get(f"{API_BASE_URL}/auth/providers", timeout=3)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {"google": False}


def get_model_info() -> Optional[Dict[str, Any]]:
    """Get ML model training metadata (dataset size, etc.) for academic demo."""
    try:
        response = requests.get(f"{API_BASE_URL}/model-info", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None


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


def whitelist_phone(phone_hash: str, phone_normalized: str, reason: str) -> Optional[Dict]:
    """Whitelist a phone number so suspicious patterns no longer block it."""
    try:
        data = {
            "phone_hash": phone_hash,
            "phone_normalized": phone_normalized,
            "reason": reason,
        }
        return api_post("/phone-whitelist", data)
    except Exception as e:
        st.error(f"Error whitelisting phone: {str(e)}")
        return None

