"""
OAuth2 / OIDC configuration for Google social login.
"""
import os
from typing import Optional, Dict, Any
import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

# OAuth2 configuration from environment
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

# Base URL for OAuth callbacks (backend URL, e.g. http://localhost:8000)
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", os.getenv("API_BASE_URL", "http://localhost:8000"))


def is_google_oauth_configured() -> bool:
    """Check if Google OAuth is configured."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def get_google_oauth_client(redirect_uri: str):
    """Create Google OAuth2 client."""
    return AsyncOAuth2Client(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        redirect_uri=redirect_uri,
        scope="openid email profile",
    )


async def fetch_google_user_info(access_token: str) -> Optional[Dict[str, Any]]:
    """Fetch user info from Google using access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "id": str(data.get("id", "")),
                "email": data.get("email", ""),
                "name": data.get("name", ""),
                "picture": data.get("picture"),
            }
    return None
