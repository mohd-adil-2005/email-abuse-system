# OAuth2 / OIDC Setup (Google & GitHub)

This project supports social login via OAuth2. To enable it, configure the providers below.

## Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a project (or use existing)
3. Configure OAuth consent screen
4. Create OAuth 2.0 Client ID (Web application)
5. Add authorized redirect URI: `http://localhost:8000/auth/google/callback` (or your backend URL)
6. Set in `.env`:
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```

## GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. New OAuth App
3. Authorization callback URL: `http://localhost:8000/auth/github/callback`
4. Set in `.env`:
   ```
   GITHUB_CLIENT_ID=your-github-client-id
   GITHUB_CLIENT_SECRET=your-github-client-secret
   ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| GOOGLE_CLIENT_ID | Google OAuth client ID | - |
| GOOGLE_CLIENT_SECRET | Google OAuth client secret | - |
| GITHUB_CLIENT_ID | GitHub OAuth client ID | - |
| GITHUB_CLIENT_SECRET | GitHub OAuth client secret | - |
| BACKEND_BASE_URL | Backend URL for OAuth callbacks | http://localhost:8000 |
| FRONTEND_URL | Frontend URL (where to redirect after login) | http://localhost:8501 |

If OAuth is not configured, only username/password login is available. The "Login with Google" and "Login with GitHub" buttons appear only when credentials are set.
