# email-abuse-detection-client

JavaScript/Node.js client for the **Email Abuse Detection System** API. Use it in your app to validate email and phone at signup and block abuse (temp emails, high spam score, suspicious phones).

- **Middleware:** Call `checkRegistration({ email, phone })` before creating a user — block if `allowed === false`.
- **Auth:** Login with `login(username, password)`, then use `withToken(accessToken)` for protected and admin endpoints.
- **Optional:** Use API key instead of JWT via `apiKey` option.

## Install

```bash
npm install @mohd-adil-2005/email-abuse-client
```

Your API (FastAPI backend) must be running, e.g. at `http://localhost:8000` or your deployed URL.

## Quick start (signup flow)

```javascript
const { EmailAbuseClient } = require('@mohd-adil-2005/email-abuse-client');

const client = new EmailAbuseClient({
  baseUrl: 'http://localhost:8000',  // or https://your-api.com
});

// Before creating a user, check if registration is allowed
const result = await client.checkRegistration({
  email: 'user@example.com',
  phone: '+919876543210',
});

if (!result.allowed) {
  throw new Error(result.message);  // e.g. "Temporary email detected and blocked"
}
// Proceed with signup...
```

## API key or JWT (protected endpoints)

```javascript
// Option 1: API key (e.g. from dashboard → Generate API key)
const client = new EmailAbuseClient({
  baseUrl: 'https://your-api.com',
  apiKey: 'sk_xxxx',
});

// Option 2: JWT after login
const loginRes = await client.login('admin', 'adminpass');
const admin = client.withToken(loginRes.access_token);

const stats = await admin.getStats();
console.log(stats.total_registrations, stats.flagged_registrations);
```

## Methods

| Method | Auth | Description |
|--------|------|-------------|
| `health()` | No | Health check |
| `checkRegistration({ email, phone })` | No | **Main middleware:** validate signup, returns `allowed`, `message`, `status`, etc. |
| `getModelInfo()` | No | ML model metadata |
| `login(username, password)` | No | Returns `access_token` (JWT) |
| `signup({ username, password, is_admin? })` | No | Register new user |
| `withToken(accessToken)` | — | Returns new client with Bearer token set |
| `getMe()` | Yes | Current user info |
| `generateApiKey()` | Yes | Generate API key (shown once) |
| `getStats()` | Yes | Registration statistics |
| `getRegistrations({ page?, page_size?, phone_hash?, status? })` | Yes | List registrations |
| `getFlagged({ page?, page_size? })` | Yes | Flagged registrations |
| `getAuditLogs({ page?, page_size? })` | Yes | Audit logs |
| `getPhoneRegistrations({ page?, page_size? })` | Yes | Phones with emails |
| `getBlockedRegistrations({ page?, page_size? })` | Yes | Blocked list |
| `override({ registration_id, status, reason })` | Admin | Override status (approved/pending/blocked) |
| `manualUpdate({ registration_id, reason, ... })` | Admin | Update flags/notes |
| `bulkBlock({ registration_ids, reason })` | Admin | Bulk block |
| `bulkImport({ registrations, skip_rate_limit? })` | Admin | Bulk import/check |
| `phoneWhitelist({ phone_hash, phone_normalized, reason })` | Admin | Whitelist phone |

## Constructor options

```javascript
new EmailAbuseClient({
  baseUrl: 'http://localhost:8000',  // default
  apiKey: 'sk_...',                  // optional, X-API-Key header
  accessToken: 'eyJ...',             // optional, Bearer token
  timeoutMs: 10000,                  // optional, default 10000
});
```

## License

MIT. Part of [Email Abuse Detection System](https://github.com/mohd-adil-2005/email-abuse-system).
