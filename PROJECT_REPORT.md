# Final Year Project Report

## Email Abuse Detection System  
### A Middleware for Signup Abuse Prevention Using Email and Phone Validation

---

## 1. Title and Abstract

**Project Title:** Email Abuse Detection System  

**Abstract:**  
The Email Abuse Detection System is a middleware that validates email and phone numbers during user registration to prevent abuse. It blocks temporary or disposable emails, invalid email domains (no MX records), high spam-score emails using a trained Random Forest model, suspicious or fake phone patterns (e.g., repeated digits), and invalid phone formats. The system enforces a maximum of three registrations per phone number. An admin dashboard allows reviewing blocked entries, manually whitelisting legitimate phones, overriding statuses, and generating reports. The system is built with FastAPI (backend), Streamlit (dashboard), SQLite, JWT authentication with persistent login, and optional Google OAuth. This report documents all features implemented for the final year project.

---

## 2. Introduction

### 2.1 Background

Online signup flows are often abused through temporary emails, fake phone numbers, and bulk registrations. This project implements a central middleware that applications can call before accepting a registration. The middleware checks email and phone against multiple rules and a machine learning model, and either allows or blocks the registration. Administrators can review blocks and whitelist legitimate users (e.g., real phone numbers that look suspicious due to digit patterns).

### 2.2 Objectives

1. **Detect and block temporary/disposable emails** using a maintained list of disposable domains.  
2. **Validate email domain** by checking MX (mail exchange) records so only domains that accept mail are allowed.  
3. **Score emails for spam likelihood** using a Random Forest model trained on SpamAssassin and Enron-Spam datasets; block above a configurable threshold.  
4. **Validate and normalize phone numbers** using international format (E.164) and region-aware validation.  
5. **Detect suspicious phone patterns** (e.g., all same digit, repeated patterns) and block unless an admin whitelists the number.  
6. **Limit registrations per phone** to a maximum of three.  
7. **Provide an admin dashboard** for viewing registrations, blocked entries, manual overrides, whitelisting phones, and reports.  
8. **Secure access** with JWT, persistent login (no logout on refresh), and optional OAuth/API keys.

### 2.3 Scope

- **In scope:** Registration check API, email/phone validation, ML-based spam scoring, admin dashboard, phone whitelist, audit logging, bulk import/export, reports.  
- **Out of scope:** Sending OTP/SMS, full mailbox verification, integration with a specific production application (the system is middleware-API based).

---

## 3. System Analysis and Design

### 3.1 High-Level Architecture

```
[Client / App]  -->  POST /check_registration (email, phone)
                            |
                            v
                    [Email Abuse Backend]
                    - Temp email check
                    - MX check (domain)
                    - Spam score (ML + rules)
                    - Phone format + suspicious check
                    - Phone count limit
                            |
                            v
                    [Database: SQLite]
                    - registrations, users, audit_logs, phone_overrides
                            |
                    [Admin Dashboard - Streamlit]
                    - Login (JWT / OAuth)
                    - View/override/whitelist/reports
```

### 3.2 Data Model (Key Entities)

| Entity           | Description |
|------------------|-------------|
| **Registration** | email, phone_hash, phone_normalized, status (approved/pending/blocked), is_temporary, spam_score, is_flagged, detection_notes, timestamps |
| **User**         | username, hashed_password, is_admin, api_key, oauth_provider, oauth_id |
| **AuditLog**     | user_id, action (e.g., override_status, phone_whitelist), details (JSON), timestamp |
| **PhoneOverride**| phone_hash, phone_normalized, allow_suspicious, reason, created_by, created_at — used to whitelist a phone so it is not blocked for “suspicious pattern” |

### 3.3 Workflow: Registration Check

1. Client sends **email** and **phone** to **POST /check_registration**.  
2. If email already exists → return *not allowed*, existing status.  
3. Normalize phone (E.164), hash it; if registrations for this phone ≥ 3 → block with note “Phone limit exceeded”.  
4. Check disposable domain list → if match, block.  
5. Check MX records for email domain → if no MX, block.  
6. Validate phone format (phonenumbers lib) → if invalid, block.  
7. Check suspicious phone (repeated digits, fake patterns) → if suspicious and not in **PhoneOverride** whitelist → block.  
8. Compute spam score (Random Forest + heuristic rules) → if score > 50, block.  
9. Create **Registration** with status **approved** or **blocked** and detection_notes.  
10. Return allowed/blocked, status, and notes to client.

---

## 4. Technologies Used

| Category      | Technology | Purpose |
|---------------|------------|---------|
| Backend API   | FastAPI    | REST API, dependency injection, OpenAPI docs |
| Database      | SQLite, SQLAlchemy | Persistence, ORM, migrations (Alembic) |
| Auth          | JWT (python-jose), bcrypt, Passlib | Login, signup, token expiry |
| OAuth         | Authlib, Google OAuth 2.0 | Optional “Sign in with Google” |
| Rate limiting | SlowAPI    | Protect endpoints from abuse |
| ML            | scikit-learn (Random Forest), joblib | Spam score model training and inference |
| Email check   | dnspython  | MX record lookup for domain validation |
| Phone check   | phonenumbers | E.164 normalization, format validation |
| Frontend      | Streamlit  | Admin dashboard (tabs, forms, tables, charts) |
| Visualization | Pandas, Plotly | Charts and data tables |
| Reports       | ReportLab  | PDF report generation |
| Persistence (UI) | extra-streamlit-components | Cookie-based auth persistence across refresh |
| Language      | Python 3   | Backend and frontend |

---

## 5. Features Implemented (Complete List)

The following is an exhaustive list of features implemented in this project, suitable for the final year project report.

---

### 5.1 Core Registration and Abuse Detection

| Feature | Description |
|--------|-------------|
| **Duplicate email check** | Rejects if email is already registered; returns existing registration status. |
| **Phone registration limit** | Maximum 3 registrations per phone number (by hashed phone); excess blocked with a clear note. |
| **Temporary email detection** | Uses a list of disposable/temporary email domains (fetched from GitHub with fallback list); blocks if email domain or parent subdomain matches. |
| **MX record validation** | Uses DNS MX lookup (dnspython) to ensure the email domain has mail servers; blocks if no MX records. |
| **Phone format validation** | Uses `phonenumbers` library for region-aware validation and E.164 normalization; blocks invalid format. |
| **Suspicious phone detection** | Detects all-same-digit numbers, short repeated patterns (e.g. 12121212), and very high digit repetition; blocks unless phone is whitelisted. |
| **Spam score (ML)** | Extracts features from email local part (length, digit/letter ratio, entropy, keywords, etc.); Random Forest model outputs spam probability; score 0–100; block if > 50. |
| **Spam score (rules)** | Heuristic rules (keywords, digit ratio, entropy) used as fallback or combined with ML. |
| **Detection notes** | Every registration stores human-readable notes (e.g. “Temporary email detected”, “Suspicious/fake phone pattern detected”, “Random Forest prediction: 38%”). |
| **Status and flags** | Registration has status (approved/pending/blocked), is_temporary, is_flagged, spam_score for reporting and filtering. |

---

### 5.2 Machine Learning Model

| Feature | Description |
|--------|-------------|
| **Training pipeline** | Script `train_model.py` loads SpamAssassin (raw emails) and Enron-Spam (CSV), combines datasets, extracts same features as production, trains Random Forest (n_estimators=200, max_depth=15). |
| **Model persistence** | Trained model saved as `spam_model.joblib`; metadata (sample counts, training date, dataset breakdown) in `spam_model_info.json`. |
| **Inference** | At runtime, `calculate_spam_score()` loads model once, extracts features from email, returns score 0–100 and notes. |
| **Model info API** | **GET /model-info** returns training metadata (total samples, ham/spam counts, datasets, training date) for dashboard display. |
| **Dashboard display** | Overview tab shows “Trained on X emails (Y ham, Z spam)” and last training date from model info. |

---

### 5.3 Authentication and Authorization

| Feature | Description |
|--------|-------------|
| **Login** | **POST /login** with username and password; returns JWT access token. |
| **Signup** | **POST /signup** to create user (optional is_admin); returns JWT. |
| **JWT expiry** | Configurable token lifetime; default 1 day (1440 minutes) via `ACCESS_TOKEN_EXPIRE_MINUTES`. |
| **Protected routes** | Endpoints use `get_current_user` or `get_current_admin_user`; 401 if invalid/expired token. |
| **API key** | Users can generate API key via **POST /generate-api-key**; key can be used instead of Bearer token for API access. |
| **Google OAuth** | Optional “Sign in with Google”; redirect to Google, callback exchanges code for token, fetches user info, creates or links user and returns JWT to frontend. |
| **Default admin** | On first run, seeds user **admin** / **adminpass** (change in production). |

---

### 5.4 Persistent Login (Session Across Refresh)

| Feature | Description |
|--------|-------------|
| **Cookie storage** | After login/signup/OAuth, JWT and username stored in browser cookies (extra-streamlit-components). |
| **Restore on load** | On dashboard load, if session has no token but cookie has one, backend **GET /me** validates token; if valid, session is restored so admin is not logged out on refresh. |
| **Logout** | Logout clears session and deletes auth cookies so refresh does not restore session. |
| **Expiry** | When token expires (e.g. after 1 day), next API call returns 401; frontend clears session and cookie and shows login again. |

---

### 5.5 Phone Whitelist (Manual Allow from Blocked)

| Feature | Description |
|--------|-------------|
| **PhoneOverride model** | New table stores phone_hash, phone_normalized, allow_suspicious, reason, created_by, created_at. |
| **Override logic** | In `create_registration`, if a PhoneOverride exists for the phone with allow_suspicious=True, the “suspicious phone” check is skipped so the number is not blocked for digit pattern. |
| **Whitelist API** | **POST /phone-whitelist** (admin only): body has phone_hash, phone_normalized, reason; creates/updates PhoneOverride; sets all *blocked* registrations for that phone to *approved* and appends note “Phone whitelisted by &lt;admin&gt;: &lt;reason&gt;”. |
| **Blocked list flag** | **GET /blocked-registrations** includes `is_whitelisted` per phone group when an override exists. |
| **Dashboard UI** | In Blocked tab, for each non-whitelisted phone: text input “Reason for allowing this phone” and button “Allow this phone (whitelist)”; on success, loading spinner, success message, list refreshes (paginated). |
| **Audit** | Whitelist action logged in audit_log (action: phone_whitelist, details: phone_hash, reason, updated_registrations count). |

---

### 5.6 Admin Dashboard – Tabs and Capabilities

| Tab | Features |
|-----|----------|
| **Overview** | Key metrics (total, allowed, blocked, temp blocked, flagged, avg spam score); ML model info banner; “Add New Registration” test form (email + phone, Check Registration); charts: emails per phone distribution, spam score distribution, status pie, allowed vs not allowed; blocked registrations summary table and expandable details. |
| **Registrations** | Paginated table of all registrations; filter by phone hash and status; CSV download; datetime formatting. |
| **Phone Numbers** | List of phone numbers with email counts; expandable view of emails per phone (status, temporary, flagged, spam score, created_at); CSV export. |
| **Blocked** | Paginated list (50 per page) of blocked phones with blocked emails; metrics (total blocked registrations, this page count); Prev/Next pagination; per-phone expander with details and “Allow this phone (whitelist)” (reason + button); success message after whitelist; CSV export of blocked list. |
| **Manual Review** | Dropdown to select a registration; display current details (email, phone, status, spam score, flags, notes); form to update is_temporary, is_flagged, status, spam score, detection_notes; reason field; buttons: Save Changes, Reset; quick actions: Mark as Spam, Mark as Temporary, Approve, Block; recent audit logs table. |
| **Spam Detection** | Table of flagged registrations; multiselect to bulk block with reason; sample temporary email domains list. |
| **Reports** | Sub-tabs: Overview Statistics (metrics, detailed stats table, status distribution); Detailed Analysis (spam score stats, high-risk registrations, phone analysis, temporary email analysis, flagged analysis); Data Breakdowns (status breakdown, blocked details, recent activity, audit summary); Export (PDF report, CSV all/blocked, JSON all/stats). |

---

### 5.7 Override and Bulk Operations

| Feature | Description |
|--------|-------------|
| **Override status** | **POST /override**: admin sends registration_id, new status (approved/pending/blocked), reason; updates registration and writes audit log. |
| **Manual update** | **POST /manual-update**: admin updates is_temporary, is_flagged, spam_score, status, detection_notes with reason; audit logged. |
| **Bulk block** | **POST /bulk_block**: list of registration_ids and reason; all set to blocked with same note; audit log. |
| **Bulk import** | **POST /bulk_import**: JSON body with list of {email, phone}; each checked through same rules (duplicate, phone limit, temp email, MX, phone, spam); up to 1000 per request; returns per-item result (success, allowed, status, message). |
| **Bulk import file** | **POST /bulk_import_file**: upload CSV/JSON/XML file; parsed and processed same as bulk import; audit log with filename and counts. |
| **Bulk import raw** | **POST /bulk_import_raw**: form with file_type and raw data; same processing. |

---

### 5.8 APIs and Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /check_registration | Core registration check (email + phone); returns allowed/blocked, status, notes. |
| POST | /login | Username/password → JWT. |
| POST | /signup | Create user → JWT. |
| GET  | /auth/google | Redirect to Google OAuth. |
| GET  | /auth/google/callback | OAuth callback; create/link user, redirect to frontend with token. |
| GET  | /auth/providers | Returns { google: true/false }. |
| GET  | /registrations | Paginated list; optional filters (phone_hash, status). |
| POST | /override | Admin: change registration status. |
| POST | /manual-update | Admin: update flags/status/notes. |
| GET  | /stats | Aggregate stats (totals, blocked, flagged, etc.). |
| GET  | /flagged | Paginated flagged registrations. |
| POST | /bulk_block | Admin: bulk block by IDs. |
| POST | /bulk_import | Admin: bulk import JSON. |
| POST | /bulk_import_file | Admin: bulk import uploaded file. |
| POST | /bulk_import_raw | Admin: bulk import raw body. |
| GET  | /phone-registrations | Phones with email counts and list. |
| GET  | /blocked-registrations | Blocked phones and emails (paginated). |
| POST | /phone-whitelist | Admin: whitelist phone, approve its blocked registrations. |
| GET  | /audit_logs | Paginated audit log. |
| GET  | /me | Current user info (validates token). |
| POST | /generate-api-key | Generate API key for current user. |
| GET  | /model-info | ML model training metadata. |
| GET  | /health | Health check. |

---

### 5.9 Non-Functional and Operational Features

| Feature | Description |
|--------|-------------|
| **Rate limiting** | SlowAPI applied (e.g. high limit on check_registration for load; stricter on login/signup). |
| **CORS** | Backend allows frontend origin for dashboard and OAuth. |
| **Pagination** | List endpoints return page, page_size, total, total_pages. |
| **Blocked tab performance** | Blocked list limited to 50 items per page with Prev/Next; expanders collapsed by default; after whitelist, reset to page 1 for fast refresh. |
| **Success feedback** | After whitelist: spinner during request, then success message at top of Blocked tab. |
| **Dark theme** | Streamlit config set to dark theme for dashboard. |
| **.gitignore** | Python cache, venv, .env, DB files, large model/data files, IDE/OS files so repo is safe for GitHub. |
| **Environment config** | Backend: .env from .env.example (DATABASE_URL, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES, OAuth, etc.). Frontend: API_BASE_URL. |

---

## 6. Implementation Highlights

- **Backend:** FastAPI application in `backend/app/main.py`; models in `models.py`, CRUD in `crud.py`, validation and ML in `utils.py`, auth in `auth.py`, OAuth in `oauth.py`. Database tables created on startup; Alembic available for migrations.  
- **Frontend:** Single Streamlit app `frontend/dashboard.py`; API helpers and cookie handling in `frontend/utils.py`.  
- **ML:** Feature extraction aligned between `train_model.py` and `utils.extract_features()`; model loaded once at startup.  
- **Security:** Passwords hashed with bcrypt; JWT with configurable expiry; phone hashed with salt for storage; .env not committed.

---

## 7. Testing and Validation

- **Manual testing:** Registration check with valid/invalid/temp emails, invalid MX, valid/suspicious phones, spam emails; dashboard login, whitelist, override, bulk operations, reports.  
- **Unit tests:** Present in `backend/tests/` (e.g. test_api, test_crud, test_utils) for critical paths.  
- **Load testing:** Script `backend/load_test_rps.py` can be used to measure requests per second for /check_registration.

---

## 8. Results and Outcomes

- **Functional:** All stated objectives met: temp email, MX, ML spam score, phone validation, suspicious-phone detection, phone limit, admin dashboard, whitelist, overrides, bulk operations, reports, persistent login.  
- **Performance:** Blocked tab and whitelist flow optimized with pagination (50 per page).  
- **Usability:** Admin can allow legitimate users from Blocked list with a reason and see success message; login persists across refresh for 1 day.

---

## 9. Conclusion and Future Work

**Conclusion:** The Email Abuse Detection System successfully implements a middleware that validates email and phone at signup, blocks abuse via multiple rules and an ML model, and provides an admin dashboard for review, whitelisting, and reporting. Features are documented and implemented for use as a final year project.

**Future work (suggestions):**  
- OTP/SMS verification for phone.  
- Mailbox verification (e.g. send verification link to email).  
- More OAuth providers (e.g. GitHub).  
- PostgreSQL for production and scaling.  
- Configurable thresholds (spam score, phone limit) via admin UI.

---

## 10. References

- FastAPI: https://fastapi.tiangolo.com/  
- Streamlit: https://docs.streamlit.io/  
- scikit-learn: https://scikit-learn.org/  
- SpamAssassin: https://spamassassin.apache.org/  
- Enron-Spam dataset (e.g. from Kaggle / public sources).  
- phonenumbers (libphonenumber): https://github.com/daviddrysdale/python-phonenumbers  
- dnspython: https://www.dnspython.org/  

---

## 11. Appendix – Feature Checklist (For Report/Verification)

| # | Feature | Implemented |
|---|---------|-------------|
| 1 | Temporary/disposable email block | Yes |
| 2 | MX record validation for domain | Yes |
| 3 | ML-based spam score (Random Forest) | Yes |
| 4 | Spam score threshold block (e.g. >50) | Yes |
| 5 | Phone format validation (E.164) | Yes |
| 6 | Suspicious phone pattern detection | Yes |
| 7 | Phone registration limit (3 per number) | Yes |
| 8 | Phone whitelist (admin allow from blocked) | Yes |
| 9 | JWT authentication (login/signup) | Yes |
| 10 | JWT expiry 1 day (configurable) | Yes |
| 11 | Persistent login (cookies, no logout on refresh) | Yes |
| 12 | Google OAuth (optional) | Yes |
| 13 | API key for programmatic access | Yes |
| 14 | Admin dashboard (Streamlit) | Yes |
| 15 | Overview, Registrations, Phones, Blocked, Manual Review, Spam, Reports tabs | Yes |
| 16 | Override registration status | Yes |
| 17 | Manual update (flags, status, notes) | Yes |
| 18 | Bulk block | Yes |
| 19 | Bulk import (JSON/CSV/XML) | Yes |
| 20 | Audit log | Yes |
| 21 | Model info API and dashboard display | Yes |
| 22 | PDF/CSV/JSON report export | Yes |
| 23 | Pagination and performance (Blocked tab) | Yes |
| 24 | .gitignore and environment config | Yes |

---

*This document serves as the feature and implementation documentation for the Final Year Project Report. All features listed have been implemented in the codebase.*
