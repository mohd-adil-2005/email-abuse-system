# Email Abuse Detection System — 1-Hour Presentation Script

**Team:** Mohd Adil, Amosh Richard, Jai, Bora  
**Use this document to explain the project and your part. Each section has time, what to say, and which code to show.**

---

## Total Time: ~60 minutes

| Part | Who | Time | Topic |
|------|-----|------|--------|
| 1 | Bora | 5 min | Introduction & problem statement |
| 2 | All | 2 min | High-level architecture (one slide) |
| 3 | Jai | 12 min | Database & data models |
| 4 | Amosh | 15 min | Backend API & business logic |
| 5 | Mohd Adil | 15 min | ML pipeline & spam detection |
| 6 | Bora | 8 min | Dashboard & frontend |
| 7 | All | 3 min | End-to-end demo & wrap-up |

---

# PART 1 — Introduction & Problem (5 min) — BORA

## What to say

*"Good morning/afternoon. We are presenting our final year project: **Email Abuse Detection System**.*

*Many applications allow signup with email and phone. Abusers use temporary emails, fake numbers, or one number for many accounts. Our system acts as a **middleware**: before your app completes signup, it calls our API with email and phone. We check:*

- *Temporary or disposable email domains — blocked.*  
- *Invalid or non-mail domains — blocked.*  
- *Suspicious phone patterns — e.g. 1111111111 — blocked.*  
- *Too many registrations per phone — configurable limit, default 3 — blocked.*  
- *ML-based spam risk score — if score > 50, registration is blocked.*

*Admins get a dashboard to see all registrations, override decisions, whitelist phones, and export reports. So the **problem** we solve is: reduce fake and abusive signups while keeping real users allowed."*

## What to show

- One slide: problem (abuse) → solution (our API + dashboard).
- Optional: `README.md` — project name, features list.

---

# PART 2 — High-Level Architecture (2 min) — ANY ONE PERSON

## What to say

*"The system has three main parts:*

1. **Backend** — FastAPI on port 8000. It has all the rules, database access, and ML scoring.*  
2. **Frontend** — Streamlit dashboard on port 8501. Admins log in, see data, override, export.*  
3. **Database** — SQLite (can be swapped to PostgreSQL). Stores registrations, users, audit logs, settings.*

*External apps send `POST /check_registration` with email and phone; we return allowed or blocked with reasons. The dashboard talks to the same API with JWT or API key."*

## What to show

- Simple diagram or bullet list: **Client App → Backend API → DB** and **Admin → Dashboard → Backend API → DB**.

---

# PART 3 — Database & Data Models (12 min) — JAI

## What to say (overview)

*"I was responsible for the database design and data models. We use SQLAlchemy with SQLite. Every table has a clear purpose for the abuse-detection and admin workflow."*

## 3.1 — File to open: `backend/app/models.py`

*"We have five main models."*

### 1) Registration

*"**Registration** stores every signup attempt we evaluate.*

- `email` — unique, we block duplicate emails.*  
- `phone_hash` — SHA256 hash of normalized phone. We never store raw phone in plain text for privacy; we only store hash and E.164 normalized form.*  
- `phone_normalized` — E.164 format for display and grouping (e.g. +919876543210).*  
- `status` — approved, pending, or blocked. This is the final decision.*  
- `is_temporary` — True if the email domain is in our disposable list.*  
- `spam_score` — 0–100 from our ML model.*  
- `is_flagged` — True if we consider it risky (e.g. spam_score > 50).*  
- `detection_notes` — human-readable reason (e.g. 'Temporary email detected', 'Phone limit exceeded').*

*Indexes on `phone_hash`, `status`, `is_flagged` keep queries fast."*

### 2) User

*"**User** is for dashboard and API authentication.*

- `username`, `hashed_password` — login.*  
- `api_key` — for programmatic access (e.g. other services calling our API).*  
- `is_admin` — only admins can override, bulk block, whitelist, change settings.*  
- `oauth_provider` and `oauth_id` — for Google OAuth login."*

### 3) AuditLog

*"**AuditLog** records who did what and when.*

- `user_id`, `action` (e.g. override_status, bulk_block, phone_whitelist), `details` (JSON), `timestamp`.*

*So every admin action is traceable."*

### 4) PhoneOverride

*"**PhoneOverride** is the whitelist for suspicious phones.*

- `phone_hash`, `phone_normalized`, `allow_suspicious`, `reason`, `created_by`.*

*If a number looks fake (e.g. 12121212) but is legitimate, admin whitelists it; then we no longer block that phone for pattern alone."*

### 5) SystemSetting

*"**SystemSetting** is key-value config.*

- Example: `MAX_REGISTRATIONS_PER_PHONE` = 3. Admins can change this from the dashboard without code change."*

## 3.2 — File to open: `backend/app/database.py`

*"We use a session factory and dependency injection. `get_db()` yields a session; after the request it closes. For SQLite we enable WAL mode and a larger cache for better concurrency. Database URL comes from environment so we can switch to PostgreSQL later."*

## 3.3 — Summary line for faculty

*"I designed the schema so that we never store raw phones, every decision is stored with reasons, and every admin action is auditable."*

---

# PART 4 — Backend API & Business Logic (15 min) — AMOSH RICHARD

## What to say (overview)

*"I implemented the FastAPI backend and the business rules that decide allow vs block. I will walk through the main flow and then the security and admin endpoints."*

## 4.1 — File to open: `backend/app/main.py`

*"The app is created with FastAPI; we add CORS and a rate limiter. On startup we load disposable domains, load the ML model once, and create the default admin user if missing."*

### Public endpoint: `POST /check_registration`

*"This is the main endpoint external apps call.*

1. *We normalize and hash the phone.*  
2. *We check if this email is already registered — if yes, we return not allowed.*  
3. *We read `MAX_REGISTRATIONS_PER_PHONE` from settings (default 3) and count how many registrations exist for this phone hash. If count >= limit, we create a registration with status blocked and return not allowed.*  
4. *Otherwise we call `create_registration()` with email, phone, and initial status. Inside that function we run all checks: temporary email, domain MX, phone format, suspicious phone pattern, and ML spam score. The status is set to blocked if any rule fails or spam score > 50.*  
5. *We return a response with `allowed`, `status`, `message`, `spam_score`, `detection_notes`, etc."*

*Show the code block where you call `normalize_phone`, `hash_phone`, `get_registration_by_email`, `count_registrations_by_phone`, and `create_registration`.*

### Auth: login, signup, Google OAuth

*"We have `POST /login` and `POST /signup` for username/password. Passwords are hashed with bcrypt. We also support Google OAuth: `/auth/google` redirects to Google, and `/auth/google/callback` receives the code, gets user info, creates or finds the user, and redirects back to the dashboard with a JWT in the URL. The frontend stores that token."*

### Protected endpoints (need JWT or API key)

*"Endpoints like `/registrations`, `/stats`, `/flagged`, `/override`, `/bulk_block`, `/audit_logs`, `/phone-whitelist`, `/settings/phone-limit` require authentication. We use `get_current_user_or_api_key`: either Bearer token or `X-API-Key` header. Admin-only endpoints use `get_current_admin_user`."*

### Bulk import

*"We have `/bulk_import` (JSON body) and `/bulk_import_file` (CSV/JSON/XML upload). Both run the same checks per row: duplicate email, phone limit, then `create_registration`. We cap at 1000 per request and log the action in audit."*

## 4.2 — File to open: `backend/app/crud.py`

*"All database operations and the core decision logic live here."*

### `create_registration()`

*"This is the heart of the business logic.*

1. *Normalize and hash phone.*  
2. *`is_temporary_email(email)` — disposable domain list.*  
3. *`is_valid_email_domain(email)` — MX record and allowed TLD.*  
4. *`is_valid_phone_format(phone)` and `is_suspicious_phone(phone_normalized)` — format and pattern. We also check if this phone is in PhoneOverride (whitelist); if yes, we ignore suspicious pattern.*  
5. *`calculate_spam_score(email)` — returns score 0–100 and notes. This uses the ML model in utils.*  
6. *`is_flagged_spam(spam_score)` — True if score > 50.*  
7. *We build `detection_notes` from all checks.*  
8. *We set `final_status`: blocked if temporary, invalid domain, invalid/suspicious phone, or flagged spam; otherwise we keep the passed-in status (e.g. approved).*  
9. *We create the Registration row and commit."*

*Show the part where you call `is_temporary_email`, `calculate_spam_score`, and set `final_status`.*

### Other CRUD

*"We have get_registration_by_email, get_registration_by_id, get_registrations (paginated, filter by phone_hash/status), get_flagged_registrations, update_registration_status, update_registration_flags, bulk_update_registration_status, get_stats, create_audit_log, get_audit_logs, get_phone_registrations, get_blocked_registrations, create_or_update_phone_override, get_setting, set_setting. All of these are used by the API endpoints."*

## 4.3 — Auth and dependencies

*"In `auth.py` we use bcrypt for password hashing and JWT (e.g. 24-hour expiry) for tokens. In `dependencies.py` we have get_current_user (JWT), get_current_admin_user, and get_current_user_or_api_key (JWT or API key). Rate limiting is applied per endpoint (e.g. strict on login, higher on check_registration)."*

## 4.4 — Summary line for faculty

*"I implemented the API and the rule engine: duplicate check, phone limit, temporary email, domain validation, phone validation, and integration with the ML score so that every registration gets a consistent allow/block decision."*

---










# PART 5 — ML Pipeline & Spam Detection (15 min) — MOHD ADIL

## What to say (overview)

*"My role was the machine learning part: training a model to score how likely an email is spam or abuse, and integrating it into the live check. I will explain the data, features, model, and how it is used at runtime."*

## 5.1 — File to open: `backend/train_model.py`

*"Training is a separate script so we can retrain without touching the API. We use two datasets: SpamAssassin (easy_ham, hard_ham, spam_2) and Enron-Spam CSV. From each email we extract the sender's local part (before @) and build a feature vector. Label is 0 for ham, 1 for spam."*

### Feature extraction — `extract_features(email)`

*"We take the local part, sanitize to alphanumeric, dot, underscore, then compute 11 features:*

1. *length*  
2. *digit_count*  
3. *digit_ratio*  
4. *letter_ratio*  
5. *special_ratio*  
6. *vowel_ratio (vowels / letters)*  
7. *has_dot (0/1)*  
8. *has_underscore (0/1)*  
9. *max_consecutive_digits*  
10. *entropy (Shannon entropy of the string)*  
11. *has_keyword (1 if any of spam, test, fake, temp, trash, promo, free, gift, win, reward appears in local part)*  

*These capture randomness, numeric abuse, and spammy keywords."*

*Show the `extract_features` function and the return list.*

### Loading data

*"SpamAssassin: we read raw emails from the archive folders, find the From line, extract the first email, take the local part, and if length >= 2 we append `extract_features(local + '@x.com')` and the label. Enron: we read the CSV, use Message or Subject to get an email or text, extract features the same way, and use the Spam/Ham column for the label."*

### Training

*"We stack all feature vectors and labels into numpy arrays. We train a **RandomForestClassifier** with n_estimators=200, max_depth=15, random_state=42. We save the model to `app/spam_model.joblib` and write metadata (total samples, ham/spam counts, training date, model name) to `app/spam_model_info.json`. The API serves this metadata at GET /model-info for the dashboard."*

*Show the `train_model()` function and where we fit and save.*

## 5.2 — File to open: `backend/app/utils.py`

*"At runtime we use the same feature set and the saved model."*

### Loading the model

*"`load_spam_model()` loads `spam_model.joblib` into a global variable once. It is called at app startup in main.py so the first request is not slow. If the file is missing we log and fall back to rules only."*

### `extract_features(email)` in utils

*"We have the same 11 features as in train_model.py so the input to the model is identical. Length, digit/letter/special ratios, vowel ratio, dot/underscore, max consecutive digits, entropy, and keyword flag."*

### `calculate_spam_score(email)`

*"We first try the ML model: extract features, call model.predict_proba([features])[0][1] (probability of class 1 = spam), convert to 0–100 integer. We also have rule-based fallback: spam keywords +25, high digit ratio +20, high entropy +30. Final score is max(ML score, rule score) capped at 100. We return (score, notes string)."*

*Show the block where we call load_spam_model(), extract_features, predict_proba, and the rule fallback.*

### `is_flagged_spam(spam_score)`

*"Returns True if spam_score > 50. So in crud.create_registration, if this is True we set status to blocked."*

### Other utils used by the pipeline

*"`is_temporary_email` uses a list of disposable domains (fetched from GitHub or fallback list). `is_valid_email_domain` checks allowed TLD and MX record via dnspython. `is_suspicious_phone` detects same digit, repeated patterns, or one digit dominating. `normalize_phone` and `hash_phone` for E.164 and SHA256. All of these are used in crud.create_registration."*

## 5.3 — Summary line for faculty

*"I built the ML pipeline: 11 features from the email local part, RandomForest trained on SpamAssassin and Enron-Spam, saved as joblib. In production we load it once, compute the same features per request, get a 0–100 spam score, and block when score > 50, with rule-based fallback if the model is missing or fails."*

---








# PART 6 — Dashboard & Frontend (8 min) — BORA

## What to say (overview)

*"I built the admin dashboard so the team can monitor registrations, review blocked ones, override decisions, whitelist phones, and export reports. It is a Streamlit app that talks to the backend API with JWT or cookie."*

## 6.1 — File to open: `frontend/utils.py`

*"This is the API client for the dashboard.*

- *API_BASE_URL from env, default localhost:8000.*  
- *We store access_token and username in session state. We also use cookies (extra_streamlit_components) so login persists across refresh.*  
- *get_auth_headers() returns the Bearer token for authenticated requests.*  
- *login(), signup(), logout(), is_authenticated(), login_with_token(), save_auth_cookie(), clear_auth_cookie(), restore_session_from_cookie() — for auth and persistence.*  
- *get_oauth_providers() — to show 'Sign in with Google' if configured.*  
- *api_get(), api_post() — generic authenticated GET/POST; on 401 we clear session and show login again.*  
- *get_stats(), get_registrations(), get_flagged_registrations(), get_audit_logs(), get_phone_registrations(), get_blocked_registrations_list(), override_registration(), bulk_block_registrations(), manual_update_registration(), check_registration(), whitelist_phone(), get_model_info() — each maps to one or two API endpoints."*

## 6.2 — File to open: `frontend/dashboard.py`

*"Single Streamlit app with tabs."*

### Page config and auth

*"We set page title, icon, wide layout. We restore session from cookie; if URL has token (OAuth callback) we login with that token and clear the param. If not authenticated we show the auth page: Sign In / Sign Up tabs, optional Google button, username/password form, and signup with admin checkbox."*

### Tabs

1. **Overview** — *Metrics (total, allowed, blocked, temp blocked, flagged, avg spam score). We show ML model info from get_model_info(). Add registration form that calls check_registration(). Charts: emails per phone, spam score distribution, status pie, allowed vs not allowed. Blocked registrations list with expandable details.*  
2. **Registrations** — *Table with filters (phone hash, status). CSV download.*  
3. **Phone Numbers** — *Phones with email counts; table of all emails per phone. CSV export.*  
4. **Blocked** — *Paginated list of blocked phones and their blocked emails. For each phone we show whitelist button; on submit we call whitelist_phone() and rerun.*  
5. **Manual Review** — *Dropdown to pick a registration. Show current details; form to change is_temporary, is_flagged, status, spam_score, detection_notes, reason. Buttons: Save, Mark as Spam, Mark as Temporary, Approve, Block. Recent audit logs below.*  
6. **Spam Detection** — *Flagged registrations table; multiselect and bulk block with reason.*  
7. **Reports** — *Overview stats, detailed analysis (spam score stats, high risk, phone analysis, temporary/flagged breakdowns), data breakdowns, and export: PDF (ReportLab), CSV, JSON.*  
8. **Settings** — *GET/POST settings/phone-limit to change max registrations per phone.*

*We also have real-time refresh: we periodically call get_stats() and compare with previous state; if something changed we rerun so the dashboard updates without manual refresh."*

## 6.3 — Summary line for faculty

*"I implemented the Streamlit dashboard: login with JWT and optional Google OAuth, cookie persistence, and tabs for overview, registrations, phones, blocked list, manual review, spam list, reports, and settings. All actions go through the same backend API and are audited."*

---

# PART 7 — End-to-End Demo & Wrap-Up (3 min) — ALL

## What to do

1. *Start backend: `cd backend && py -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.*  
2. *Start frontend: `cd frontend && py -m streamlit run dashboard.py`.*  
3. *Open dashboard, login (admin / adminpass).*  
4. *In Overview, use "Add New Registration": first try a normal email and phone — allowed. Then try user@tempmail.com and any phone — blocked, temporary. Then try spam123@test.com — show blocked/flagged and spam score.*  
5. *Show Registrations table, Blocked tab, Manual Review (override one), and Reports export (e.g. CSV or PDF).*

## Closing line (any one)

*"So in one flow: the client sends email and phone to our API; we validate domain, phone, and limits; we score the email with our ML model; we store the result and return allowed or blocked. Admins see everything in the dashboard and can override or whitelist. Thank you."*

---

# Quick Reference — Who Explains What (Files)

| Person   | Main files to explain |
|----------|------------------------|
| **Jai**  | `backend/app/models.py`, `backend/app/database.py` |
| **Amosh**| `backend/app/main.py`, `backend/app/crud.py`, `backend/app/auth.py`, `backend/app/dependencies.py` |
| **Mohd Adil** | `backend/train_model.py`, `backend/app/utils.py` (ML parts: features, load_spam_model, calculate_spam_score, is_flagged_spam) |
| **Bora** | `frontend/dashboard.py`, `frontend/utils.py` |

---

# Common Faculty Questions — Short Answers

- **Why Random Forest?**  
  Good with mixed numeric features, robust, no scaling needed, interpretable feature importance, fast for real-time scoring.

- **What if the model file is missing?**  
  We fall back to rule-based score (keywords, digit ratio, entropy) so the system still blocks obvious abuse.

- **Why hash the phone?**  
  Privacy: we never store raw phone; we only need to count and group by the same number. Hash is one-way and salted.

- **How do you prevent one person from making many accounts?**  
  We limit how many registrations one phone (hash) can have; the limit is configurable (e.g. 3). We also block suspicious phone patterns and temporary emails.

- **Who can override a blocked registration?**  
  Only users with is_admin=True, via dashboard or API, and every override is logged in audit_logs with user_id, action, and details.

- **What is the flow for a single check?**  
  Request → normalize/hash phone → duplicate check → phone limit check → create_registration (temp email, domain MX, phone format, suspicious phone, spam score) → set status → return response.

Use this script to rehearse so each member can explain their part confidently within the 1-hour slot.
