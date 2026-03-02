# Email Abuse Detection System — Project Documentation

This document describes **everything implemented** in the Email-Abuse-System project, step by step.

---

## 1. Project Overview

**Email-Abuse-System** is a middleware that checks **email + phone** at signup and blocks abuse:

- **Temporary/disposable emails** (blocked)
- **Invalid or non-mail domains** (no MX records)
- **High spam score** from ML model (blocked above threshold)
- **Suspicious/fake phone patterns** (e.g. repeated digits)
- **Invalid phone format** (region-aware validation)
- **Max 3 registrations per phone number**

Admins can review and override blocks (e.g. whitelist legitimate phones) from a Streamlit dashboard.

---

## 2. Tech Stack

| Layer    | Technology |
|----------|------------|
| Backend  | FastAPI, SQLAlchemy, SQLite, JWT (python-jose), bcrypt, SlowAPI (rate limit) |
| ML       | scikit-learn (Random Forest), joblib |
| Validation | dnspython (MX), phonenumbers (E.164) |
| Frontend | Streamlit, Pandas, Plotly, ReportLab (PDF), extra-streamlit-components (cookies) |
| Auth     | Username/password, optional Google OAuth, API key |

---

## 3. Project Structure

```
Email-Abuse-System/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app, all endpoints
│   │   ├── auth.py          # JWT, password hash
│   │   ├── crud.py          # DB operations
│   │   ├── database.py      # SQLite engine, get_db
│   │   ├── dependencies.py # get_current_user, limiter
│   │   ├── models.py        # Registration, User, AuditLog, PhoneOverride
│   │   ├── oauth.py         # Google OAuth
│   │   ├── schemas.py       # Pydantic request/response
│   │   ├── utils.py         # Disposable domains, spam score, phone/email checks
│   │   ├── spam_model.joblib      # (generated) ML model
│   │   └── spam_model_info.json   # (generated) Training metadata
│   ├── data/                # Datasets for training (SpamAssassin, Enron-Spam)
│   ├── alembic/            # DB migrations
│   ├── train_model.py       # Train Random Forest on emails
│   ├── requirements.txt
│   └── .env.example / .env  # Config (env not committed)
├── frontend/
│   ├── dashboard.py        # Streamlit UI (tabs, auth, blocked, whitelist)
│   ├── utils.py            # API helpers, login, cookies
│   ├── requirements.txt
│   └── .streamlit/config.toml  # Dark theme
├── .gitignore
├── run_project.bat         # Start backend + frontend (Windows)
├── run_backend_optimized.bat
├── OAUTH_SETUP.md
├── README.md
└── DOCS.md                 # This file
```

---

## 4. Setup (Step by Step)

### 4.1 Clone and enter project

```bash
git clone <repo-url>
cd Email-Abuse-System
```

### 4.2 Backend

1. **Create virtual environment (optional but recommended)**

   ```bash
   cd backend
   py -m venv .venv
   .venv\Scripts\activate   # Windows
   ```

2. **Install dependencies**

   ```bash
   py -m pip install -r requirements.txt
   ```

3. **Environment file**

   - Copy `backend/.env.example` to `backend/.env`.
   - Edit `.env`: set `SECRET_KEY`, `DATABASE_URL`, and optionally `ACCESS_TOKEN_EXPIRE_MINUTES`, OAuth keys, etc.

4. **Database**

   - Tables are created on first run via `Base.metadata.create_all(bind=engine)` in `main.py`.
   - Default admin user is seeded: **admin** / **adminpass**.

5. **Train ML model (optional)**

   ```bash
   py train_model.py
   ```

   This creates `app/spam_model.joblib` and `app/spam_model_info.json` (SpamAssassin + Enron-Spam).

6. **Run backend**

   ```bash
   py -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

   API: http://localhost:8000  
   Docs: http://localhost:8000/docs

### 4.3 Frontend

1. **Install dependencies**

   ```bash
   cd frontend
   py -m pip install -r requirements.txt
   ```

   (On Windows use `py -m pip` if `pip` is not in PATH.)

2. **Run dashboard**

   ```bash
   py -m streamlit run dashboard.py
   ```

   Dashboard: http://localhost:8501

### 4.4 One-command run (Windows)

- Double-click **`run_project.bat`** to start backend and frontend in separate windows.

---

## 5. Features Implemented (Step by Step)

### 5.1 Registration check and abuse rules

- **POST /check_registration** (email + phone):
  - Rejects if email already registered.
  - Rejects if phone already has 3 registrations.
  - Detects temporary email (disposable domain list).
  - Checks MX records for email domain (dnspython).
  - Validates phone format (phonenumbers, E.164).
  - Detects suspicious phone (repeated digits, fake patterns).
  - Computes spam score (Random Forest + rules); blocks if score > 50.
  - Creates a `Registration` with status `approved`, `pending`, or `blocked` and stores detection notes.

### 5.2 Authentication

- **POST /login**, **POST /signup**: JWT token; default admin **admin** / **adminpass**.
- **JWT expiry**: 1 day by default (`ACCESS_TOKEN_EXPIRE_MINUTES=1440` in `.env`).
- **Google OAuth**: Optional; configure `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`; see `OAUTH_SETUP.md`.
- **API key**: **POST /generate-api-key** for programmatic access.

### 5.3 Persistent login (no logout on refresh)

- **Backend**: Token lifetime set to 1 day; configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`.
- **Frontend**: Auth token and username stored in **cookies** (extra-streamlit-components).
  - On load, if session is empty but cookie has a token, backend `/me` is called; if valid, session is restored.
  - On login/signup/OAuth, token is saved to cookie.
  - On logout, session and auth cookies are cleared.
- Result: Admin stays logged in across browser refresh until token expires or they click Logout.

### 5.4 Phone whitelist (manual allow from Blocked)

- **Problem**: Legitimate numbers (e.g. repeated digits) were blocked by “suspicious phone” rule.
- **Solution**: Admin can whitelist a phone so it is no longer treated as suspicious.

**Backend**

- **Model**: `PhoneOverride` (phone_hash, phone_normalized, allow_suspicious, reason, created_by).
- **Logic**: In `create_registration`, if a `PhoneOverride` exists for that phone with `allow_suspicious=True`, the “suspicious phone” check is skipped.
- **POST /phone-whitelist** (admin only): Creates/updates override and sets all **blocked** registrations for that phone to **approved**, with a note “Phone whitelisted by &lt;admin&gt;: &lt;reason&gt;”.
- **GET /blocked-registrations**: Each phone group can include `is_whitelisted` when an override exists.

**Frontend (Blocked tab)**

- For each blocked phone (not already whitelisted): “Reason for allowing this phone” + button **“Allow this phone (whitelist)”**.
- On success: loading spinner, then success message; page resets to first page and list refreshes (whitelisted phone disappears from blocked list).

### 5.5 Blocked tab performance

- **Before**: Fetched 10,000 blocked registrations on every load and after every whitelist → slow.
- **After**:
  - **Page size 50**: Only 50 blocked registrations per request.
  - **Pagination**: Prev / Next and “Page X of Y”.
  - **Expanders**: Collapsed by default for faster render.
  - After whitelist, view resets to page 1.
- Result: Whitelist + rerun is much faster.

### 5.6 Dashboard tabs

- **Overview**: Metrics, ML model info (training size), test registration form, charts (emails per phone, spam score, status breakdown), blocked summary.
- **Registrations**: Paginated table, filters (phone hash, status), CSV export.
- **Phone Numbers**: Phones with email counts and per-phone email list.
- **Blocked**: Paginated blocked phones and emails; per-phone whitelist (reason + “Allow this phone”); export CSV.
- **Manual Review**: Select registration, change status/flags/spam score, quick actions (Mark spam, Approve, Block), audit log.
- **Spam Detection**: Flagged registrations, bulk block.
- **Reports**: Stats, analysis, PDF/CSV/JSON export.

### 5.7 Other API endpoints (summary)

- **Override**: POST /override — change registration status (admin).
- **Manual update**: POST /manual-update — change flags/status/notes (admin).
- **Bulk block**: POST /bulk_block.
- **Bulk import**: POST /bulk_import, /bulk_import_file, /bulk_import_raw (CSV/JSON/XML).
- **Stats**: GET /stats.
- **Flagged**: GET /flagged.
- **Phones**: GET /phone-registrations.
- **Blocked**: GET /blocked-registrations.
- **Audit**: GET /audit_logs.
- **Model info**: GET /model-info (training metadata for demo).
- **Health**: GET /health.

### 5.8 ML model (academic demo)

- **Training**: `train_model.py` loads SpamAssassin (raw emails) + Enron-Spam CSV, extracts features, trains Random Forest, saves `spam_model.joblib` and `spam_model_info.json`.
- **Inference**: `utils.calculate_spam_score()` uses the model; threshold 50 for blocking.
- **Dashboard**: Overview shows “Trained on X emails (ham/spam)” from GET /model-info.

### 5.9 Git and deployment

- **.gitignore**: Python cache, venv, `.env`, `.env.example`, `*.db`, `*.db-wal`, `*.db-shm`, `spam_model.joblib`, large data dirs, IDE/OS files, logs, Streamlit secrets, etc., so the repo is safe to push to GitHub.
- **.env**: Create from `.env.example`; never commit `.env`.

---

## 6. Configuration (Environment)

### Backend (`backend/.env`)

| Variable | Description | Example |
|----------|-------------|---------|
| DATABASE_URL | SQLite DB path | sqlite:///./email_abuse.db |
| SECRET_KEY | JWT signing key | (change in production) |
| ACCESS_TOKEN_EXPIRE_MINUTES | Token lifetime (minutes) | 1440 (1 day) |
| GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET | Google OAuth | (optional) |
| BACKEND_BASE_URL / FRONTEND_URL | OAuth redirects | http://localhost:8000, http://localhost:8501 |
| SALT | Phone hashing salt | (optional) |
| PHONE_DEFAULT_REGION | phonenumbers default region | IN |

### Frontend

- **API_BASE_URL**: Backend URL (default http://localhost:8000). Set via env or Streamlit config.

---

## 7. Default Credentials

- **Admin**: username **admin**, password **adminpass** (change in production).

---

## 8. Quick Reference

| Task | Command / Action |
|------|-------------------|
| Run full project (Windows) | `run_project.bat` |
| Run backend only | `cd backend` → `py -m uvicorn app.main:app --host 127.0.0.1 --port 8000` |
| Run frontend only | `cd frontend` → `py -m streamlit run dashboard.py` |
| Install frontend deps (Windows) | `cd frontend` → `py -m pip install -r requirements.txt` |
| Train ML model | `cd backend` → `py train_model.py` |
| API docs | http://localhost:8000/docs |
| Dashboard | http://localhost:8501 |

---

This document reflects the project as implemented; use it for handover, viva, or future changes.
