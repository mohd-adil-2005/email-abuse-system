# Production Database URL Setup (Cloud PostgreSQL)

This guide explains how to get and set `DATABASE_URL` for production.

## 1) What you need

- A cloud PostgreSQL provider account (Neon, Supabase, Railway, Render Postgres, AWS RDS, etc.)
- Your backend deployment target (Docker host, Render service, VM, ECS, etc.)

## 2) Create a cloud PostgreSQL database

General process (same idea on all providers):

1. Open your provider dashboard.
2. Create a new PostgreSQL project/database.
3. Wait until database status is "Ready".
4. Open the **Connection** or **Connect** tab.
5. Copy the connection string / URI.

It usually looks like:

`postgresql://USER:PASSWORD@HOST:5432/DB_NAME?sslmode=require`

For this FastAPI app, use SQLAlchemy format:

`postgresql+psycopg2://USER:PASSWORD@HOST:5432/DB_NAME`

If provider requires SSL and your host blocks query params, use:

`postgresql+psycopg2://USER:PASSWORD@HOST:5432/DB_NAME?sslmode=require`

## 3) Set DATABASE_URL in production

Set environment variable on your deployment platform:

- Key: `DATABASE_URL`
- Value: your cloud PostgreSQL URL

Example:

`DATABASE_URL=postgresql+psycopg2://app_user:strong_pass@ep-abc123.region.provider.com:5432/email_abuse`

## 4) Where to set it

- Docker server: in `.env` used by compose or in shell environment
- Render/Railway/Fly.io: service environment variables section
- Kubernetes: ConfigMap/Secret
- GitHub Actions deploy: repository/environment secrets

## 5) Local vs production behavior in this project

- `docker-compose.yml` currently supports:
  - **Local fallback** to local compose `db` service
  - **Production override** via `DATABASE_URL` env var

So when `DATABASE_URL` is set, backend uses that value.

## 6) Validate quickly after deployment

1. Open `http://<your-backend>/health` -> should return 200.
2. Call `/check_registration` once with sample data.
3. Confirm row is visible in dashboard and persisted.

## 7) Security notes

- Never commit real DB password to GitHub.
- Rotate DB password if it was exposed.
- Restrict DB network access to trusted apps.

