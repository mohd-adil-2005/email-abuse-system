# Publish on npm + Put your API on the internet

## Two different things

| What | Meaning |
|------|--------|
| **npm package** | The JavaScript code (`email-abuse-detection-client`) that **calls** your API. You publish this on npm so others can `npm install` it and use it in their Node.js apps. |
| **Your API (backend)** | The FastAPI server that runs on your PC right now (localhost:8000). For others to use it **on the internet**, you must **deploy** this backend to a hosting service (Railway, Render, etc.). |

- You can **publish the npm package first** even if your API is not on the internet. People who install the package will set `baseUrl` to **their own** API URL (or yours once you deploy).
- When you **deploy your API**, you get a URL like `https://your-app.railway.app`. Then you (and others) use that URL as `baseUrl` when using the npm package.

---

# Part 1: How to publish the npm package (simple steps)

## Step 1: Create a free npm account

1. Open: **https://www.npmjs.com/signup**
2. Fill: **Username**, **Email**, **Password**
3. Verify email if npm asks you to.

## Step 2: Open terminal in the client folder

1. In Cursor/VS Code, open the folder: `Email-Abuse-System/email-abuse-client`
2. Open the terminal (Ctrl + `) and make sure you are in that folder. You can run:
   ```bash
   cd email-abuse-client
   ```
   (if you started from the project root).

## Step 3: Log in to npm from the terminal

Run:

```bash
npm login
```

- It will ask: **Username** → type your npm username  
- Then: **Password** → type your npm password  
- Then: **Email** → type the same email you used for npm  
- If it says "Logged in as ...", you are done with login.

## Step 4: Use a scoped name (so the name is always yours)

We use a scoped name so nobody else can take it. Open `package.json` and set the name to:

```json
"name": "@mohd-adil-2005/email-abuse-client"
```

(Use your real npm username if it is not `mohd-adil-2005`.)

## Step 5: Publish to npm

In the same terminal (inside `email-abuse-client`), run:

```bash
npm publish --access public
```

- For a scoped package (`@username/...`), `--access public` is required the first time so everyone can install it.
- If it says something like "+\s@mohd-adil-2005/email-abuse-client@1.0.0", the package is published.

## Step 6: Check it on the website

- Open: **https://www.npmjs.com/package/@mohd-adil-2005/email-abuse-client**  
  (Replace `mohd-adil-2005` with your npm username if different.)

Now anyone can install with:

```bash
npm install @mohd-adil-2005/email-abuse-client
```

---

# Part 2: Put your API on the internet (deploy backend)

Right now your API runs only on your PC (`http://localhost:8000`). To use it from the internet (and give a URL to others), you need to **deploy** the backend.

Here are two **free** options that work well with FastAPI.

## Option A: Railway (easy, free tier)

1. Go to **https://railway.app** and sign up (e.g. with GitHub).
2. Click **"New Project"** → **"Deploy from GitHub repo"** and select your **Email-Abuse-System** repo (you must push the code to GitHub first).
3. Set **Root Directory** to `backend` (so Railway runs the FastAPI app, not the whole repo).
4. Set **Start Command** to something like:
   ```bash
   pip install -r requirements.txt && uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
5. Add a **Postgres** or keep **SQLite** (SQLite is simpler but not ideal for production; Railway can give you a disk volume for SQLite).
6. Deploy. Railway will give you a URL like: **https://your-app-name.up.railway.app**
7. Use this URL as `baseUrl` when using the npm package, e.g.:
   ```javascript
   const client = new EmailAbuseClient({ baseUrl: 'https://your-app-name.up.railway.app' });
   ```

## Option B: Render (easy, free tier)

1. Go to **https://render.com** and sign up.
2. **New** → **Web Service** → connect your GitHub repo (**Email-Abuse-System**).
3. Set:
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Deploy. Render will give you a URL like: **https://your-app-name.onrender.com**
5. Use this URL as `baseUrl` in the npm client.

---

# Part 3: Database when you deploy

Your app currently uses **SQLite**: a single file (`email_abuse.db`) on your PC. Data stays there as long as the file exists.

When you deploy to Railway or Render, the server’s disk is often **temporary**. On each redeploy the container is recreated and **the SQLite file can be lost**, so you’d lose users, registrations, and logs.

You have two options.

## Option 1: Keep SQLite (simplest, but data may not persist)

- Do nothing: leave `DATABASE_URL=sqlite:///./email_abuse.db` in the deployed app’s environment.
- The app will run, but **on redeploy the database can reset** (empty again). Fine for a quick demo, not for real use.

Some hosts let you attach a **persistent volume** (a disk that survives redeploys). If you use that and put the SQLite file on the volume, data can persist. Check Railway/Render docs for “Volumes” or “Persistent disk”.

## Option 2: Use PostgreSQL (recommended for “real” deployment)

Use a **hosted PostgreSQL** database so data is stored in the cloud and survives redeploys.

### On Railway

1. In your Railway project, click **“New”** → **“Database”** → **“PostgreSQL”**.
2. After it’s created, open the Postgres service and copy the **Connection URL** (looks like `postgresql://postgres:xxxx@host:5432/railway`).
3. Open your **FastAPI service** (the backend) → **Variables** tab.
4. Add a variable: **`DATABASE_URL`** = paste the Postgres connection URL.
5. Redeploy the backend. The app will create tables on first run (it already does this in code) and use Postgres instead of SQLite.

### On Render

1. In the Render dashboard, click **“New”** → **“PostgreSQL”** and create a database (free tier).
2. Open the database → **“Info”** or **“Connections”** and copy the **Internal Database URL** (e.g. `postgresql://user:pass@host/dbname`).
3. Open your **Web Service** (the backend) → **Environment**.
4. Add: **`DATABASE_URL`** = that Postgres URL.
5. Save and redeploy.

### Make sure the backend can talk to PostgreSQL

The project’s `backend/requirements.txt` already includes support for PostgreSQL. If you get an error like “no module named psycopg2”, add this to `backend/requirements.txt` and redeploy:

```
psycopg2-binary
```

Your app code does **not** need changes: it reads `DATABASE_URL` from the environment. If `DATABASE_URL` is a `postgresql://...` URL, the app uses PostgreSQL; if it’s `sqlite:///...`, it uses SQLite.

### Summary

| Where you run | Database | What to set |
|---------------|----------|-------------|
| **Your PC (local)** | SQLite file | `DATABASE_URL=sqlite:///./email_abuse.db` (default) – no change needed. |
| **Railway / Render** | **Keep SQLite** | Leave default; app works but data may be lost on redeploy. |
| **Railway / Render** | **PostgreSQL** | Create a Postgres database on the same platform, copy its URL, set **`DATABASE_URL`** in your backend’s environment to that URL. Optionally add `psycopg2-binary` to `requirements.txt` if needed. |

---

# Summary

| Goal | What to do |
|------|------------|
| **Publish the npm package** | Create npm account → `npm login` → set `"name": "@your-username/email-abuse-client"` in package.json → run `npm publish --access public` in `email-abuse-client` folder. |
| **Put API on the internet** | Push project to GitHub → use Railway or Render → deploy the `backend` folder → use the given URL as `baseUrl` in the client. |
| **Let others use your API** | Deploy the API (above), then share the API URL. They install your npm package and pass that URL as `baseUrl`. |

If you tell me which step you are on (e.g. "I have npm account but don't know the next command" or "I want to deploy on Railway"), I can give you the exact commands for your case.
