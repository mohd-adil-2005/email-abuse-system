# API Integration Guide (Postman + Signup Flow)

This guide shows exactly how a company backend can use this middleware API.

## 1) Login and get JWT

**Request**

- `POST http://localhost:8000/login`
- Header: `Content-Type: application/json`
- Body:

```json
{
  "username": "admin",
  "password": "adminpass"
}
```

**Response**

```json
{
  "access_token": "<JWT_TOKEN>",
  "token_type": "bearer"
}
```

## 2) Generate API key using JWT

**Request**

- `POST http://localhost:8000/generate-api-key`
- Header: `Authorization: Bearer <JWT_TOKEN>`

**Response**

```json
{
  "api_key": "sk_xxxxxxxxx",
  "message": "API key generated successfully..."
}
```

## 3) View saved API key anytime (after login)

**Request**

- `GET http://localhost:8000/my-api-key`
- Header: `Authorization: Bearer <JWT_TOKEN>`

## 4) Protected check endpoint for company integration

**Request**

- `POST http://localhost:8000/v1/check_registration`
- Headers:
  - `Content-Type: application/json`
  - `X-API-Key: sk_xxxxxxxxx`
- Body:

```json
{
  "email": "testuser@example.com",
  "phone": "+919876543210"
}
```

**Expected response**

```json
{
  "allowed": true,
  "email": "testuser@example.com",
  "status": "approved",
  "message": "Registration allowed"
}
```

If blocked:

```json
{
  "allowed": false,
  "status": "blocked",
  "message": "Temporary email detected and blocked"
}
```

---

## 5) Signup page backend integration code (Python example)

```python
import requests

API_URL = "http://localhost:8000/v1/check_registration"
API_KEY = "sk_your_api_key"

def validate_signup(email: str, phone: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
    }
    payload = {"email": email, "phone": phone}
    r = requests.post(API_URL, headers=headers, json=payload, timeout=10)
    return r.json()

def signup_handler(email: str, phone: str):
    result = validate_signup(email, phone)
    if not result.get("allowed"):
        return {"ok": False, "message": result.get("message", "Registration blocked")}
    # Continue your own user creation flow here
    return {"ok": True, "message": "User can be created"}
```

Short explanation:
- Call middleware first
- If `allowed=false`, stop signup and show reason
- If `allowed=true`, continue account creation

---

## 6) MERN stack integration (recommended)

### Backend (Node/Express) example

```javascript
// services/emailAbuse.js
const axios = require("axios");

const ABUSE_API_URL = "http://localhost:8000/v1/check_registration";
const ABUSE_API_KEY = process.env.ABUSE_API_KEY; // store in env

async function checkRegistration(email, phone) {
  const response = await axios.post(
    ABUSE_API_URL,
    { email, phone },
    {
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": ABUSE_API_KEY,
      },
      timeout: 10000,
    }
  );
  return response.data;
}

module.exports = { checkRegistration };
```

```javascript
// routes/signup.js
const express = require("express");
const router = express.Router();
const { checkRegistration } = require("../services/emailAbuse");

router.post("/signup", async (req, res) => {
  try {
    const { email, phone, password } = req.body;

    // Step 1: check with middleware API
    const result = await checkRegistration(email, phone);

    // Step 2: block or allow
    if (!result.allowed) {
      return res.status(400).json({
        ok: false,
        message: result.message,
        details: {
          status: result.status,
          spam_score: result.spam_score,
          is_temporary: result.is_temporary,
          notes: result.detection_notes,
        },
      });
    }

    // Step 3: create user in your DB (your existing logic)
    // const user = await User.create({ email, phone, passwordHash: ... });

    return res.json({ ok: true, message: "Signup allowed", middleware: result });
  } catch (err) {
    return res.status(500).json({ ok: false, message: "Signup failed", error: err.message });
  }
});

module.exports = router;
```

### Frontend (React) note

- React frontend should call your **own Node backend** `/signup`.
- Node backend calls middleware API securely with `X-API-Key`.
- Do **not** expose API key in browser/frontend code.

---

## 7) Postman checklist (super simple)

1. Login request -> copy JWT  
2. Generate API key -> copy `sk_...`  
3. Protected check request with `X-API-Key` header  
4. If response has `allowed=true` -> allow signup in your app


