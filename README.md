# EDFP — Ethical Digital Footprint Profiler v2

> OSINT-based public exposure assessment tool — defensive cybersecurity research only.
> Aggregates publicly available data from 20+ APIs. No simulation, no fake data.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER / CLIENT                         │
│                                                                 │
│  login  register  scan  dashboard  history  analytics  admin    │
│         db-viewer  phone  defensive                             │
│                                                                 │
│         10 Jinja2 templates · Tailwind CSS · Vanilla JS         │
│                    WebSocket client (scan progress)             │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP / WebSocket
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VERCEL (serverless)                          │
│                                                                 │
│  @vercel/python runtime   api/index.py entry                    │
│  /static → CDN            env vars from dashboard               │
│                                                                 │
│  git push → auto redeploy via GitHub integration                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  FASTAPI APPLICATION  (app/main.py)             │
│                                                                 │
│  ┌──────────────┐  ┌─────────────────┐  ┌────────────────────┐ │
│  │  middleware  │  │  WebSocket mgr  │  │  Pydantic v2       │ │
│  │  auth.py     │  │  scan broadcast │  │  15 schemas        │ │
│  │  CORS · sess │  │  /ws/scan/{id}  │  │  ScanRequest/Res.  │ │
│  └──────────────┘  └─────────────────┘  └────────────────────┘ │
│                                                                 │
│  Routers (7):                                                   │
│  ┌────────┐ ┌────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐  │
│  │  auth  │ │  scan  │ │ history │ │analytics │ │  report  │  │
│  │login   │ │12stage │ │  CRUD   │ │ charts + │ │PDF export│  │
│  │register│ │  OSINT │ │ user-   │ │  admin   │ │defensive │  │
│  │logout  │ │timed   │ │ scoped  │ │ db-viewer│ │ guides   │  │
│  └────────┘ └────────┘ └─────────┘ └──────────┘ └──────────┘  │
│  ┌──────────────┐  ┌─────────────────┐                         │
│  │   username   │  │     phone       │                         │
│  │ enum/checker │  │  OSINT/WhoisXML │                         │
│  └──────────────┘  └─────────────────┘                         │
└───────────┬─────────────────────────────────────┬───────────────┘
            │                                     │
            ▼                                     ▼
┌───────────────────────────┐      ┌──────────────────────────────┐
│     SERVICES LAYER        │      │      SQLite DATABASE         │
│     app/services/         │      │      app/db/database.py      │
│                           │      │                              │
│  api_clients.py           │      │  tables:                     │
│    20 async API functions │      │  ┌─────────────────────────┐ │
│    asyncio.gather()       │      │  │ users                   │ │
│    _timed_call() logging  │      │  │ id · username · email   │ │
│                           │      │  │ password_hash · role    │ │
│  osint_engine.py          │      │  │ is_active · last_login  │ │
│    email miner            │      │  ├─────────────────────────┤ │
│    phone miner            │      │  │ sessions                │ │
│                           │      │  │ token · user_id         │ │
│  risk_engine.py           │      │  │ expires_at              │ │
│    exposure score         │      │  ├─────────────────────────┤ │
│    identity graph         │      │  │ scan_history            │ │
│    risk level (L/M/H)     │      │  │ scan_id · full_name     │ │
│                           │      │  │ risk · score · duration │ │
│  entity_resolver.py       │      │  ├─────────────────────────┤ │
│    exposure points        │      │  │ scan_details            │ │
│                           │      │  │ scan_id · result_json   │ │
│  report_generator.py      │      │  ├─────────────────────────┤ │
│    PDF via ReportLab      │      │  │ api_usage_log           │ │
│                           │      │  │ api_name · latency      │ │
│  phone_osint.py           │      │  │ success · error_msg     │ │
│    E.164 metadata         │      │  ├─────────────────────────┤ │
│                           │      │  │ username_cache          │ │
│  username_enum.py         │      │  │ platform · exists       │ │
│    platform checker       │      │  └─────────────────────────┘ │
│                           │      │                              │
│  scoring.py               │      │  Local:  data/profiler.db    │
│    confidence score       │      │  Vercel: /tmp/profiler.db    │
└───────────┬───────────────┘      │  Cloud:  Turso (optional)    │
            │                      └──────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL OSINT APIs (20)                     │
│                                                                 │
│  Web Search:                                                    │
│  ├── SerpAPI          Google search mentions                    │
│  ├── Brave Search     Privacy-focused search (2k/mo free)       │
│  ├── GitHub API       Profile + repo + commit mining            │
│  └── Twitter/X API   Public profile lookup by name             │
│                                                                 │
│  Breach & Email:                                                │
│  ├── LeakCheck.io     Breach check by email (50/day free)       │
│  ├── HIBP v3          Have I Been Pwned ($3.50/mo)              │
│  ├── FullContact      Email enrichment → social profiles        │
│  ├── Hunter.io        Email finder + domain search              │
│  ├── EmailRep.io      Email reputation (1k/day free)            │
│  ├── AbstractAPI      Email format + deliverability check       │
│  └── Gravatar         Avatar + profile from email hash          │
│                                                                 │
│  Infrastructure:                                                │
│  ├── Shodan           Internet-connected device search          │
│  ├── Censys           Host + certificate intelligence           │
│  ├── URLScan.io       Web scan history by domain/email          │
│  ├── crt.sh           Certificate Transparency log search       │
│  └── DNS Recon        Passive MX/A/NS via HackerTarget (free)   │
│                                                                 │
│  Phone & Identity:                                              │
│  ├── WhoisXML Phone   Carrier + line type lookup                │
│  ├── PhoneInfoga      Docker-based phone OSINT (self-hosted)    │
│  └── IntelX           Intelligence X dark/deep web index        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Scan Pipeline — 12 Stages

Every scan runs asynchronously through 12 stages. Progress is broadcast live via WebSocket to the frontend.

| Stage | Name | APIs Called |
|-------|------|-------------|
| 1 | Core discovery | GitHub, SerpAPI, Brave Search, Hunter, Shodan, IntelX, Twitter/X |
| 2 | Email & phone mining | Text extraction from all stage-1 snippets |
| 3 | Breach + enrichment | LeakCheck, HIBP, Gravatar, AbstractAPI, EmailRep, FullContact |
| 4 | Infrastructure recon | crt.sh, URLScan.io, Censys |
| 5 | Phone enrichment | WhoisXML Phone Intelligence + E.164 metadata |
| 6 | Exposure scoring | Risk engine calculates score 0–100 |
| 7 | Identity graph | Nodes + edges: target → emails → profiles → breaches |
| 8 | Contact assembly | Unified email + phone list with confidence scores |
| 9 | DNS passive recon | HackerTarget MX/A/NS lookup |
| 10 | Persist to DB | Save scan to SQLite with duration_ms |
| 11 | Done | Return `ScanResult` to frontend |

---

## Project Structure

```
ep_v2/
├── api/
│   └── index.py              ← Vercel serverless entry point
├── app/
│   ├── main.py               ← FastAPI app, routers, WebSocket, page routes
│   ├── middleware/
│   │   └── auth.py           ← Session cookie auth helpers
│   ├── models/
│   │   └── schemas.py        ← 15 Pydantic v2 models
│   ├── db/
│   │   └── database.py       ← aiosqlite CRUD + analytics queries
│   ├── routers/
│   │   ├── auth.py           ← POST /api/auth/login|register|logout
│   │   ├── scan.py           ← POST /api/scan
│   │   ├── history.py        ← GET/DELETE /api/history
│   │   ├── analytics.py      ← GET /api/analytics/* + /api/admin/*
│   │   ├── report.py         ← GET /api/report/pdf/{scan_id}
│   │   ├── phone.py          ← POST /api/phone/analyze
│   │   └── username.py       ← POST /api/username/check
│   ├── services/
│   │   ├── api_clients.py    ← 20 async external API functions
│   │   ├── osint_engine.py   ← Email + phone text extraction
│   │   ├── risk_engine.py    ← Exposure score + identity graph
│   │   ├── entity_resolver.py← Exposure point weighting
│   │   ├── report_generator.py← PDF generation via ReportLab
│   │   ├── phone_osint.py    ← E.164 phone metadata
│   │   └── username_enum.py  ← Multi-platform username checker
│   └── utils/
│       └── scoring.py        ← Confidence + exposure score math
├── templates/                ← 10 Jinja2 HTML templates
│   ├── index.html            ← Main scan page
│   ├── dashboard.html        ← Scan results + identity graph
│   ├── login.html
│   ├── register.html
│   ├── history.html
│   ├── analytics.html        ← Charts: trend, risk dist., top targets
│   ├── admin.html            ← User management panel
│   ├── db_viewer.html        ← SQLite browser (admin only)
│   ├── defensive.html        ← Privacy removal guides
│   └── phone_dashboard.html
├── static/
│   ├── css/custom.css
│   └── js/app.js
├── vercel.json               ← Vercel routing + DB_PATH env
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Database Schema

```sql
-- User accounts
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,        -- pbkdf2_hmac sha256, 260k iter
    role          TEXT    DEFAULT 'user',  -- 'user' | 'admin'
    is_active     INTEGER DEFAULT 1,
    created_at    TEXT    NOT NULL,
    last_login    TEXT
);

-- Session tokens (72h expiry)
CREATE TABLE sessions (
    token       TEXT    PRIMARY KEY,       -- secrets.token_urlsafe(32)
    user_id     INTEGER NOT NULL,
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

-- Scan summary (fast queries, analytics)
CREATE TABLE scan_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT    UNIQUE NOT NULL,
    user_id          INTEGER,
    full_name        TEXT    NOT NULL,
    location         TEXT,
    organization     TEXT,
    email            TEXT,
    risk_level       TEXT    NOT NULL,     -- 'LOW' | 'MODERATE' | 'HIGH'
    exposure_score   INTEGER NOT NULL,     -- 0–100
    confidence_score INTEGER NOT NULL,     -- 0–100
    profiles_found   INTEGER DEFAULT 0,
    emails_found     INTEGER DEFAULT 0,
    phones_found     INTEGER DEFAULT 0,
    breaches_found   INTEGER DEFAULT 0,
    sources_checked  INTEGER DEFAULT 0,
    duration_ms      INTEGER DEFAULT 0,
    created_at       TEXT    NOT NULL
);

-- Full scan result JSON
CREATE TABLE scan_details (
    scan_id     TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,             -- full ScanResult serialized
    created_at  TEXT NOT NULL
);

-- API call performance log
CREATE TABLE api_usage_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    scan_id    TEXT,
    api_name   TEXT    NOT NULL,
    success    INTEGER NOT NULL,
    latency_ms INTEGER DEFAULT 0,
    error_msg  TEXT,
    called_at  TEXT    NOT NULL
);

-- Username check cache
CREATE TABLE username_cache (
    username    TEXT NOT NULL,
    platform    TEXT NOT NULL,
    profile_url TEXT,
    "exists"    INTEGER NOT NULL,
    checked_at  TEXT    NOT NULL,
    PRIMARY KEY (username, platform)
);
```

---

## API Endpoints

### Auth
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/login` | Login page |
| `GET` | `/register` | Register page |
| `POST` | `/api/auth/login` | Login → set session cookie |
| `POST` | `/api/auth/register` | Register → set session cookie |
| `POST` | `/api/auth/logout` | Clear session cookie |
| `GET` | `/api/auth/me` | Get current user info |

### Scan
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Run full OSINT scan (12 stages) |
| `WS` | `/ws/scan/{scan_id}` | Real-time progress stream |

### History
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/history/` | List scan history (paginated, filtered) |
| `GET` | `/api/history/{scan_id}` | Get full scan detail |
| `GET` | `/api/history/stats` | Aggregate stats for current user |
| `DELETE` | `/api/history/{scan_id}` | Delete scan (admin only) |

### Analytics
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/analytics/overview` | Stats + risk dist. + breach stats |
| `GET` | `/api/analytics/trend` | Daily scan count (last N days) |
| `GET` | `/api/analytics/top-targets` | Highest exposure score targets |
| `GET` | `/api/analytics/api-performance` | API latency + success rate (7d) |
| `GET` | `/api/diagnostics` | Check which API keys are loaded |

### Admin
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List all users with scan counts |
| `PATCH` | `/api/admin/users/{id}/status` | Block / unblock user |
| `PATCH` | `/api/admin/users/{id}/role` | Change user role |
| `GET` | `/api/admin/db/tables` | List tables + row counts |
| `GET` | `/api/admin/db/query` | Browse table rows (paginated) |
| `GET` | `/api/admin/db/export/{table}` | Download table as CSV |

### Report & Tools
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/report/pdf/{scan_id}` | Download PDF intelligence report |
| `POST` | `/api/phone/analyze` | Phone OSINT (standalone) |
| `POST` | `/api/username/check` | Check username across platforms |

---

## Setup — Local Development

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd ep_v2
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your API keys (see [API Keys](#api-keys) section below).

### 3. Run

```bash
python -m uvicorn app.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** — redirects to login page.

**Default admin account:** `admin` / `admin123` — change this immediately after first login via Admin panel.

---

## Setup — Deploy to Vercel

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

> Make sure `.env` is in `.gitignore` — **never commit API keys**.

### 2. Import to Vercel

1. Go to [vercel.com](https://vercel.com) → **Add New Project**
2. Import your GitHub repo
3. Leave all build settings as default — Vercel auto-detects Python

### 3. Add Environment Variables

In Vercel dashboard → **Settings → Environment Variables**, add:

```
GITHUB_TOKEN        ghp_...
SERPAPI             your_serpapi_key
LEAKCHECK_API_KEY   your_leakcheck_key
BRAVE_API_KEY       BSA...
SHODAN_KEY          your_shodan_key
INTELLIGENCE_KEY    your_intelx_key
HUNTER_API_KEY      your_hunter_key
WHOISXML_API_KEY    at_...
URLSCAN_API_KEY     your_urlscan_key
CENSYS_API_KEY      censys_...
DB_PATH             /tmp/profiler.db
```

### 4. Deploy

Click **Deploy**. After ~1 minute your app is live at `https://your-project.vercel.app`.

### 5. Verify

Open `https://your-project.vercel.app/api/diagnostics` (login as admin first) to confirm all API keys are loaded.

---

## API Keys

| Key | Service | Free Tier | Get It |
|-----|---------|-----------|--------|
| `GITHUB_TOKEN` | GitHub API | 5k req/hr | [github.com/settings/tokens](https://github.com/settings/tokens) |
| `SERPAPI` | Google Search | 100/mo | [serpapi.com](https://serpapi.com) |
| `LEAKCHECK_API_KEY` | Breach check | 50/day | [leakcheck.io](https://leakcheck.io) |
| `BRAVE_API_KEY` | Brave Search | 2k/mo | [brave.com/search/api](https://brave.com/search/api) |
| `HIBP_API_KEY` | Have I Been Pwned | $3.50/mo | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| `FULLCONTACT_API_KEY` | Person enrichment | 500/mo | [app.fullcontact.com](https://app.fullcontact.com) |
| `TWITTER_BEARER_TOKEN` | Twitter/X API | Free | [developer.twitter.com](https://developer.twitter.com) |
| `SHODAN_KEY` | Device search | Paid | [account.shodan.io](https://account.shodan.io) |
| `INTELLIGENCE_KEY` | IntelX | Limited free | [intelx.io](https://intelx.io) |
| `HUNTER_API_KEY` | Email finder | 25/mo | [hunter.io](https://hunter.io) |
| `WHOISXML_API_KEY` | Phone lookup | 500/mo | [whoisxmlapi.com](https://whoisxmlapi.com) |
| `URLSCAN_API_KEY` | Web scan history | Free | [urlscan.io](https://urlscan.io) |
| `CENSYS_API_KEY` | Host intel | 250/mo | [app.censys.io](https://app.censys.io) |
| `EMAILREP_API_KEY` | Email reputation | 1k/day | [emailrep.io/key](https://emailrep.io/key) |
| `ABSTRACT_API_KEY` | Email validation | 100/mo | [abstractapi.com](https://www.abstractapi.com) |

---

## Known Limitations on Vercel

| Feature | Status | Notes |
|---------|--------|-------|
| REST API + Templates | ✅ Works | All scan, auth, analytics endpoints |
| WebSocket progress | ⚠️ Limited | Serverless doesn't support persistent WS |
| Database persistence | ⚠️ Ephemeral | `/tmp` resets on cold start — use Turso for persistent storage |
| PDF export | ✅ Works | Generated on demand, streamed directly |

### Fix database persistence with Turso (free)

```bash
# Install Turso CLI
npm install -g @turso/cli

# Create database
turso auth login
turso db create edfp-db

# Get credentials
turso db show edfp-db --url
turso db tokens create edfp-db
```

Add to Vercel environment variables:
```
TURSO_DATABASE_URL   libsql://edfp-db-username.turso.io
TURSO_AUTH_TOKEN     eyJhbGc...
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web framework | FastAPI 0.111 |
| ASGI server | Uvicorn 0.30 |
| Data validation | Pydantic v2.7 |
| Templates | Jinja2 3.1 |
| Database | SQLite via aiosqlite 0.20 |
| HTTP client | httpx 0.27 (async) |
| PDF generation | ReportLab 4.2 |
| Real-time | WebSockets 12.0 |
| Frontend | Tailwind CSS + Vanilla JS + Chart.js |
| Deployment | Vercel serverless (@vercel/python) |
| CI/CD | GitHub → Vercel auto-deploy |

---

## Security Notes

- Passwords hashed with `pbkdf2_hmac` SHA-256, 260,000 iterations + random salt
- Session tokens are `secrets.token_urlsafe(32)` with 72h expiry
- DB Viewer is read-only — no edit/delete from UI
- `password_hash` is always masked in DB Viewer and API responses
- `.env` is excluded from git via `.gitignore`
- Admin-only endpoints protected by `require_admin()` middleware

---

## Ethical Use

This tool is for **defensive security research only** — assessing your own or your organization's public digital exposure. All data is sourced from publicly indexed sources. Do not use to profile individuals without their consent.

---

*EDFP v2 — Built with FastAPI + Vercel*
